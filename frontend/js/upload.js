// frontend/js/upload.js
// Handles file upload, receives prediction percentages & sample, renders Chart.js percent bar.

const uploadForm = document.getElementById("uploadForm");
const fileInput = document.getElementById("fileInput");
const uploadStatus = document.getElementById("uploadStatus");
const chartSection = document.getElementById("chartSection");
const sampleSection = document.getElementById("sampleSection");
const sampleBody = document.getElementById("sampleBody");
let predChart = null;

function showStatus(msg, isError=false) {
  uploadStatus.style.color = isError ? "#ff6b6b" : "#9fb9d2";
  uploadStatus.innerText = msg;
}

function renderPercentChart(percentages) {
  chartSection.style.display = "block";
  const ctx = document.getElementById("predChart").getContext("2d");
  const labels = Object.keys(percentages);
  const data = Object.values(percentages);

  if (predChart) {
    predChart.data.labels = labels;
    predChart.data.datasets[0].data = data;
    predChart.update();
    return;
  }

  predChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Percent",
        data: data,
        backgroundColor: ["#6ee7ff","#ffcd4a","#ff6b6b","#9ad28f"],
      }]
    },
    options: {
      indexAxis: 'y',
      scales: {
        x: { beginAtZero: true, max: 100 }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderSampleTable(rows) {
  sampleSection.style.display = "block";
  sampleBody.innerHTML = "";
  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.src_ip||""}</td>
      <td>${r.dst_ip||""}</td>
      <td>${r.protocol||""}</td>
      <td>${r.packet_count!==undefined? r.packet_count : (r.count_packets || "")}</td>
      <td>${r.total_bytes!==undefined? r.total_bytes : (r.total_bytes || "")}</td>
      <td>${r.prediction||""}</td>
      <td>${r.probability? Number(r.probability).toFixed(3) : ""}</td>
    `;
    sampleBody.appendChild(tr);
  });
}

uploadForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const file = fileInput.files[0];
  if (!file) {
    showStatus("Choose a file first", true);
    return;
  }
  const form = new FormData();
  form.append("file", file);

  showStatus("Uploading and analyzing... (may take a few seconds)");
  chartSection.style.display = "none";
  sampleSection.style.display = "none";

  try {
    const resp = await fetch("/upload_file", {
      method: "POST",
      body: form
    });
    const data = await resp.json();
    if (!resp.ok || data.status !== "ok") {
      const msg = data.message || data.error || ("Upload failed ("+resp.status+")");
      showStatus(msg, true);
      return;
    }

    showStatus(`Analysis done — ${data.flows} flows from ${data.file}`);
    // Render percentages as Option 2 (percentage)
    const percentages = data.percentages || {};
    renderPercentChart(percentages);

    // render sample table
    const sample = data.sample || [];
    renderSampleTable(sample);
  } catch (err) {
    console.error(err);
    showStatus("Upload or analysis error — check server logs", true);
  }
});
