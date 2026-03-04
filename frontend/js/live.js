// frontend/js/live.js
// Restored and upgraded to support a dedicated IP Filter input.

let pollingInterval;
let chart;
const maxPoints = 30; // last 30 updates

async function fetchPackets() {
  const res = await fetch("/live_packets?n=300");
  const data = await res.json();
  return data;
}

async function updatePackets() {
  const packets = await fetchPackets();
  const tableBody = document.getElementById("packetTableBody");
  tableBody.innerHTML = "";

  let totalLength = 0;
  let packetCount = 0;

  packets.forEach(pkt => {
    if ((pkt.src_ip === "-" || pkt.src_ip === "") && (pkt.dst_ip === "-" || pkt.dst_ip === "")) return; // skip empty
    const row = document.createElement("tr");

    // Determine row color / class
    const proto = (pkt.protocol || "").toUpperCase();
    const flags = (pkt.flags || "").toUpperCase();

    if (proto.includes("UDP")) {
      row.classList.add("udp-packet");
    } else if (proto.includes("ICMP")) {
      row.classList.add("icmp-packet");
    } else if (flags.includes("RST") || flags.includes("FIN") || flags.includes("SYN")) {
      // highlight abnormal TCP packets
      row.classList.add("suspect");
    }

    row.innerHTML = `
      <td>${pkt.timestamp}</td>
      <td>${pkt.src_ip}</td>
      <td>${pkt.dst_ip}</td>
      <td>${pkt.protocol}</td>
      <td>${pkt.length}</td>
    `;
    tableBody.appendChild(row);
    totalLength += pkt.length || 0;
    packetCount++;
  });

  // Auto-scroll table
  const tableDiv = document.getElementById("packetTableContainer");
  tableDiv.scrollTop = tableDiv.scrollHeight;

  // Update chart
  updateChart(packetCount, totalLength);
}

function startPolling() {
  if (pollingInterval) clearInterval(pollingInterval);
  updatePackets();
  pollingInterval = setInterval(updatePackets, 2000);
}

function stopPolling() {
  if (pollingInterval) clearInterval(pollingInterval);
}

function setupChart() {
  const ctx = document.getElementById("liveTrafficChart");
  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Packets per 2s",
          borderColor: "#00e6a8",
          backgroundColor: "rgba(0,230,168,0.15)",
          data: [],
          tension: 0.3,
        },
      ],
    },
    options: {
      responsive: true,
      animation: false,
      scales: {
        x: { title: { display: true, text: "Time" } },
        y: { title: { display: true, text: "Packets" } },
      },
      plugins: { legend: { display: false } },
    },
  });
}

function updateChart(count, bytes) {
  const now = new Date().toLocaleTimeString();
  if (!chart) return;

  const labels = chart.data.labels;
  const data = chart.data.datasets[0].data;

  labels.push(now);
  data.push(count);

  if (labels.length > maxPoints) {
    labels.shift();
    data.shift();
  }

  chart.update();
}

// Build combined BPF filter from `filter` and `ipFilter` inputs
function buildCombinedFilter() {
  const userFilter = document.getElementById("filter").value.trim();
  const ipOnly = document.getElementById("ipFilter").value.trim();
  let final = "";

  if (!userFilter && !ipOnly) return "";

  if (ipOnly) {
    const ipExpr = ipOnly.includes("ip.") || ipOnly.includes("==") ? ipOnly : `ip.addr==${ipOnly}`;
    final = userFilter ? `${userFilter} and ${ipExpr}` : ipExpr;
  } else {
    final = userFilter;
  }

  console.log("[Frontend] Sending filter:", final); // ✅ new debug line
  return final;
}


// Event handlers
document.getElementById("start").addEventListener("click", async () => {
  const iface = document.getElementById("iface").value.trim() || "Wi-Fi";
  const combinedFilter = buildCombinedFilter();

  await fetch("/start_capture", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ interface: iface, filter: combinedFilter }),
  });
  
  startPolling();
});

document.getElementById("stop").addEventListener("click", async () => {
  await fetch("/stop_capture", { method: "POST" });
  stopPolling();
});

document.getElementById("clear").addEventListener("click", async () => {
  await fetch("/clear_packets", { method: "POST" });
  document.getElementById("packetTableBody").innerHTML = "";
});

window.addEventListener("DOMContentLoaded", () => {
  setupChart();
});
