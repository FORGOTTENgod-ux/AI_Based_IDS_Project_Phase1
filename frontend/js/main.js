// frontend/js/main.js
// Updated upload logic: sends file to backend /predict and displays returned summary

const navToggle = document.getElementById('navToggle');
const navMenu = document.getElementById('navMenu');

if (navToggle) {
  navToggle.addEventListener('click', () => {
    navMenu.classList.toggle('active');
    const spans = navToggle.querySelectorAll('span');
    if (navMenu.classList.contains('active')) {
      spans[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
      spans[1].style.opacity = '0';
      spans[2].style.transform = 'rotate(-45deg) translate(7px, -6px)';
    } else {
      spans[0].style.transform = 'none';
      spans[1].style.opacity = '1';
      spans[2].style.transform = 'none';
    }
  });

  const navLinks = document.querySelectorAll('.nav-link');
  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      // Don't close menu if clicking on dropdown toggle
      if (!link.classList.contains('dropdown-toggle')) {
        navMenu.classList.remove('active');
        const spans = navToggle.querySelectorAll('span');
        spans[0].style.transform = 'none';
        spans[1].style.opacity = '1';
        spans[2].style.transform = 'none';
      }
    });
  });
}

// Dropdown Menu Functionality
const navDropdowns = document.querySelectorAll('.nav-dropdown');
const isMobile = window.innerWidth <= 768;

// Handle dropdown on mobile (click to toggle)
if (isMobile) {
  navDropdowns.forEach(dropdown => {
    const toggle = dropdown.querySelector('.dropdown-toggle');
    if (toggle) {
      toggle.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        
        // Close other dropdowns
        navDropdowns.forEach(otherDropdown => {
          if (otherDropdown !== dropdown) {
            otherDropdown.classList.remove('active');
          }
        });
        
        // Toggle current dropdown
        dropdown.classList.toggle('active');
      });
    }
  });

  // Close dropdowns when clicking outside
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.nav-dropdown')) {
      navDropdowns.forEach(dropdown => {
        dropdown.classList.remove('active');
      });
    }
  });

  // Close mobile menu when clicking dropdown links
  const dropdownLinks = document.querySelectorAll('.dropdown-link');
  dropdownLinks.forEach(link => {
    link.addEventListener('click', () => {
      if (navMenu) {
        navMenu.classList.remove('active');
        const spans = navToggle?.querySelectorAll('span');
        if (spans) {
          spans[0].style.transform = 'none';
          spans[1].style.opacity = '1';
          spans[2].style.transform = 'none';
        }
      }
      // Close all dropdowns
      navDropdowns.forEach(dropdown => {
        dropdown.classList.remove('active');
      });
    });
  });
}

// Handle dropdown on desktop (hover)
if (!isMobile) {
  navDropdowns.forEach(dropdown => {
    dropdown.addEventListener('mouseenter', () => {
      dropdown.classList.add('active');
    });
    
    dropdown.addEventListener('mouseleave', () => {
      dropdown.classList.remove('active');
    });
  });
}

// Update on window resize
let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    const newIsMobile = window.innerWidth <= 768;
    if (newIsMobile !== isMobile) {
      location.reload(); // Reload to reinitialize event listeners
    }
  }, 250);
});

const header = document.getElementById('header');
let lastScroll = 0;
window.addEventListener('scroll', () => {
  const currentScroll = window.pageYOffset;
  if (currentScroll > 100) {
    header.classList.add('scrolled');
  } else {
    header.classList.remove('scrolled');
  }
  lastScroll = currentScroll;
});

// animations
const observerOptions = {
  threshold: 0.1,
  rootMargin: '0px 0px -50px 0px'
};
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) entry.target.classList.add('visible');
  });
}, observerOptions);
const fadeElements = document.querySelectorAll('.fade-in');
fadeElements.forEach(el => observer.observe(el));

// Upload UI elements
const fileInput = document.getElementById('fileInput');
const fileLabel = document.getElementById('fileLabel');
const fileName = document.getElementById('fileName');
const uploadBtn = document.getElementById('uploadBtn');
const uploadMessage = document.getElementById('uploadMessage');
const fileInfo = document.getElementById('fileInfo');

// Backend endpoint (adjust host if needed)
const BACKEND_PREDICT_URL = "http://127.0.0.1:5000/predict";

if (fileInput) {
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      fileName.textContent = file.name;
      const fileSize = (file.size / 1024).toFixed(2);
      fileInfo.innerHTML = `<strong>Selected:</strong> ${file.name} (${fileSize} KB)`;
      fileInfo.style.opacity = '1';
      fileLabel.style.borderColor = 'var(--accent-teal)';
      fileLabel.style.backgroundColor = '#E6FFFA';
    }
  });

  uploadBtn.addEventListener('click', async () => {
    const file = fileInput.files[0];
    if (!file) {
      showMessage('Please select a file first!', 'error');
      return;
    }

    const validExtensions = ['.pcap', '.pcapng', '.csv'];
    const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (!validExtensions.includes(fileExtension)) {
      showMessage('Invalid file type! Please upload .pcap, .pcapng, or .csv files only.', 'error');
      return;
    }

    const maxSize = 100 * 1024 * 1024; // 100MB
    if (file.size > maxSize) {
      showMessage('File size exceeds 100MB limit!', 'error');
      return;
    }

    // prepare UI
    uploadBtn.disabled = true;
    uploadBtn.textContent = 'Analyzing...';
    uploadBtn.style.opacity = '0.7';
    showMessage('Uploading and analyzing file...', 'success');

    try {
      const formData = new FormData();
      formData.append('file', file);

      const resp = await fetch(BACKEND_PREDICT_URL, {
        method: 'POST',
        body: formData
      });

      const json = await resp.json();
      if (!resp.ok) {
        const err = json.error || JSON.stringify(json);
        showMessage(`Error: ${err}`, 'error');
      } else {
        // show summary if present
        if (json.summary) {
          const entries = Object.entries(json.summary);
          const summaryText = entries.map(([k,v]) => `${k}: ${v}`).join(' | ');
          showMessage(`Analysis complete — ${summaryText}`, 'success');
        } else if (json.results && Array.isArray(json.results) && json.results.length) {
          // fallback: count predictions
          const counts = {};
          json.results.forEach(r => { counts[r.prediction] = (counts[r.prediction]||0)+1; });
          const summaryText = Object.entries(counts).map(([k,v])=>`${k}: ${v}`).join(' | ');
          showMessage(`Analysis complete — ${summaryText}`, 'success');
        } else {
          showMessage('Analysis complete — no predictions returned', 'error');
        }
        console.log('Full result:', json);
      }
    } catch (err) {
      console.error(err);
      showMessage('Server not reachable. Make sure backend is running.', 'error');
    } finally {
      // reset UI
      uploadBtn.disabled = false;
      uploadBtn.textContent = 'Upload & Analyze';
      uploadBtn.style.opacity = '1';
      setTimeout(() => {
        fileInput.value = '';
        fileName.textContent = 'No file chosen';
        fileInfo.innerHTML = '';
        fileInfo.style.opacity = '0';
        fileLabel.style.borderColor = '#CBD5E0';
        fileLabel.style.backgroundColor = '#F7FAFC';
      }, 2000);
    }
  });
}

function showMessage(message, type) {
  uploadMessage.textContent = message;
  uploadMessage.className = `upload-message ${type} show`;
  if (type === 'error') {
    setTimeout(() => uploadMessage.classList.remove('show'), 5000);
  } else if (type === 'success') {
    setTimeout(() => uploadMessage.classList.remove('show'), 8000);
  }
}

// small hover effect
const buttons = document.querySelectorAll('.btn');
buttons.forEach(btn => {
  btn.addEventListener('mouseenter', function() { this.style.transform = 'translateY(-2px) scale(1.02)'; });
  btn.addEventListener('mouseleave', function() { this.style.transform = 'translateY(0) scale(1)'; });
});

window.addEventListener('load', () => {
  setTimeout(() => fadeElements.forEach((el,i) => setTimeout(()=>el.classList.add('visible'), i*100)), 200);
});

// FAQ Accordion Functionality
const faqItems = document.querySelectorAll('.faq-item');
faqItems.forEach(item => {
  const question = item.querySelector('.faq-question');
  question.addEventListener('click', () => {
    const isActive = item.classList.contains('active');
    
    // Close all FAQ items
    faqItems.forEach(faqItem => {
      faqItem.classList.remove('active');
    });
    
    // Open clicked item if it wasn't active
    if (!isActive) {
      item.classList.add('active');
    }
  });
});

// Enhanced scroll animations with parallax effect (disabled to avoid conflicts with hover effects)
// Uncomment if you want subtle parallax effect
/*
window.addEventListener('scroll', () => {
  const scrolled = window.pageYOffset;
  const parallaxElements = document.querySelectorAll('.step-card, .tech-card, .use-case-card');
  
  parallaxElements.forEach((el, index) => {
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight && rect.bottom > 0 && !el.matches(':hover')) {
      const speed = 0.05 + (index % 3) * 0.02;
      const yPos = -(scrolled * speed);
      el.style.transform = `translateY(${yPos}px)`;
    }
  });
});
*/

// Smooth scroll for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      const headerOffset = 80;
      const elementPosition = target.getBoundingClientRect().top;
      const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

      window.scrollTo({
        top: offsetPosition,
        behavior: 'smooth'
      });
    }
  });
});

// Add hover sound effect simulation (visual feedback)
const interactiveCards = document.querySelectorAll('.feature-card, .tech-card, .use-case-card, .testimonial-card, .team-card');
interactiveCards.forEach(card => {
  card.addEventListener('mouseenter', function() {
    this.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
  });
  
  card.addEventListener('mouseleave', function() {
    this.style.transition = 'all 0.4s ease';
  });
});

// Add counter animation for numbers (if you add statistics later)
function animateCounter(element, target, duration = 2000) {
  let start = 0;
  const increment = target / (duration / 16);
  const timer = setInterval(() => {
    start += increment;
    if (start >= target) {
      element.textContent = target;
      clearInterval(timer);
    } else {
      element.textContent = Math.floor(start);
    }
  }, 16);
}

// Intersection Observer for enhanced fade-in animations
const observerOptionsEnhanced = {
  threshold: 0.1,
  rootMargin: '0px 0px -100px 0px'
};

const observerEnhanced = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      // Add stagger effect for grid items
      const siblings = Array.from(entry.target.parentElement.children);
      const index = siblings.indexOf(entry.target);
      setTimeout(() => {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }, index * 100);
    }
  });
}, observerOptionsEnhanced);

// Observe all fade-in elements
const allFadeElements = document.querySelectorAll('.fade-in');
allFadeElements.forEach(el => observerEnhanced.observe(el));
