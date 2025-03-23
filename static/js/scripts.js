document.addEventListener("DOMContentLoaded", () => {
  const loading = document.getElementById("loading");
  if (loading) loading.style.display = "none";

  showSection("inicio");
  cargarReportes();
  cargarMetricas();
});

function showSection(id) {
  document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
  const target = document.getElementById(id);
  if (target) target.classList.add("active");
}

function cargarReportes() {
  fetch("/reportes")
    .then(res => res.json())
    .then(data => {
      if (data.error) return;

      const ctx1 = document.getElementById("phishingChart").getContext("2d");
      new Chart(ctx1, {
        type: "doughnut",
        data: {
          labels: ["Seguro", "Sospechoso", "Phishing"],
          datasets: [{
            data: data.phishing_stats,
            backgroundColor: ["#198754", "#ffc107", "#dc3545"]
          }]
        }
      });

      const ctx2 = document.getElementById("attachmentsChart").getContext("2d");
      new Chart(ctx2, {
        type: "bar",
        data: {
          labels: ["Limpios", "Sospechosos", "Maliciosos"],
          datasets: [{
            data: data.attachment_stats,
            label: "Adjuntos",
            backgroundColor: ["#198754", "#ffc107", "#dc3545"]
          }]
        }
      });

      const ctx3 = document.getElementById("phishingTrendsChart").getContext("2d");
      new Chart(ctx3, {
        type: "line",
        data: {
          labels: data.trends.dates,
          datasets: [{
            data: data.trends.counts,
            label: "Phishing por día",
            borderColor: "#0d6efd",
            tension: 0.3
          }]
        }
      });
    });
}

function cargarMetricas() {
  fetch("/metricas")
    .then(res => res.json())
    .then(data => {
      document.getElementById("total").textContent = data.total;
      document.getElementById("precision").textContent = data.precision;
      document.getElementById("sensibilidad").textContent = data.sensibilidad;
      document.getElementById("especificidad").textContent = data.especificidad;
    });
}
