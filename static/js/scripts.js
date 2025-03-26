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


function actualizarBarraRiesgo() {
  fetch('/metricas')
    .then(res => res.json())
    .then(data => {
      if (data.total > 0) {
        const riesgo = ((data.phishing + data.sospechosos) / data.total * 100).toFixed(1);
        const barra = document.getElementById("barraRiesgo");
        barra.style.width = riesgo + "%";
        barra.innerText = riesgo + "%";
      }
    });
}
document.addEventListener("DOMContentLoaded", actualizarBarraRiesgo);


document.addEventListener("DOMContentLoaded", () => {
  fetch("/metricas")
    .then(res => res.json())
    .then(data => {
      document.getElementById("total").textContent = data.total;
      document.getElementById("precision").textContent = data.precision + " %";
      document.getElementById("sensibilidad").textContent = data.sensibilidad + " %";
      document.getElementById("especificidad").textContent = data.especificidad + " %";
      document.getElementById("tiempo_analisis").textContent = "N/A";
      document.getElementById("porcentaje_sospechosos").textContent = data.porcentaje_sospechosos + " %";
      document.getElementById("ultimo_analisis").textContent = data.ultimo_analisis;
    })
    .catch(err => console.error("Error cargando métricas:", err));
});

async function cargarResumenInicio() {
  const res = await fetch("/metricas");
  const datos = await res.json();
  document.getElementById("totalInicio").innerText = datos.total;
  document.getElementById("phishingInicio").innerText = datos.total > 0 ? ((datos.phishing / datos.total) * 100).toFixed(1) + "%" : "--";
  document.getElementById("segurosInicio").innerText = datos.total > 0 ? ((datos.seguros / datos.total) * 100).toFixed(1) + "%" : "--";
}
document.addEventListener("DOMContentLoaded", cargarResumenInicio);


const consejos = [
  "💡 Consejo: Nunca hagas clic en enlaces sospechosos de correos desconocidos.",
  "🔐 Usa contraseñas únicas y seguras en tus cuentas.",
  "📛 Verifica la dirección del remitente antes de confiar en un correo.",
  "⚠️ Evita descargar archivos adjuntos de fuentes no verificadas.",
  "🛡️ Usa autenticación en dos pasos siempre que puedas."
];
let i = 0;
setInterval(() => {
  document.getElementById("consejoSeguridad").innerText = consejos[i % consejos.length];
  i++;
}, 6000); // cambia cada 6 segundos


async function estadoSistema() {
  const res = await fetch("/historial");
  const html = await res.text();
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  const filas = doc.querySelectorAll("tbody tr");
  if (filas.length > 0) {
    const ultimaFecha = filas[filas.length - 1].querySelector("td:last-child").innerText;
    document.getElementById("ultimoEscaneo").innerText = ultimaFecha;
  }
}
document.addEventListener("DOMContentLoaded", estadoSistema);

fetch('/reportes')
  .then(res => res.json())
  .then(data => {
    const labels = data.timeline.map(e => e.fecha);
    const counts = labels.reduce((acc, val) => {
      acc[val] = (acc[val] || 0) + 1;
      return acc;
    }, {});
    
    new Chart(document.getElementById('timelineChart'), {
      type: 'bar',
      data: {
        labels: Object.keys(counts),
        datasets: [{
          label: 'Detecciones de Phishing',
          data: Object.values(counts),
          backgroundColor: 'rgba(255, 99, 132, 0.7)'
        }]
      }
    });
  });




  document.getElementById("emlForm").addEventListener("submit", async function(e) {
    e.preventDefault();
  
    const form = e.target;
    const formData = new FormData(form);
  
    try {
      const response = await fetch("/analyze_email_eml", {
        method: "POST",
        body: formData
      });
  
      if (!response.ok) throw new Error("Error al analizar el correo.");
  
      const data = await response.json();
  
      // Rellenar campos del modal con formato visual bonito
      const estadoHTML = data.is_phishing.includes("Phishing")
        ? `<span class="text-danger fw-bold">🚨 ${data.is_phishing}</span>`
        : data.is_phishing.includes("Sospechoso")
          ? `<span class="text-warning fw-bold">⚠️ ${data.is_phishing}</span>`
          : `<span class="text-success fw-bold">✅ ${data.is_phishing}</span>`;
  
      document.querySelector("#resultadoModal .modal-title").innerText = `📩 Detalles del Correo`;
  
      document.querySelector("#resultadoModal .modal-body").innerHTML = `
        <p><strong>📌 Asunto:</strong> ${data.subject}</p>
        <p><strong>📨 Remitente:</strong> ${data.from}</p>
        <p><strong>🔒 Estado:</strong> ${estadoHTML}</p>
  
        <div class="border rounded p-3 mb-3 bg-light">
          <h6 class="fw-bold">🔵 Autenticación SPF, DKIM y DMARC</h6>
          <p><strong>SPF:</strong> ${data.spf_result}</p>
          <p><strong>DKIM:</strong> ${data.dkim_result}</p>
          <p><strong>DMARC:</strong> ${data.dmarc_result}</p>
          ${data.spf_result.startsWith("❌") && data.dkim_result.startsWith("❌") && data.dmarc_result.startsWith("❌") 
            ? `<div class="alert alert-warning mt-2">⚠️ Este correo no tiene mecanismos de autenticación válidos.</div>` 
            : ""}
        </div>
  
        <div class="border rounded p-3 mb-3 bg-light">
          <h6 class="fw-bold">🔍 Motivos del Análisis</h6>
          ${data.reasons.length > 0 
            ? `<ul class="list-group">${data.reasons.map(m => `<li class="list-group-item">${m}</li>`).join("")}</ul>` 
            : `<p class="text-muted">No se han identificado motivos específicos.</p>`}
        </div>
  
        <div class="border rounded p-3 mb-3 bg-light">
          <h6 class="fw-bold">📎 Archivos Adjuntos</h6>
          ${data.attachments.length > 0 
            ? `<ul class="list-group">${data.attachments.map(a => {
                if (a.includes("🚨")) return `<li class="list-group-item"><span class="text-danger">Phishing 🚨 ${a}</span></li>`;
                if (a.includes("⚠️")) return `<li class="list-group-item"><span class="text-warning">Sospechoso ⚠️ ${a}</span></li>`;
                return `<li class="list-group-item"><span class="text-success">Seguro ✅ ${a}</span></li>`;
              }).join("")}</ul>` 
            : `<p class="text-muted">No hay archivos adjuntos en este correo.</p>`}
        </div>
      `;
  
      // Mostrar el modal bonito con Bootstrap
      const modal = new bootstrap.Modal(document.getElementById("resultadoModal"));
      modal.show();
  
    } catch (err) {
      alert("❌ Hubo un problema al analizar el archivo.");
      console.error(err);
    }
  });
  