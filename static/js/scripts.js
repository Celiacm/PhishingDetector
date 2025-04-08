document.addEventListener("DOMContentLoaded", () => {
  const loading = document.getElementById("loading");
  if (loading) loading.style.display = "none";

  showSection("inicio");
  cargarReportes();
  cargarResumenInicio();
  actualizarBarraRiesgo();
  mostrarBannerCookiesSiEsNecesario();
  configurarFeedback();
  estadoSistema();
  cargarMetricas();

});



function showSection(sectionId) {
  document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
  const target = document.getElementById(sectionId);
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
            label: "Correos por Clasificación",
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
        },
        options: {
          scales: {
            x: {
              ticks: {
                maxRotation: 45,
                minRotation: 45,
                autoSkip: true,
                maxTicksLimit: 10
              }
            },
            y: {
              beginAtZero: true
            }
          }
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
        },
        options: {
          plugins: {
            title: {
              display: true,
              text: 'Correos totales por día',
              font: {
                size: 16,
                weight: 'bold'
              },
              padding: {
                top: 10,
                bottom: 10
              }
            }
          },
          
        }
        
      });

      const ctx4 = document.getElementById("totalChart").getContext("2d");
      new Chart(ctx4, {
        type: "bar",
        data: {
          labels: data.timeline.dates,
          datasets: [{
            label: "Correos Totales por Día",
            data: data.timeline.totalCounts,
            backgroundColor: "rgba(13, 110, 253, 0.7)"
          }]
        },
        options: {
          plugins: {
            title: {
              display: true,
              text: 'Correos Totales por Día',
            }
          }
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

        // Actualizar barra
        const barra = document.getElementById("barraRiesgo");
        barra.classList.remove("bg-success", "bg-warning", "bg-danger");

        if (riesgo < 30) {
          barra.classList.add("bg-success");
        } else if (riesgo < 70) {
          barra.classList.add("bg-warning");
        } else {
          barra.classList.add("bg-danger");
        }

        barra.style.width = riesgo + "%";
        barra.innerText = riesgo + "%";


        // Mostrar gauge
        mostrarGaugeRiesgo(parseFloat(riesgo));
      }
    });
}

function mostrarGaugeRiesgo(valor) {
  let colorGauge = "#198754"; // Verde
  let textoNivel = "🟢 Riesgo Bajo";

  if (valor > 70) {
    colorGauge = "#dc3545"; // Rojo
    textoNivel = "🔴 Riesgo Alto";
  } else if (valor > 30) {
    colorGauge = "#ffc107"; // Amarillo
    textoNivel = "🟡 Riesgo Medio";
  }

  const opts = {
    angle: 0,
    lineWidth: 0.3,
    radiusScale: 1,
    pointer: {
      length: 0.6,
      strokeWidth: 0.04,
      color: colorGauge
    },
    limitMax: false,
    limitMin: false,
    generateGradient: true,
    colorStart: colorGauge,
    colorStop: colorGauge,
    strokeColor: "#E0E0E0",
    highDpiSupport: true
  };

  const target = document.getElementById("gaugeRiesgo");
  const gauge = new Gauge(target).setOptions(opts);
  gauge.maxValue = 100;
  gauge.setMinValue(0);
  gauge.animationSpeed = 32;
  gauge.set(valor);

  // Mostrar texto de porcentaje y nivel
  const textoRiesgo = document.getElementById("textoRiesgo");
  textoRiesgo.innerHTML = `${textoNivel} (${valor.toFixed(1)}%)`;
}





document.addEventListener("DOMContentLoaded", () => {
  const filtroEstado = document.getElementById("filtroEstado");
  const busquedaTabla = document.getElementById("busquedaTabla");

  if (filtroEstado && busquedaTabla) {
    filtroEstado.addEventListener("change", filtrarTabla);
    busquedaTabla.addEventListener("keyup", filtrarTabla);
  }

  function filtrarTabla() {
    const estado = filtroEstado.value.toLowerCase();
    const busqueda = busquedaTabla.value.toLowerCase();
    document.querySelectorAll("#historial tbody tr").forEach(row => {
      const texto = row.textContent.toLowerCase();
      const coincideEstado = !estado || texto.includes(estado);
      const coincideBusqueda = !busqueda || texto.includes(busqueda);
      row.style.display = (coincideEstado && coincideBusqueda) ? "" : "none";
    });
  }
});





document.addEventListener("DOMContentLoaded", () => {
  const formTest = document.getElementById("formularioTest");

  if (formTest) {
    formTest.addEventListener("submit", async (e) => {
      e.preventDefault();

      const formData = new FormData(formTest);

      try {
        const response = await fetch("/enviar_test", {
          method: "POST",
          body: formData
        });

        if (!response.ok) throw new Error("Error al enviar el test");

        const data = await response.json();

        // Mostrar el resultado en el modal
        const contenido = document.getElementById("contenidoModalResultadoTest");
        contenido.innerText = data.mensaje;

        const modal = new bootstrap.Modal(document.getElementById("modalResultadoTest"));
        modal.show();
      } catch (err) {
        alert("❌ Hubo un problema al procesar el test.");
        console.error(err);
      }
    });
  }
});


function abrirMiniJuego(tipo) {
  switch (tipo) {
    case "visual":
      abrirJuegoVisual();
      break;
    case "enlaces":
      abrirJuegoEnlaces();
      break;
    case "rapido":
      abrirJuegoRapido();
      break;
    case "versus":
      abrirJuegoVersus();
      break;
    case "dominios":
      abrirJuegoDominios();
      break;
  }
}




function abrirJuegoDominios() {
  const modal = new bootstrap.Modal(document.getElementById("modalJuegoDominios"));
  modal.show();
}

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("formDominios");

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();

      const formData = new FormData(form);
      const res = await fetch("/evaluar_dominios", {
        method: "POST",
        body: formData
      });

      const data = await res.json();
      const r = document.getElementById("resultadoDominios");
      r.innerHTML = `
        <p>🎯 Aciertos del usuario: <strong>${data.usuario}/${data.total}</strong></p>
        <p>🤖 Coincidencias con el sistema: <strong>${data.coincidencias}/${data.total}</strong></p>
        ${data.usuario === data.coincidencias
          ? "<p class='text-success'>✅ ¡Coincidencia total con tu sistema!</p>"
          : "<p class='text-warning'>⚠️ Algunas respuestas no coincidieron.</p>"
        }
      `;
      r.style.display = "block";
      r.scrollIntoView({ behavior: "smooth" });
    });
  }
});


function abrirJuegoVisual() {
  const modal = new bootstrap.Modal(document.getElementById("modalJuegoVisual"));
  modal.show();
}

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("formVisual");

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();

      const formData = new FormData(form);
      const res = await fetch("/evaluar_visual", {
        method: "POST",
        body: formData
      });
      const data = await res.json();

      const resultado = document.getElementById("resultadoVisual");
      resultado.innerHTML = `
        <p>🎯 Aciertos del usuario: <strong>${data.usuario}/${data.total}</strong></p>
        <p>🤖 Coincidencias con el sistema: <strong>${data.coincidencias}/${data.total}</strong></p>
        ${data.coincidencias === data.total
          ? "<p class='text-success'>✅ ¡Coincidencia total!</p>"
          : "<p class='text-warning'>⚖️ Algunas respuestas no coincidieron con el sistema.</p>"
        }
      `;
      resultado.style.display = "block";
      resultado.scrollIntoView({ behavior: "smooth" });
    });
  }
});







function abrirJuegoEnlaces() {
  const modal = new bootstrap.Modal(document.getElementById("modalDesafioEnlaces"));
  modal.show();
}
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("formEnlaces");

  if (form) {
    form.addEventListener("submit", async function (e) {
      e.preventDefault();
    
      const formData = new FormData(form);
    
      try {
        const res = await fetch("/evaluar_enlaces", {
          method: "POST",
          body: formData
        });
    
        const data = await res.json();
    
        const resultado = document.getElementById("resultadoEnlaces");
        resultado.innerHTML = `
          <p>🎯 Aciertos del usuario: <strong>${data.usuario} / ${data.total}</strong></p>
          <p>🤖 Coincidencias con el sistema: <strong>${data.coincidencias} / ${data.total}</strong></p>
          ${data.coincidencias === data.total
            ? "<p class='text-success'>✅ ¡Coincidencia total con tu sistema!</p>"
            : "<p class='text-warning'>⚖️ Interesante... algunas respuestas difieren del motor.</p>"
          }
        `;
        resultado.style.display = "block";
        resultado.scrollIntoView({ behavior: "smooth" });
    
      } catch (err) {
        alert("❌ Error al evaluar los enlaces");
        console.error(err);
      }
    });
    
  }
});



let preguntasRapidas = [
  {
    id: "r1",
    texto: "Remitente: info@netflix.com\nAsunto: Tu factura mensual está lista.",
    correcto: "seguro"
  },
  {
    id: "r2",
    texto: "Remitente: soporte@paypal-alert.com\nAsunto: Verifica tu cuenta para evitar suspensiones.",
    correcto: "phishing"
  },
  {
    id: "r3",
    texto: "Remitente: microsoft@update.com\nAsunto: Tu licencia expirará hoy. Actualiza ya.",
    correcto: "phishing"
  }
];

let rondaActual = 0;
let aciertosRapidos = 0;
let coincidenciasRapidas = 0;
let temporizadorRapido = null;
let tiempo = 10;

function abrirJuegoRapido() {
  rondaActual = 0;
  aciertosRapidos = 0;
  coincidenciasRapidas = 0;
  document.getElementById("resultadoRapido").style.display = "none";
  const modal = new bootstrap.Modal(document.getElementById("modalJuegoRapido"));
  modal.show();
  siguientePreguntaRapida();
}

function siguientePreguntaRapida() {
  if (rondaActual >= preguntasRapidas.length) {
    mostrarResultadoRapido();
    return;
  }

  const pregunta = preguntasRapidas[rondaActual];
  document.getElementById("preguntaRapido").innerText = pregunta.texto;
  tiempo = 10;
  actualizarContadorRapido();
  temporizadorRapido = setInterval(() => {
    tiempo--;
    actualizarContadorRapido();
    if (tiempo === 0) {
      clearInterval(temporizadorRapido);
      responderRapido(null); // no respondió
    }
  }, 1000);
}

function actualizarContadorRapido() {
  const el = document.getElementById("contadorRapido");
  el.innerText = tiempo;
  el.style.color = tiempo <= 3 ? "red" : "#333";
}

async function responderRapido(respuesta) {
  clearInterval(temporizadorRapido);
  const pregunta = preguntasRapidas[rondaActual];

  if (respuesta && respuesta === pregunta.correcto) {
    aciertosRapidos++;
  }

  // Analizar con el sistema real
  const formData = new FormData();
  formData.append("texto", pregunta.texto);

  try {
    const res = await fetch("/analizar_respuesta_rapida", {
      method: "POST",
      body: formData
    });

    const data = await res.json();
    const sistema = data.resultado;
    if (sistema === respuesta) {
      coincidenciasRapidas++;
    }
  } catch (err) {
    console.error("Error al analizar:", err);
  }

  rondaActual++;
  setTimeout(siguientePreguntaRapida, 500);
}

function mostrarResultadoRapido() {
  const r = document.getElementById("resultadoRapido");
  r.innerHTML = `
    <p>🎯 Aciertos del usuario: <strong>${aciertosRapidos}/${preguntasRapidas.length}</strong></p>
    <p>🤖 Coincidencias con el sistema: <strong>${coincidenciasRapidas}/${preguntasRapidas.length}</strong></p>
  `;
  r.style.display = "block";
}




function abrirJuegoVersus() {
  document.getElementById("formVersus").reset();
  document.getElementById("resultadoVersus").style.display = "none";
  const modal = new bootstrap.Modal(document.getElementById("modalJuegoVersus"));
  modal.show();
}

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("formVersus");

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();

      const formData = new FormData(form);
      const res = await fetch("/evaluar_versus", {
        method: "POST",
        body: formData
      });

      const data = await res.json();
      const div = document.getElementById("resultadoVersus");

      div.innerHTML = `
        <p>👤 Tú dijiste: <strong>${data.usuario}</strong></p>
        <p>🤖 El sistema detectó: <strong>${data.sistema}</strong></p>
        ${data.usuario === data.sistema
          ? "<p class='text-success'>✅ ¡Coincidiste con el detector!</p>"
          : "<p class='text-danger'>⚠️ Respuesta distinta al análisis del sistema.</p>"
        }
      `;
      div.style.display = "block";
      div.scrollIntoView({ behavior: "smooth" });
    });
  }
});




function alternarTema() {
  const html = document.documentElement;
  const temaActual = html.dataset.bsTheme;
  const nuevoTema = temaActual === "dark" ? "light" : "dark";
  html.dataset.bsTheme = nuevoTema;
  localStorage.setItem("tema", nuevoTema);
}

document.addEventListener("DOMContentLoaded", () => {
  const temaGuardado = localStorage.getItem("tema") || "light";
  document.documentElement.dataset.bsTheme = temaGuardado;
});




document.addEventListener("DOMContentLoaded", () => {
  fetch("/metricas")
    .then(res => res.json())
    .then(data => {
      document.getElementById("total").textContent = data.total;
      document.getElementById("precision").textContent = data.precision + " %";
      document.getElementById("sensibilidad").textContent = data.sensibilidad + " %";
      document.getElementById("especificidad").textContent = data.especificidad + " %";
      document.getElementById("tiempo_analisis").textContent = data.tiempo_medio + " s";
      document.getElementById("porcentaje_sospechosos").textContent = data.porcentaje_sospechosos + " %";
      document.getElementById("ultimo_analisis").textContent = data.ultimo_analisis;
      document.getElementById("feedbackOk").textContent = data.feedback_correctos;
      document.getElementById("feedbackKo").textContent = data.feedback_incorrectos;

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

document.getElementById("emlForm").addEventListener("submit", function (e) {
  e.preventDefault();

  const formData = new FormData(this);

  fetch("/analyze_email_eml", {
    method: "POST",
    body: formData
  })
    .then(response => response.json())
    .then(data => {
      if (data.error) {
        alert("❌ " + data.error);
      } else {
        mostrarModalConDetalles(data);
      }
    })
    .catch(error => {
      console.error("Error al analizar:", error);
      alert("❌ Error inesperado al analizar el correo.");
    });
});

function mostrarModalConDetalles(data) {
  const modal = new bootstrap.Modal(document.getElementById("resultadoModal"));

  document.getElementById("modalAsunto").innerHTML = `<strong>📌</strong> ${data.subject || "(Sin asunto)"}`;
  document.getElementById("modalRemitente").innerHTML = `<strong>📨</strong> ${data.from || "(Remitente desconocido)"}`;
  document.getElementById("modalScore").innerHTML = `<strong>📊</strong> ${data.score}/15`;

  let estadoHtml = "";
  if (data.estado.includes("Phishing")) {
    estadoHtml = `<span class="text-danger fw-bold">🚨 ${data.estado}</span>`;
  } else if (data.estado.includes("Sospechoso")) {
    estadoHtml = `<span class="text-warning fw-bold">⚠️ ${data.estado}</span>`;
  } else {
    estadoHtml = `<span class="text-success fw-bold">✅ ${data.estado}</span>`;
  }
  document.getElementById("modalEstado").innerHTML = estadoHtml;

  document.getElementById("modalSPF").innerHTML = data.spf ? "✅ Válido" : "❌ Fallido";
  document.getElementById("modalDKIM").innerHTML = data.dkim ? "✅ Válido" : "❌ Fallido";
  document.getElementById("modalDMARC").innerHTML = data.dmarc ? "✅ Válido" : "❌ Fallido";

  const ulMotivos = document.getElementById("modalMotivos");
  ulMotivos.innerHTML = "";
  let motivos = [];
  try {
    motivos = typeof data.reasons === "string" ? JSON.parse(data.reasons) : data.reasons;
  } catch (e) {
    motivos = [];
  }

  if (motivos && motivos.length > 0) {
    motivos.forEach(m => {
      const div = document.createElement("div");
      div.className = "list-group-item";
      div.innerText = `🔎 ${m}`;
      ulMotivos.appendChild(div);
    });
  } else {
    const div = document.createElement("div");
    div.className = "list-group-item text-muted";
    div.innerText = "(Sin motivos disponibles)";
    ulMotivos.appendChild(div);
  }

  const ulAdjuntos = document.getElementById("modalAdjuntos");
  ulAdjuntos.innerHTML = "";
  if (data.attachments && data.attachments.length > 0) {
    data.attachments.forEach(adj => {
      const li = document.createElement("li");
      li.innerText = adj;
      ulAdjuntos.appendChild(li);
    });
  } else {
    ulAdjuntos.innerHTML = "<li class='text-muted'>Sin archivos adjuntos</li>";
  }

  document.getElementById("modalTiempo").innerText = data.tiempo?.toFixed(2) || "--";

  modal.show();
}




function showSection(sectionId) {
  const sections = document.querySelectorAll(".section");
  sections.forEach(section => section.classList.remove("active"));

  const target = document.getElementById(sectionId);
  if (target) {
    target.classList.add("active");
    target.style.display = "block";

    if (sectionId === "inicio") {
      actualizarBarraRiesgo();
    }

    if (sectionId === "reportes") {
      cargarReportes();   // ⬅️ volver a cargar los gráficos
    }
  }

  sections.forEach(section => {
    if (section.id !== sectionId) {
      section.style.display = "none";
    }
  });
}


  function aceptarCookies() {
    document.getElementById("cookie-banner").style.display = "none";
    document.cookie = "cookies_aceptadas=true; max-age=" + (60 * 60 * 24 * 365); // 1 año
  }
  
  function rechazarCookies() {
    document.getElementById("cookie-banner").style.display = "none";
  }
  
  function mostrarBannerCookiesSiEsNecesario() {
    const cookies = document.cookie.split(";").map(c => c.trim());
    const yaAceptadas = cookies.find(c => c.startsWith("cookies_aceptadas="));
    if (!yaAceptadas) {
      document.getElementById("cookie-banner").style.display = "block";
    }
  }
  
  document.addEventListener("DOMContentLoaded", mostrarBannerCookiesSiEsNecesario);

  function configurarFeedback() {
    document.querySelectorAll(".feedback-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const modal = btn.closest(".modal");
        const idCorreo = modal.querySelector(".correo-id")?.value;
        const correcto = btn.dataset.correcto === "true";
  
        if (!idCorreo) {
          console.error("❌ ID de correo no encontrado.");
          return;
        }
  
        fetch("/feedback", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: `correo_id=${idCorreo}&correcto=${correcto}`
        })
        .then(res => {
          if (res.ok) {
            mostrarToast("✅ Feedback guardado. ¡Gracias!");
            modal.querySelector(".modal-body").insertAdjacentHTML("beforeend",
              `<div class="alert alert-success mt-3">Gracias por tu feedback.</div>`);
            
            // 🔥 NUEVO: actualizar métricas y resumen
            cargarMetricas();
            cargarResumenInicio();
          } else {
            mostrarToast("❌ Error al guardar feedback.");
          }
        })
        .catch(err => console.error("❌ Error en petición:", err));
      });
    });
  }
  


  function mostrarToast(mensaje) {
    const toast = document.getElementById("toastFeedback");
    const msg = document.getElementById("toastFeedbackMsg");
  
    msg.textContent = mensaje;
    toast.classList.add("show");
  
    setTimeout(() => {
      toast.classList.remove("show");
    }, 3000);
  }
  
  document.getElementById("correo_id_modal").value = data.id;  // Asegúrate de tener el ID
  

  
  