const frases = [
    "El 91% de los ataques cibernéticos comienzan con un correo de phishing. ¡Revisa bien tus mensajes!",
    "Los correos de phishing suelen usar urgencia como estrategia. Si algo parece demasiado urgente, piénsalo dos veces.",
    "Más del 70% de los correos fraudulentos usan dominios que imitan empresas legítimas."
];

const quiz = [
    {
        pregunta: "¿Cómo puedes detectar un correo de phishing?",
        opciones: ["A) Comprobar el dominio y los enlaces", "B) Hacer clic rápido y ver qué pasa"],
        correcta: 0,
        explicacion: "Siempre revisa los enlaces antes de hacer clic y verifica el remitente."
    },
    {
        pregunta: "¿Qué debes hacer si recibes un correo sospechoso?",
        opciones: ["A) Reportarlo y eliminarlo", "B) Responder y preguntar si es legítimo"],
        correcta: 0,
        explicacion: "Nunca respondas a correos sospechosos. Es mejor reportarlos y eliminarlos."
    }
];

function mostrarFrase() {
    const index = Math.floor(Math.random() * frases.length);
    document.getElementById("frase").innerText = frases[index];
}

function mostrarQuiz() {
    const index = Math.floor(Math.random() * quiz.length);
    const pregunta = quiz[index];
    document.getElementById("pregunta").innerText = pregunta.pregunta;
    document.getElementById("opcion1").innerText = pregunta.opciones[0];
    document.getElementById("opcion2").innerText = pregunta.opciones[1];
    document.getElementById("opcion1").onclick = () => mostrarResultado(index, 0);
    document.getElementById("opcion2").onclick = () => mostrarResultado(index, 1);
}

function mostrarResultado(index, seleccion) {
    const resultadoBox = document.getElementById("resultado");
    if (quiz[index].correcta === seleccion) {
        resultadoBox.innerHTML = "✅ ¡Correcto!";
    } else {
        resultadoBox.innerHTML = "❌ Incorrecto. " + quiz[index].explicacion;
    }
}

function showSection(section) {
    document.querySelectorAll('.section').forEach(div => div.classList.add('hidden'));
    document.getElementById(section).classList.remove('hidden');
}

function verDetalles(index) {
    const modalBody = document.getElementById("detallesCorreo");
    modalBody.innerHTML = "<p class='text-center text-muted'>Cargando detalles...</p>";
    fetch(`/detalles_correo/${index}`)
        .then(response => {
            if (!response.ok) throw new Error("Error al obtener los detalles del correo.");
            return response.text();
        })
        .then(data => modalBody.innerHTML = data)
        .catch(error => {
            modalBody.innerHTML = `<p class='text-danger text-center'>No se pudieron cargar los detalles.</p>`;
            console.error("Error:", error);
        });

    new bootstrap.Modal(document.getElementById("modalDetalles")).show();
}

document.addEventListener("DOMContentLoaded", function () {
    mostrarFrase();
    mostrarQuiz();
    setTimeout(() => {
        document.getElementById("loading").style.display = "none";
    }, 1500);

    // Obtener métricas
    fetch('/metricas')
        .then(response => response.json())
        .then(data => {
            document.getElementById("precision").innerText = data.precision;
            document.getElementById("sensibilidad").innerText = data.sensibilidad;
            document.getElementById("especificidad").innerText = data.especificidad;
        })
        .catch(error => {
            console.error("Error al obtener métricas:", error);
        });

    // Cargar reportes
    fetch('/reportes')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.warn(data.error);
                document.getElementById("errorReportes").style.display = "block";
            } else {
                document.getElementById("errorReportes").style.display = "none";
                renderCharts(data.phishing_stats, data.attachment_stats, data.trends);
            }
        })
        .catch(error => {
            console.error("Error al cargar reportes:", error);
            document.getElementById("errorReportes").style.display = "block";
        });
});

function renderCharts(phishingData, attachmentsData, trendsData) {
    const phishingCtx = document.getElementById('phishingChart').getContext('2d');
    new Chart(phishingCtx, {
        type: 'doughnut',
        data: {
            labels: ['Seguro ✅', 'Sospechoso ⚠️', 'Phishing 🚨'],
            datasets: [{ data: phishingData, backgroundColor: ['green', 'orange', 'red'] }]
        }
    });

    const attachmentsCtx = document.getElementById('attachmentsChart').getContext('2d');
    new Chart(attachmentsCtx, {
        type: 'bar',
        data: {
            labels: ['Limpios ✅', 'Sospechosos ⚠️', 'Peligrosos 🚨'],
            datasets: [{ data: attachmentsData, backgroundColor: ['blue', 'yellow', 'red'] }]
        }
    });

    if (trendsData.dates.length > 0) {
        const trendsCtx = document.getElementById('phishingTrendsChart').getContext('2d');
        new Chart(trendsCtx, {
            type: 'line',
            data: {
                labels: trendsData.dates,
                datasets: [{
                    label: 'Correos Phishing por Día 🚨',
                    data: trendsData.counts,
                    borderColor: 'red',
                    backgroundColor: 'rgba(255, 0, 0, 0.2)',
                    fill: true
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                }
            }
        });
    } else {
        document.getElementById("phishingTrendsChart").outerHTML =
            "<p class='text-muted text-center'>No hay datos de tendencias aún.</p>";
    }
}
