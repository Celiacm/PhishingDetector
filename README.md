🛡️ PhishingDetector
PhishingDetector es un sistema web desarrollado con Flask que permite analizar correos electrónicos para detectar posibles intentos de phishing.
Utiliza autenticación SPF, DKIM, DMARC, reglas YARA, integración con VirusTotal y alertas automáticas por Telegram.
El sistema incluye una interfaz web intuitiva para visualizar reportes, métricas y realizar análisis manuales o automáticos.

🌐 Objetivo General
Fortalecer la seguridad digital de personas y organizaciones mediante la identificación clara de correos electrónicos fraudulentos o sospechosos, reduciendo el riesgo de ataques de phishing.

🎯 Objetivos Específicos (SMART)
🛡️ Desarrollar un sistema de detección de phishing en tiempo real.

🛡️ Implementar análisis de archivos adjuntos mediante reglas YARA y escaneos en VirusTotal.

🛡️ Enviar alertas automáticas por Telegram cuando se detecte phishing.

🛡️ Visualizar reportes y métricas de análisis a través de una interfaz web.

🛡️ Aumentar la precisión de detección de correos de phishing en un 70% durante un periodo de 3 meses.

🛠️ Tecnologías Utilizadas
Tecnología	Descripción
Flask	Framework web en Python
SQLite	Base de datos ligera local
SPF, DKIM, DMARC	Protocolos de autenticación de correo
YARA	Análisis de patrones y malware en adjuntos
VirusTotal API	Escaneo antivirus en enlaces y archivos
Telegram Bot API	Envío de alertas en tiempo real
HTML, Bootstrap, Chart.js	Diseño y visualización gráfica
🔍 Características Principales
Autenticación OAuth2 mediante Gmail.

Análisis automático de correos al iniciar sesión.

Carga manual de correos en formato .eml.

Verificación de autenticación SPF, DKIM y DMARC.

Análisis de adjuntos sospechosos usando YARA y VirusTotal.

Detección de enlaces sospechosos en el cuerpo del correo.

Sistema de puntuación de riesgo y clasificación (Seguro, Sospechoso, Phishing).

Reportes estadísticos interactivos con gráficos.

Exportación de resultados a CSV y PDF.

Alertas inmediatas en Telegram ante detecciones críticas.

Modo prueba para realizar validaciones manuales.

Métricas avanzadas: Precisión, Sensibilidad, Especificidad.

📈 Métricas del Sistema
El sistema mide su efectividad a través de:

Precisión (Accuracy)

Sensibilidad (Recall)

Especificidad (Specificity)

Estas métricas permiten evaluar y mejorar continuamente el rendimiento del motor de detección.

🚀 Instalación y Uso Rápido
Clona el repositorio:

bash
Copiar
Editar
git clone https://github.com/Celiacm/PhishingDetector.git
cd PhishingDetector
Instala las dependencias:

bash
Copiar
Editar
pip install -r requirements.txt
Configura el archivo .env con tus claves:

bash
Copiar
Editar
# Ejemplo de .env
OAUTH_ACCESS_TOKEN=your_access_token
OAUTH_EMAIL=your_email@gmail.com
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
VIRUSTOTAL_API_KEY=your_virustotal_key
SECRET_KEY=your_flask_secret_key
Ejecuta la aplicación:

bash
Copiar
Editar
python app.py
Accede al sistema en tu navegador:

cpp
Copiar
Editar
http://127.0.0.1:5000/
🧹 Consideraciones de Seguridad
Nunca subas tu archivo .env al repositorio público.

Protege tus claves de OAuth2, Telegram y VirusTotal.

Utiliza un .gitignore adecuado para ocultar archivos sensibles.