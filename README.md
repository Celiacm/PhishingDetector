# PhishingDetector
PhishingDetector 🛡️

PhishingDetector es un sistema web desarrollado con Flask que permite analizar correos electrónicos en busca de intentos de phishing, utilizando autenticación SPF, DKIM, DMARC, reglas YARA, integración con VirusTotal y alertas por Telegram. Incluye una interfaz web intuitiva que permite ver reportes, métricas y realizar análisis manuales.

🌐 Objetivo General

Ayudar a personas y organizaciones a identificar claramente correos electrónicos fraudulentos y sospechosos, reduciendo la probabilidad de caer en fraudes y fortaleciendo la seguridad digital frente a amenazas en constante evolución.

🌟 Objetivos Específicos (SMART)

Desarrollar un sistema de detección de phishing en tiempo real.

Implementar análisis de archivos adjuntos con reglas YARA y VirusTotal ✔️

Enviar alertas automáticas por Telegram cuando se detecta phishing ✔️

Mostrar una interfaz web con reportes, métricas y análisis ✔️

Aumentar la precisión de detección en un 70% durante un periodo de 3 meses

📖 Tecnologías utilizadas

Flask (framework web en Python)

SQLite (base de datos local)

SPF, DKIM, DMARC (protocolos de autenticación)

YARA (análisis de patrones de malware)

VirusTotal API (análisis antivirus)

Telegram Bot API (alertas en tiempo real)

HTML, Bootstrap y Chart.js (interfaz gráfica)


🔎 Características principales

Autenticación mediante Gmail (OAuth2)

Análisis automático y manual de correos

Verificación SPF / DKIM / DMARC

Análisis de adjuntos con YARA y VirusTotal

Reportes estadísticos con gráficas

Exportación a CSV y PDF

Alerta inmediata en Telegram si hay phishing crítico

Modo prueba para validación controlada

Métricas de precisión, sensibilidad y especificidad






