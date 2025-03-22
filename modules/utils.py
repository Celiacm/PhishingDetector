import requests
import logging
import os

logger = logging.getLogger(__name__)

# Variables de entorno necesarias para Telegram
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_telegram_alert(email_info, status):
    """
    Envía un mensaje de alerta vía Telegram cuando se detecta un correo de alto riesgo de phishing.
    email_info: diccionario con claves "from" y "subject" del correo.
    status: estado de phishing (string) detectado.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("⚠️ Token de Telegram o Chat ID no configurados. No se envió alerta.")
        return
    message = ("🚨 *ALERTA DE PHISHING DETECTADO* 🚨\n\n"
               "📧 *Correo sospechoso detectado*\n"
               f"🔴 *Estado:* {status}\n"
               f"📨 *Remitente:* {email_info.get('from')}\n"
               f"📢 *Asunto:* {email_info.get('subject')}\n")
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        })
        logger.info("🚀 Alerta de Telegram enviada correctamente.")
    except Exception as e:
        logger.error(f"Error al enviar alerta de Telegram: {e}")
