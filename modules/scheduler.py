import schedule
import time
import threading

from modules.utils import get_emails_without_session, send_telegram_alert


def auto_scan_emails():
    """
    Escanea correos de forma automática y envía alerta si se detecta phishing.
    """
    emails = get_emails_without_session(limit=10)
    for email in emails:
        if email['is_phishing'].startswith("Phishing"):
            send_telegram_alert({
                "from": email["from"],
                "subject": email["subject"]
            }, email["is_phishing"])


def loop():
    """
    Bucle que ejecuta las tareas programadas.
    """
    schedule.every(5).minutes.do(auto_scan_emails)
    while True:
        schedule.run_pending()
        time.sleep(60)


def run():
    """
    Inicia el hilo en segundo plano para el escaneo automático.
    """
    threading.Thread(target=loop, daemon=True).start()
