# modules/scheduler.py
import schedule
import threading
import time


def auto_scan_emails():
    from modules.db import get_emails_without_session  # Importación dentro de la función
    print("⏱️ Escaneo automático en segundo plano...")
    get_emails_without_session(limit=10)


def run():
    schedule.every(5).minutes.do(auto_scan_emails)
    def loop():
        while True:
            schedule.run_pending()
            time.sleep(60)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
