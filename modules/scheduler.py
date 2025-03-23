# scheduler.py
import schedule
import time
import threading
from modules.utils import send_telegram_alert
from modules.utils import get_emails_without_session

def auto_scan_emails():
    emails = get_emails_without_session(limit=10)
    for email in emails:
        if email['is_phishing'].startswith("Phishing"):
            send_telegram_alert({"from": email["from"], "subject": email["subject"]}, email["is_phishing"])

def loop():
    schedule.every(5).minutes.do(auto_scan_emails)
    while True:
        schedule.run_pending()
        time.sleep(60)

def run():
    threading.Thread(target=loop, daemon=True).start()