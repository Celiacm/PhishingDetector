import os
import imaplib
import requests
import email as email_module
from email import policy
import modules.email_analysis as email_analysis
import modules.db as db
from modules.helpers import score_a_estado





def send_telegram_alert(email_data, riesgo):
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return

    msg = f"🚨 Detección de {riesgo}\nRemitente: {email_data['from']}\nAsunto: {email_data['subject']}"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {"chat_id": chat_id, "text": msg}
    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"Error enviando alerta: {e}")

def get_emails_without_session(limit=10):
    imap_server = os.environ.get("IMAP_SERVER", "imap.gmail.com")
    token = os.environ.get("OAUTH_ACCESS_TOKEN")
    email_account = os.environ.get("OAUTH_EMAIL")
    if not token or not email_account:
        print("⚠️ Credenciales OAuth no disponibles para escaneo automático.")
        return []

    emails = []
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.authenticate("XOAUTH2", lambda x: f"user={email_account}\1auth=Bearer {token}\1\1")
        mail.select("inbox")
        result, data = mail.search(None, "ALL")
        if result != "OK" or not data or not data[0]:
            print("⚠️ No se pudieron recuperar correos en escaneo automático (bandeja vacía o error).")
            return []

        email_ids = data[0].split()
        if limit:
            email_ids = email_ids[-limit:]
        print(f"🔍 Escaneo automático: {len(email_ids)} correos a procesar.")

        for e_id in email_ids:
            
            result, msg_data = mail.fetch(e_id, "(RFC822)")
            if result != "OK":
                print(f"⚠️ Error al obtener (auto) el correo ID {e_id}.")
                continue

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg_bytes = response_part[1]
                  
                    msg = email_module.message_from_bytes(msg_bytes, policy=policy.default)
                    subject = msg.get("subject", "(Sin asunto)")
                    sender = msg.get("from", "Desconocido")
                    # Evitar volver a analizar remitentes ya procesados
                    if db.existe_remitente(sender):
                        print(f"🛑 Ya existe un análisis del remitente: {sender}. Se omite.")
                        continue
                    
                    if db.get_email_by_message_id(message_id):
                        print(f"📌 Correo ya analizado (Message-ID duplicado): {message_id}")
                        continue



                    message_id = msg.get("Message-ID", "").strip()

                    body = ""
                    try:
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                                    break
                        else:
                            body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                    except Exception as e:
                        print(f"⚠️ Error leyendo cuerpo de correo (auto) ID {e_id}: {e}")
                        continue

                    resultado = email_analysis.is_phishing({
                        "body": body,
                        "sender": sender,
                        "subject": subject,
                        "email_raw": msg_bytes
                    })

                    phishing_status = resultado["estado"]
                    reasons = resultado["motivos"]
                    score = resultado["score"]


                    if phishing_status.startswith("Phishing"):
                        send_telegram_alert({"from": sender, "subject": subject}, phishing_status)


                    score_limitado = min(score, 15)

                    email_data = {
                        "subject": subject,
                        "from": sender,
                        "spf_result": None,
                        "dkim_result": None,
                        "dmarc_result": None,
                        "attachments": [],
                        "message_id": message_id,
                        "reasons": reasons,
                        "score": score_limitado,
                        "estado": score_a_estado(score_limitado),   
                        "user_email": email_account
                    }
                    db.save_email_to_db(email_data)

                    emails.append(email_data)

        mail.logout()
        print(f"📩 Escaneo automático completado. Correos analizados: {len(emails)}.")

    except Exception as e:
        print(f"⚠️ Error en escaneo automático de correos: {e}")
        return []

    return emails

