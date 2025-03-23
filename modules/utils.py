# utils.py
import requests
import os
import imaplib

import modules.email_analysis as email_analysis

def send_telegram_alert(data, status):
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    mensaje = f"🚨 ALERTA DE PHISHING 🚨\nRemitente: {data['from']}\nAsunto: {data['subject']}\nEstado: {status}"
    try:
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      data={"chat_id": chat_id, "text": mensaje})
    except Exception as e:
        print("❌ Error enviando alerta Telegram:", e)

def get_emails_without_session(limit=10):
    """
    Recupera correos de Gmail sin usar la sesión de Flask (útil para procesos en segundo plano).
    Usa las variables de entorno OAUTH_ACCESS_TOKEN y OAUTH_EMAIL.
    Limita la cantidad de correos recuperados a `limit` más recientes.
    """
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
                    import email as email_module
                    from email import policy
                    msg = email_module.message_from_bytes(msg_bytes, policy=policy.default)
                    subject = msg.get("subject", "(Sin asunto)")
                    sender = msg.get("from", "Desconocido")
                    # Obtener texto del correo
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
                    phishing_status = email_analysis.is_phishing(body, sender, subject, email_raw=msg_bytes)[0]
                    # Si es phishing de alto riesgo, alertar por Telegram
                    if phishing_status.startswith("Phishing"):
                        send_telegram_alert({"from": sender, "subject": subject}, phishing_status)
                    emails.append({
                        "subject": subject,
                        "from": sender,
                        "is_phishing": phishing_status
                        # Nota: Detalles y adjuntos omitidos por eficiencia en escaneo automático
                    })
        mail.logout()
        print(f"📩 Escaneo automático completado. Correos analizados: {len(emails)}.")
    except Exception as e:
        print(f"⚠️ Error en escaneo automático de correos: {e}")
        return []
    return emails


