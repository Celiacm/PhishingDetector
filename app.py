from flask import Flask, redirect, url_for, session, request, render_template, jsonify, Response
from requests_oauthlib import OAuth2Session
from bs4 import BeautifulSoup  # Necesario para extraer enlaces de HTML
from collections import Counter
from datetime import datetime
import os, jwt, imaplib, email, json, re, unicodedata, requests, email.policy, yara, io
import quopri, dns.resolver, dkim, schedule, time, threading, csv

import urllib.parse
from email import policy

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "clave_secreta_super_segura")
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


# 🔑 Token del bot de Telegram (REEMPLAZA con el tuyo)
TELEGRAM_BOT_TOKEN = "8143866019:AAHuvoken_pyqWkLLtL4h57mYq12-ao4fks"

# 📩 Tu Chat ID (REEMPLAZA con el tuyo)
TELEGRAM_CHAT_ID = "2064396630"


# 🔑 API Key de VirusTotal 
VIRUSTOTAL_API_KEY = "84163cf4e7c1e47c41cfc7de9ed6d8c2305e8612875a646c8f0aaaf2c1fc6819"

# 📂 Carpeta donde se guardarán los archivos temporales
ATTACHMENT_FOLDER = "attachments"



def send_telegram_alert(email, status):
    """Envía una alerta a Telegram si se detecta phishing de alto riesgo."""
    message = f"🚨 *ALERTA DE PHISHING DETECTADO* 🚨\n\n"
    message += f"📧 *Correo sospechoso detectado*\n"
    message += f"🔴 *Estado:* {status}\n"
    message += f"📨 *Remitente:* {email['from']}\n"
    message += f"📢 *Asunto:* {email['subject']}\n"
    
    # 📌 URL de la API de Telegram
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    # Enviar el mensaje
    requests.post(url, data={
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    })


YARA_RULES = """
rule DetectMaliciousFiles {
    meta:
        description = "Regla para detectar malware basado en patrones comunes"
        author = "TFG Seguridad"
        date = "2025-03-09"
        severity = "high"

    strings:
        $exe_string = "This program cannot be run in DOS mode"
        $suspicious1 = "malware"
        $suspicious2 = "trojan"
        $suspicious3 = "ransomware"
        $suspicious4 = "keylogger"
        $suspicious5 = "password stealer"
        $suspicious6 = "remote access tool"
        $suspicious7 = "backdoor"
        $suspicious8 = "exploit"
        
        $js_obfuscation1 = "eval(String.fromCharCode("
        $js_obfuscation2 = "unescape("
        $powershell_malicious = "IEX(New-Object Net.WebClient).DownloadString"
        $bat_malicious = "cmd /c powershell -"
        
        $macro1 = "Sub AutoOpen()"
        $macro2 = "Sub Document_Open()"
        $macro3 = "CreateObject(\\"Scripting.FileSystemObject\\")"
        $macro4 = "CreateObject(\\"WScript.Shell\\")"

        $zip_suspicious1 = "This zip file contains malware"
        $zip_suspicious2 = "This archive is encrypted and contains malware"

    condition:
        (uint16(0) == 0x5A4D) or 
        any of ($suspicious1, $suspicious2, $suspicious3, $suspicious4, $suspicious5, $suspicious6, $suspicious7, $suspicious8) or 
        any of ($js_obfuscation1, $js_obfuscation2, $powershell_malicious, $bat_malicious) or 
        any of ($macro1, $macro2, $macro3, $macro4) or 
        any of ($zip_suspicious1, $zip_suspicious2) or
        any of them
}
"""




def get_emails_without_session():
    # Recupera correos de Gmail sin usar session de Flask (para hilos)
    try:
        imap_server = OAUTH_CONFIG["gmail"]["imap_server"]
        token = os.environ.get("OAUTH_ACCESS_TOKEN")  # Usa una variable de entorno
        email_user = os.environ.get("OAUTH_EMAIL")  # También almacena el correo

        if not token or not email_user:
            print("⚠️ No se encontró token OAuth o usuario de correo.")
            return []

        mail = imaplib.IMAP4_SSL(imap_server)
        mail.authenticate("XOAUTH2", lambda x: f"user={email_user}\1auth=Bearer {token}\1\1")
        mail.select("inbox")
        result, data = mail.search(None, "ALL")

        if result != "OK" or not data[0]:
            print("⚠️ No se pudieron recuperar correos o la bandeja está vacía.")
            return []

        email_ids = data[0].split()[-10:]  # Últimos 10 correos
        emails = []

        print(f"📩 Se encontraron {len(email_ids)} correos para procesar.")

        for e_id in email_ids:
            result, msg_data = mail.fetch(e_id, "(RFC822)")
            if result != "OK":
                print(f"⚠️ Error al obtener el correo con ID {e_id}.")
                continue

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg_bytes = response_part[1]
                    msg = email.message_from_bytes(msg_bytes, policy=policy.default)

                    subject = msg.get("subject", "(Sin asunto)")
                    sender = msg.get("from", "Desconocido")
                    body = ""

                    try:
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    try:
                                        body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                                    except UnicodeDecodeError:
                                        body = part.get_payload(decode=True).decode("latin-1", errors="ignore")
                                    break  
                        else:
                            try:
                                body = msg.get_payload(decode=True).decode("utf-8")
                            except UnicodeDecodeError:
                                body = msg.get_payload(decode=True).decode("latin-1", errors="ignore")

                    except Exception as e:
                        print(f"⚠️ Error al procesar el contenido del correo: {e}")
                        continue  # Evita que un correo defectuoso detenga el procesamiento

                    print(f"📨 Procesando correo de: {sender} | Asunto: {subject}")

                    # 🔍 Verificación de phishing
                    phishing_status = is_phishing(body, sender, subject, email_raw=msg_bytes)

                    # 🚨 Enviar alerta si es Phishing de alto riesgo
                    if phishing_status == "Phishing 🚨 (Alto riesgo)":
                        send_telegram_alert({
                            "from": sender,
                            "subject": subject
                        }, phishing_status)

                    emails.append({
                        "subject": subject,
                        "from": sender,
                        "is_phishing": phishing_status
                    })

        mail.logout()
        print(f"✅ Correos recuperados correctamente: {len(emails)}")
        return emails

    except Exception as e:
        print(f"⚠️ Error al obtener correos en escaneo automático: {str(e)}")
        return []


# Función que ejecutará el escaneo automático cada X minutos
def auto_scan_emails():
    print("🔍 Iniciando escaneo automático de correos...")
    emails = get_emails_without_session()  # Llamamos a la nueva función SIN session de Flask
    print(f"📩 Escaneo completado. {len(emails)} correos procesados.")


# Programar el escaneo automático cada 5 minutos
schedule.every(5).minutes.do(auto_scan_emails)

# Función para ejecutar el escaneo en un hilo separado
def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)  # Esperar 1 minuto antes de volver a revisar tareas programadas

# Iniciar el escaneo automático en un hilo separado
scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()






# 📂 Asegurar que la carpeta de adjuntos existe
if not os.path.exists(ATTACHMENT_FOLDER):
    os.makedirs(ATTACHMENT_FOLDER)

# 🚀 Cargar reglas de YARA


try:
    yara_rules = yara.compile(source=YARA_RULES)
except yara.SyntaxError as e:
    print(f"⚠️ Error de sintaxis en las reglas YARA: {e}")
    exit(1)



def analyze_attachment(part):
    #Analiza archivos adjuntos en busca de amenazas
    filename = part.get_filename()
    if filename:
        file_data = part.get_payload(decode=True)
        if not file_data:
            return "⚠️ Archivo vacío o no pudo ser analizado."

        print(f"📂 Analizando adjunto: {filename}")

        # 🛑 Comprobar extensiones peligrosas
        dangerous_extensions = {".exe", ".js", ".bat", ".cmd", ".scr", ".pif", ".zip", ".rar", ".tar", ".gz"}
        file_extension = os.path.splitext(filename)[1].lower()

        if file_extension in dangerous_extensions:
            return f"🚨 Archivo peligroso detectado: {filename} ({file_extension})"

        # 📌 Guardar temporalmente el archivo
        file_path = os.path.join(ATTACHMENT_FOLDER, filename)
        with open(file_path, "wb") as f:
            f.write(file_data)

        # 🔍 Análisis con YARA
        yara_result = yara_rules.match(file_path)
        if yara_result:
            return f"🚨 Archivo sospechoso detectado con YARA: {yara_result}"

        # 🔍 Enviar archivo a VirusTotal para escaneo
        vt_result = scan_with_virustotal(file_path)
        return vt_result

    return "✅ No se detectaron amenazas en el adjunto."

def scan_with_virustotal(file_path):
    #Escanea un archivo en VirusTotal y devuelve el resultado
    try:
        with open(file_path, "rb") as f:
            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                files={"file": f}
            )
            json_response = response.json()
            if "error" in json_response:
                return "⚠️ No se pudo analizar en VirusTotal"
            return f"✅ Archivo analizado en VirusTotal: {json_response}"
    except Exception as e:
        return f"⚠️ Error al escanear en VirusTotal: {str(e)}"






# Cargar credenciales desde el archivo JSON
def load_credentials():
    with open("client_secret_319539446164-ta4n5cc4eu7sm63g75s0u52aefs1ckck.apps.googleusercontent.com.json") as f:
        creds = json.load(f)["web"]
    return creds

oauth_creds = load_credentials()

OAUTH_CONFIG = {
    "gmail": {
        "client_id": oauth_creds["client_id"],
        "client_secret": oauth_creds["client_secret"],
        "auth_url": oauth_creds["auth_uri"],
        "token_url": oauth_creds["token_uri"],
        "redirect_uri": "http://127.0.0.1:5000/callback/gmail",
        "scope": ["openid", "email", "profile", "https://mail.google.com/"],
        "imap_server": "imap.gmail.com"
    }
}

@app.route("/login/<provider>")
def login(provider):
    oauth = OAuth2Session(
        OAUTH_CONFIG[provider]["client_id"],
        scope=OAUTH_CONFIG[provider]["scope"],
        redirect_uri=OAUTH_CONFIG[provider]["redirect_uri"]
    )
    authorization_url, state = oauth.authorization_url(
        OAUTH_CONFIG[provider]["auth_url"],
        access_type="offline",
        prompt="consent"
    )
    session["oauth_state"] = state
    session["provider"] = provider
    return redirect(authorization_url)

@app.route("/callback/<provider>")
def callback(provider):
    oauth = OAuth2Session(
        OAUTH_CONFIG[provider]["client_id"],
        state=session.get("oauth_state"),
        redirect_uri=OAUTH_CONFIG[provider]["redirect_uri"]
    )
    token = oauth.fetch_token(
        OAUTH_CONFIG[provider]["token_url"],
        client_secret=OAUTH_CONFIG[provider]["client_secret"],
        authorization_response=request.url
    )
    user_info = oauth.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
    session["email"] = user_info.get("email")
    session["oauth_token"] = token

    if not session["email"]:
        return "⚠️ No se pudo obtener el correo electrónico.", 400
    
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


def check_spf(sender_email):
    #Verifica si el remitente está autorizado mediante SPF
    try:
        domain = sender_email.split("@")[-1]
        answers = dns.resolver.resolve(domain, 'TXT')
        for txt_record in answers:
            if "v=spf1" in str(txt_record):
                return f"✅ SPF encontrado: {txt_record}"
        return "⚠️ No hay registro SPF"
    except Exception as e:
        return f"⚠️ Error en la consulta SPF: {e}"



def check_dkim(email_raw):
    #Verifica si el correo tiene una firma DKIM válida
    try:
        if isinstance(email_raw, str):  # Convertir a bytes si es un string
            email_raw = email_raw.encode("utf-8", errors="ignore")
        signature = dkim.verify(email_raw)
        return "✅ DKIM válido" if signature else "❌ DKIM inválido"
    except Exception as e:
        return f"⚠️ Error en la verificación DKIM: {e}"






def check_dmarc(sender_email):
    #Consulta la política DMARC del dominio del remitente
    try:
        domain = sender_email.split("@")[-1]
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for txt_record in answers:
            if "v=DMARC1" in str(txt_record):
                return f"✅ DMARC encontrado: {txt_record}"
        return "⚠️ No hay política DMARC"
    except Exception as e:
        return f"⚠️ Error en la consulta DMARC: {e}"



def is_phishing(email_body, email_sender, email_subject, email_raw=None):
    #Analiza un correo para detectar phishing basado en puntuación de riesgo.

    ### ✅ CONFIGURACIONES GENERALES ###
    
    # 🏢 Lista de dominios confiables (empresas, universidades, etc.)
    TRUSTED_DOMAINS = {
        "paypal.com", "amazon.com", "microsoft.com", "google.com",
        "outlook.com", "hotmail.com", "adidas.com", "elpais.com",
        "bbva.com", "mit.edu", "harvard.edu"
    }

    # 🚫 Lista de dominios sospechosos (phishing, spam, apuestas, etc.)
    BLACKLISTED_DOMAINS = {
        "gophish.com", "ruleta.com", "trampasdejuego.com", "casino-online.com",
        "freegift.com", "secure-login.com", "phishing.com", "malware-site.com"
    }

    # 🔗 Lista de patrones de enlaces de phishing
    PHISHING_LINKS = [
        r"bit\.ly", r"tinyurl\.com", r"freegift.*", r"login-secure.*", 
        r"verify-.*", r"phish.*", r"\.html$"
    ]

    # 🔍 Lista de palabras clave sospechosas en phishing
    PHISHING_KEYWORDS = [
        r"urgente", r"inmediato", r"acción requerida", r"verifica.*cuenta",
        r"confirma.*identidad", r"problema.*seguridad", r"revisión obligatoria",
        r"clic.*aquí", r"inicie sesión aquí", r"compruebe su cuenta",
        r"descargar.*archivo", r"ingrese sus credenciales", r"su cuenta.*bloqueada",
        r"felicidades.*ganado", r"premio exclusivo", r"oferta limitada",
        r"transacción.*no autorizada", r"alerta.*bancaria", r"hemos recibido una solicitud de",
        r"su correo será desactivado"
    ]

    ### 🎯 INICIALIZACIÓN ###
    score = 0
    domain = email_sender.split("@")[-1].lower()

    print(f"\n📩 Analizando correo de: {email_sender} | Asunto: {email_subject}")


     ### 🔠 DETECCIÓN DE SPOOFING (SPF, DKIM, DMARC) ###
    spf_result = check_spf(email_sender)
    dmarc_result = check_dmarc(email_sender)
    if email_raw:
        try:
            dkim_result = check_dkim(email_raw)
        except Exception as e:
            dkim_result = f"⚠️ Error en DKIM: {str(e)}"
    else:
        dkim_result = "❌ No se puede verificar DKIM"


    print(f"🔎 SPF: {spf_result}")
    print(f"🔎 DMARC: {dmarc_result}")
    print(f"🔎 DKIM: {dkim_result}")

 # Penalizar correos sin autenticación válida
    if "⚠️" in spf_result:
        score += 3
    if "⚠️" in dmarc_result:
        score += 3
    if "❌" in dkim_result:
        score += 4

        ### 🔠 DETECCIÓN DE SPOOFING (Unicode y dominios) ###
    normalized = unicodedata.normalize("NFKD", email_sender)
    if email_sender != normalized:
        print("⚠️ Remitente con caracteres Unicode sospechosos (+3)")
        score += 3  

    if domain in BLACKLISTED_DOMAINS:
        print(f"🚨 Dominio en lista negra: {domain} (+5)")
        score += 5  
    elif domain not in TRUSTED_DOMAINS:
        print(f"⚠️ Dominio desconocido: {domain} (+2)")
        score += 2  

    # 🔥 Detección específica de GoPhish
    if "gophish" in domain:
        print(f"🚨 Remitente sospechoso de GoPhish detectado: {domain} (+6)")
        score += 6  


     ### 📝 DECODIFICAR EL CUERPO DEL CORREO PARA RECONSTRUIR URLs ###
    decoded_bytes = quopri.decodestring(email_body)  # Decodifica `quoted-printable`
    email_body_clean = decoded_bytes.decode("utf-8", errors="ignore")
    email_body_clean = urllib.parse.unquote_plus(email_body_clean)  # Decodifica `%XX`

    ### 🔗 DETECCIÓN MEJORADA DE ENLACES DE PHISHING ###
    
    # 1️⃣ Extraer URLs dentro de etiquetas <a href="...">
    soup = BeautifulSoup(email_body_clean, "html5lib")
    extracted_urls = [a["href"] for a in soup.find_all("a", href=True)]

    # 2️⃣ Extraer URLs de texto plano en el email
    extracted_urls += re.findall(r'https?://[^\s]+', email_body_clean)

    # 3️⃣ Reemplazar "hxxp://" por "http://"
    extracted_urls = [url.replace("hxxp://", "http://") for url in extracted_urls]

    print(f"🔗 URLs detectadas en el correo: {extracted_urls}")

    # 4️⃣ Normalizar `[.]` → `.` (ofuscación de dominios)
    extracted_urls = [re.sub(r"\[\.\]", ".", url) for url in extracted_urls]


    # 4️⃣ Analizar si las URLs son sospechosas
    for url in extracted_urls:
        if any(re.search(pattern, url, re.IGNORECASE) for pattern in PHISHING_LINKS):
            print(f"🚨 Enlace sospechoso detectado: {url} (+6)")
            score += 6  

    ### 📝 DETECCIÓN DE PALABRAS CLAVE DE PHISHING ###
    text_content = email_body + " " + email_subject
    for phrase in PHISHING_KEYWORDS:
        if re.search(phrase, text_content, re.IGNORECASE):
            print(f"⚠️ Palabra clave sospechosa detectada: {phrase} (+4)")
            score += 4  

    ### 🕵️ DETECCIÓN DE TEXTO INVISIBLE (evasión de detección) ###
    if re.search(r"<span.*style=['\"]display:\s*none['\"].*>.*</span>", email_body, re.IGNORECASE):
        print("🚨 Texto oculto detectado en el correo (+3)")
        score += 3  

    ### 📊 EVALUACIÓN FINAL ###
    print(f"📊 Puntaje total: {score}")

    if score >= 10:
        return "Phishing 🚨 (Alto riesgo)"
    elif score >= 5:
        return "Sospechoso ⚠️ (Riesgo moderado)"
    else:
        return "Seguro ✅ (Bajo riesgo)"



@app.route("/analyze_email", methods=["POST"])
def analyze_email():
    email_body = request.form.get("email_content")
    email_sender = request.form.get("email_sender")
    email_subject = request.form.get("email_subject")

    if not email_body or not email_sender or not email_subject:
        return "⚠️ Todos los campos son obligatorios.", 400

    is_suspicious = is_phishing(email_body, email_sender, email_subject)
    return render_template("index.html", emails=get_emails(), phishing_result=is_suspicious)



def get_emails():
    #Recupera los correos electrónicos recientes desde Gmail a través de IMAP y los analiza.
    provider = session.get("provider")
    if not provider:
        print("⚠️ No hay un proveedor autenticado.")
        return []
    
    imap_server = OAUTH_CONFIG[provider]["imap_server"]
    token = session.get("oauth_token", {}).get("access_token")
    email_user = session.get("email")
    
    if not token or not email_user:
        print("⚠️ No se encontró token OAuth o usuario de correo.")
        return []

    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.authenticate("XOAUTH2", lambda x: f"user={email_user}\1auth=Bearer {token}\1\1")
        mail.select("inbox")
        result, data = mail.search(None, "ALL")

        if result != "OK" or not data[0]:
            print("⚠️ No se pudieron recuperar correos o la bandeja está vacía.")
            return []

        email_ids = data[0].split()[-10:]  # Últimos 10 correos
        emails = []

        print(f"📩 Se encontraron {len(email_ids)} correos para procesar.")

        for e_id in email_ids:
            result, msg_data = mail.fetch(e_id, "(RFC822)")
            if result != "OK":
                print(f"⚠️ Error al obtener el correo con ID {e_id}.")
                continue

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg_bytes = response_part[1]
                    msg = email.message_from_bytes(msg_bytes, policy=policy.default)

                    subject = msg.get("subject", "(Sin asunto)")
                    sender = msg.get("from", "Desconocido")
                    body = ""

                    try:
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    try:
                                        body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                                    except UnicodeDecodeError:
                                        body = part.get_payload(decode=True).decode("latin-1", errors="ignore")
                                    break  
                        else:
                            try:
                                body = msg.get_payload(decode=True).decode("utf-8")
                            except UnicodeDecodeError:
                                body = msg.get_payload(decode=True).decode("latin-1", errors="ignore")

                    except Exception as e:
                        print(f"⚠️ Error al procesar el contenido del correo: {e}")
                        continue  # Evita que un correo defectuoso detenga el procesamiento

                    print(f"📨 Procesando correo de: {sender} | Asunto: {subject}")
                    attachments_analysis = []

                    # 📂 Extraer y analizar archivos adjuntos
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_maintype() == "multipart":
                                continue
                            if part.get_content_disposition() is None:
                                continue
                            attachment_result = analyze_attachment(part)
                            attachments_analysis.append(attachment_result)

                    # 🔎 Verificación SPF, DKIM y DMARC con datos seguros
                  
                    try:
                        # 🔍 Verificación de phishing con datos decodificados correctamente
                        phishing_status = is_phishing(body, sender, subject, email_raw=msg_bytes)

                        # 🔎 Verificación SPF, DKIM y DMARC con datos seguros
                        spf_status = check_spf(sender)
                        dmarc_status = check_dmarc(sender)
                        dkim_status = check_dkim(msg_bytes)

                        # 🚨 Enviar alerta si es Phishing de alto riesgo
                        if phishing_status == "Phishing 🚨 (Alto riesgo)":
                            send_telegram_alert({
                                "from": sender,
                                "subject": subject
                            }, phishing_status)

                        emails.append({
                            "subject": subject,
                            "from": sender,
                            "is_phishing": phishing_status,
                            "spf_result": spf_status,
                            "dkim_result": dkim_status,
                            "dmarc_result": dmarc_status,
                            "attachments": attachments_analysis  # 📂 Incluir análisis de adjuntos
                        })

                    except Exception as e:
                        print(f"⚠️ Error al analizar correo: {e}")
                        continue  # Evita que un error de análisis detenga la ejecución

        mail.logout()

        print(f"✅ Correos recuperados correctamente: {len(emails)}")
        return emails

    except Exception as e:
        print(f"⚠️ Error al obtener correos: {str(e)}")
        return []


from collections import Counter
from datetime import datetime

@app.route("/reportes")
def reportes():
    emails = get_emails()
    
    if not emails:
        return jsonify({
            "error": "No hay datos disponibles",
            "phishing_stats": [0, 0, 0],
            "attachment_stats": [0, 0, 0],
            "trends": {"dates": [], "counts": []}
        }), 200

    # 📊 Contar tipos de correos
    phishing_count = sum(1 for email in emails if email["is_phishing"] == "Phishing 🚨 (Alto riesgo)")
    sospechoso_count = sum(1 for email in emails if email["is_phishing"] == "Sospechoso ⚠️ (Riesgo moderado)")
    seguro_count = len(emails) - phishing_count - sospechoso_count

    # 📊 Contar archivos adjuntos analizados
    archivos_limpios = sum(1 for email in emails for adj in email.get("attachments", []) if "✅" in adj)
    archivos_sospechosos = sum(1 for email in emails for adj in email.get("attachments", []) if "⚠️" in adj)
    archivos_peligrosos = sum(1 for email in emails for adj in email.get("attachments", []) if "🚨" in adj)

    # 📅 Obtener tendencias de phishing
    phishing_dates = [email.get("date", datetime.now().strftime("%d-%b")) for email in emails if email["is_phishing"] == "Phishing 🚨 (Alto riesgo)"]
    trend_counts = Counter(phishing_dates)  # Cuenta ocurrencias por fecha

    trend_dates = sorted(trend_counts.keys())  # Fechas ordenadas
    trend_values = [trend_counts[date] for date in trend_dates]  # Cantidad de phishing por fecha

    return jsonify({
        "phishing_stats": [seguro_count, sospechoso_count, phishing_count],
        "attachment_stats": [archivos_limpios, archivos_sospechosos, archivos_peligrosos],
        "trends": {"dates": trend_dates, "counts": trend_values}
    })



@app.route("/exportar_csv")
def exportar_csv():
    emails = get_emails()  # Recuperar la lista de correos

    if not emails:
        return "No hay datos disponibles", 400

    si = io.StringIO()
    writer = csv.writer(si, delimiter=";", quotechar='"', quoting=csv.QUOTE_MINIMAL)

    # 📝 Encabezados mejorados
    writer.writerow(["Asunto", "Remitente", "Estado de Seguridad", "SPF", "DKIM", "DMARC"])

    # 📝 Escribir los datos de los correos
    for email in emails:
        writer.writerow([
            email.get("subject", "-"),
            email.get("from", "-"),
            email.get("is_phishing", "-"),
            email.get("spf_result", "-"),
            email.get("dkim_result", "-"),
            email.get("dmarc_result", "-")
        ])

    output = Response("\ufeff" + si.getvalue(), mimetype="text/csv")  # Agregar BOM para compatibilidad con Excel
    output.headers["Content-Disposition"] = "attachment; filename=reportes.csv"
    return output


@app.route("/detalles_correo/<int:index>")
def detalles_correo(index):
    emails = get_emails()
    if index < 0 or index >= len(emails):
        return "Correo no encontrado", 404
    email = emails[index]
    return render_template("detalles_correo.html", email=email)



@app.route("/")
def index():
    if "oauth_token" not in session:
        return redirect(url_for("login", provider="gmail"))
    
    emails = get_emails()
    print(f"🔎 Correos enviados a la interfaz: {emails}")

    return render_template("index.html", emails=emails)


if __name__ == "__main__":
    app.run(debug=True)

