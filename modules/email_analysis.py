import os
import re
import yara
import whois
import logging
import unicodedata
import quopri
import requests
import urllib.parse
from bs4 import BeautifulSoup
import dns.resolver
import dkim  # Biblioteca DKIM (e.g., dkimpy)

logger = logging.getLogger(__name__)

# Directorio donde se guardarán los archivos adjuntos para análisis
ATTACHMENT_FOLDER = os.getenv("ATTACHMENT_FOLDER", "attachments")
if not os.path.isdir(ATTACHMENT_FOLDER):
    os.makedirs(ATTACHMENT_FOLDER, exist_ok=True)

# Reglas YARA para detección de malware en adjuntos
YARA_RULES = r"""
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
        $js_obfuscation1 = "eval(String.fromCharCode())"
        $js_obfuscation2 = "unescape()"
        $powershell_malicious = "IEX(New-Object Net.WebClient).DownloadString"
        $bat_malicious = "cmd /c powershell -"
        $macro1 = "Sub AutoOpen()"
        $macro2 = "Sub Document_Open()"
        $macro3 = "CreateObject(\"Scripting.FileSystemObject\")"
        $macro4 = "CreateObject(\"WScript.Shell\")"
        $zip_suspicious1 = "This zip file contains malware"
        $zip_suspicious2 = "This archive is encrypted and contains malware"

    condition:
        (uint16(0) == 0x5A4D) or
        any of ($suspicious1, $suspicious2, $suspicious3, $suspicious4, $suspicious5, $suspicious6, $suspicious7, $suspicious8) or
        any of ($js_obfuscation1, $js_obfuscation2) or 
        any of ($powershell_malicious, $bat_malicious) or 
        any of ($macro1, $macro2, $macro3, $macro4) or 
        any of ($zip_suspicious1, $zip_suspicious2) or
        any of them
}


"""
# Compilar reglas YARA una vez
try:
    YARA_COMP = yara.compile(source=YARA_RULES)
    logger.info("Reglas YARA compiladas correctamente.")
except Exception as e:
    YARA_COMP = None
    logger.error(f"⚠️ Error de sintaxis en las reglas YARA: {e}. Se omitirán análisis YARA.")

# Extensiones de archivo permitidas para análisis (otros se marcarán como no permitidos)
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".png", ".jpg"}

def allowed_file(filename):
    """Verifica si la extensión de un archivo adjunto está permitida para análisis."""
    return "." in filename and os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

def check_spf(sender_email):
    """Verifica si el dominio del remitente tiene un registro SPF válido."""
    try:
        domain = sender_email.split("@")[-1]
        answers = dns.resolver.resolve(domain, 'TXT')
        for txt in answers:
            if "v=spf1" in str(txt):
                return f"✅ SPF encontrado: {txt}"
        return "⚠️ No hay registro SPF"
    except Exception as e:
        logger.warning(f"Error en la consulta SPF: {e}")
        return f"⚠️ Error en la consulta SPF: {e}"

def check_dkim(email_bytes):
    """Verifica si el correo (bytes) tiene una firma DKIM válida."""
    try:
        valid = dkim.verify(email_bytes)
        return "✅ DKIM válido" if valid else "❌ DKIM inválido"
    except Exception as e:
        logger.warning(f"Error en la verificación DKIM: {e}")
        return f"⚠️ Error en la verificación DKIM: {e}"

def check_dmarc(sender_email):
    """Consulta la política DMARC del dominio del remitente (si existe)."""
    try:
        domain = sender_email.split("@")[-1]
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for txt in answers:
            if "v=DMARC1" in str(txt):
                return f"✅ DMARC encontrado: {txt}"
        return "⚠️ No hay política DMARC"
    except Exception as e:
        logger.warning(f"Error en la consulta DMARC: {e}")
        return f"⚠️ Error en la consulta DMARC: {e}"

def check_phishing_database(domain):
    """Verifica si un dominio aparece en la base de datos de phishing (phishtank)."""
    try:
        url = f"https://www.phishtank.com/checkurl/{domain}"
        response = requests.get(url, timeout=5)
        if "verified phish" in response.text.lower():
            return True
    except Exception as e:
        logger.error(f"Error consultando PhishTank: {e}")
    return False

def check_domain_age(domain):
    """Verifica la antigüedad de un dominio en días (dominios muy nuevos se consideran sospechosos)."""
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        # La fecha de creación puede ser lista (si el dominio tuvo varias fechas, tomar la primera)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (creation_date and (datetime.now() - creation_date).days) if creation_date else None
        return age_days
    except Exception:
        return None

def scan_with_virustotal(file_path):
    """Envía un archivo a la API de VirusTotal para escaneo y devuelve un resultado simple."""
    try:
        with open(file_path, "rb") as f:
            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers={"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")},
                files={"file": f},
                timeout=15
            )
        data = response.json()
        if "error" in data:
            return "⚠️ No se pudo analizar en VirusTotal"
        # Devolver un mensaje simplificado (podría extenderse para mostrar resultados detallados)
        return f"✅ Archivo analizado en VirusTotal: {data.get('data', {}).get('id', 'OK')}"
    except Exception as e:
        logger.error(f"Error al escanear archivo en VirusTotal: {e}")
        return f"⚠️ Error en VirusTotal: {e}"

def analyze_attachment(part):
    """
    Analiza un adjunto de correo (`part`) en busca de amenazas.
    Retorna un mensaje indicando el resultado del análisis del archivo adjunto.
    """
    filename = part.get_filename()
    if not filename:
        return "✅ Sin adjunto"  # Parte del correo sin nombre de archivo (no es adjunto real)
    file_data = part.get_payload(decode=True)
    if not file_data:
        return f"⚠️ {filename}: Archivo no pudo ser decodificado."
    logger.info(f"📂 Analizando adjunto: {filename}")
    # Comprobar extensiones peligrosas inmediatas
    dangerous_ext = {".exe", ".js", ".bat", ".cmd", ".scr", ".pif", ".zip", ".rar", ".tar", ".gz"}
    ext = os.path.splitext(filename)[1].lower()
    if ext in dangerous_ext:
        return f"🚨 {filename}: Archivo potencialmente peligroso ({ext})"
    # Guardar el archivo temporalmente para análisis
    file_path = os.path.join(ATTACHMENT_FOLDER, filename)
    try:
        with open(file_path, "wb") as f:
            f.write(file_data)
    except Exception as e:
        logger.error(f"Error al guardar adjunto {filename}: {e}")
        return f"⚠️ {filename}: No se pudo guardar para análisis."
    # Verificar si la extensión es de las permitidas para escaneo profundo
    if not allowed_file(filename):
        return f"⚠️ {filename}: Tipo de archivo no permitido."
    # Analizar con reglas YARA (si se pudieron compilar)
    if YARA_COMP:
        try:
            matches = YARA_COMP.match(file_path)
            if matches:
                return f"🚨 {filename}: Posible malware detectado por YARA ({matches[0].rule})"
        except Exception as e:
            logger.error(f"Error analizando {filename} con YARA: {e}")
    # Analizar con VirusTotal API
    vt_result = scan_with_virustotal(file_path)
    return f"{filename}: {vt_result}"

def is_phishing(email_body, email_sender, email_subject, email_raw=None):
    """
    Analiza el contenido de un correo para determinar si es phishing.
    Retorna una clasificación: "Seguro ✅ (Bajo riesgo)", "Sospechoso ⚠️ (Riesgo moderado)" o "Phishing 🚨 (Alto riesgo)".
    """
    # Listas blancas y negras de dominios
    TRUSTED_DOMAINS = {"paypal.com", "amazon.com", "microsoft.com", "google.com", "outlook.com",
                       "hotmail.com", "adidas.com", "elpais.com", "bbva.com", "mit.edu", "harvard.edu"}
    BLACKLISTED_DOMAINS = {"gophish.com", "ruleta.com", "trampasdejuego.com", "casino-online.com",
                           "freegift.com", "secure-login.com", "phishing.com", "malware-site.com"}
    PHISHING_LINK_PATTERNS = [r"bit\.ly", r"tinyurl\.com", r"freegift", r"login-secure", 
                              r"verify-", r"phish", r"\.html$"]
    PHISHING_KEYWORDS = [r"urgente", r"inmediato", r"acción requerida", r"verifica.*cuenta",
                         r"confirma.*identidad", r"problema.*seguridad", r"revisión obligatoria",
                         r"clic.*aquí", r"inicie sesión", r"compruebe su cuenta", r"descargar.*archivo",
                         r"ingrese sus credenciales", r"cuenta.*bloqueada", r"felicidades.*ganado",
                         r"premio exclusivo", r"oferta limitada", r"transacción.*no autorizada",
                         r"alerta.*bancaria", r"hemos recibido una solicitud de", r"su correo será desactivado"]
    score = 0  # Puntaje de riesgo
    domain = email_sender.split("@")[-1].lower() if "@" in email_sender else email_sender
    logger.info(f"🔎 Analizando correo de {email_sender} - Asunto: {email_subject}")
    # 1. Verificación de autenticación: SPF, DKIM, DMARC
    spf_result = check_spf(email_sender)
    dmarc_result = check_dmarc(email_sender)
    if email_raw:
        dkim_result = check_dkim(email_raw)
    else:
        dkim_result = "❌ No se puede verificar DKIM"
    # Penalizar falta de autenticación
    if "⚠️" in spf_result or "No hay registro SPF" in spf_result:
        score += 3
    if "⚠️" in dmarc_result or "No hay política DMARC" in dmarc_result:
        score += 3
    if "❌" in dkim_result:
        score += 4
    # 2. Antigüedad del dominio del remitente
    domain_age = check_domain_age(domain)
    if domain_age is not None and domain_age < 30:  # menos de 30 días
        logger.warning(f"⚠️ Dominio muy reciente detectado ({domain}, {domain_age} días). +4 puntos")
        score += 4
    # 3. Dominios en lista negra de phishing
    if check_phishing_database(domain):
        logger.warning(f"🚨 Dominio {domain} aparece como phishing conocido. +6 puntos")
        score += 6
    # 4. Spoofing de caracteres (Homoglyphs en email)
    normalized_sender = unicodedata.normalize("NFKD", email_sender)
    if email_sender != normalized_sender:
        logger.warning("⚠️ Remitente contiene caracteres Unicode sospechosos. +3 puntos")
        score += 3
    # 5. Verificación contra dominios confiables/sospechosos
    if domain in BLACKLISTED_DOMAINS:
        logger.warning(f"🚨 Dominio {domain} está en lista negra. +5 puntos")
        score += 5
    elif domain not in TRUSTED_DOMAINS:
        logger.info(f"⚠️ Dominio {domain} no está en la lista de confianza. +2 puntos")
        score += 2
    # 6. Detección específica de patrones (por ejemplo, dominios de GoPhish)
    if "gophish" in domain:
        logger.warning(f"🚨 Dominio asociado a GoPhish detectado ({domain}). +6 puntos")
        score += 6
    # 7. Procesar el cuerpo del correo para análisis de enlaces
    # Decodificar cuerpo (quoted-printable, URL encoded, etc.)
    decoded_body = quopri.decodestring(email_body.encode('utf-8', errors='ignore'))
    decoded_body = urllib.parse.unquote_plus(decoded_body.decode('utf-8', errors='ignore'))
    # Extraer URLs de anclas HTML y de texto plano
    soup = BeautifulSoup(decoded_body, "html5lib")
    extracted_urls = [a["href"] for a in soup.find_all("a", href=True)]
    extracted_urls += re.findall(r'https?://[^\s]+', decoded_body)
    # Normalizar URLs ofuscadas (hxxp -> http, [.] -> .)
    extracted_urls = [url.replace("hxxp://", "http://") for url in extracted_urls]
    extracted_urls = [re.sub(r"\[\.\]", ".", url) for url in extracted_urls]
    # Evaluar cada URL detectada
    for url in extracted_urls:
        for pattern in PHISHING_LINK_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                logger.warning(f"🚨 Enlace sospechoso detectado: {url} +6 puntos")
                score += 6
                break
    # 8. Búsqueda de palabras clave sospechosas en asunto y cuerpo
    combined_text = f"{email_subject} {decoded_body}"
    for keyword in PHISHING_KEYWORDS:
        if re.search(keyword, combined_text, re.IGNORECASE):
            logger.warning(f"⚠️ Palabra clave sospechosa encontrada ({keyword}). +4 puntos")
            score += 4
    # 9. Detección de texto oculto (HTML) que podría usarse para evadir detección
    if re.search(r"<span\s+style=['\"]display:\s*none['\"].*?>.*?</span>", email_body, re.IGNORECASE):
        logger.warning("🚨 Texto oculto encontrado en el correo. +3 puntos")
        score += 3
    # 10. Resultado en base al puntaje total acumulado
    logger.info(f"📊 Puntaje final para el correo: {score}")
    if score >= 10:
        return "Phishing 🚨 (Alto riesgo)"
    elif score >= 5:
        return "Sospechoso ⚠️ (Riesgo moderado)"
    else:
        return "Seguro ✅ (Bajo riesgo)"
