import dns.resolver
import yara
import os, re, time, dkim
import requests
from email.utils import parseaddr
from urllib.parse import urlparse
import hashlib
import email
import json
import tempfile
from email import policy
from email.parser import BytesParser
from email import message_from_bytes
from modules.db import correo_ya_analizado
from modules.helpers import score_a_estado






# Carga reglas YARA (compila desde archivo si existe)
yara_rules = yara.compile(filepath="modules/yara_rules.yar") if os.path.exists("modules/yara_rules.yar") else None



PESOS = {
        "auth_fail": 3,
        "enlace_sospechoso": 4,
        "enlace_ip": 3,
        "enlace_ofuscado": 2,
        "exceso_enlaces": 1,
        "remitente_raro": 2,
        "return_path_diff": 2,
        "dominio_gratuito": 2,
        "header_privada": 1,
        "adjunto_raro": 2,
        "mensaje_urgente": 2,
        "contenido_html": 1,
}

BRAND_KEYWORDS = ["paypal", "apple", "netflix", "amazon", "bbva", "santander"]
SHORT_URLS = ["bit.ly", "tinyurl.com", "goo.gl"]
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf"]
KEYWORDS = ["verifica", "actualiza", "contraseña", "urgente", "haz clic"]
THREAT_PHRASES = ["suspenderemos", "bloquearemos", "desactivará"]
SUSPECT_DOMAINS = ["apple.verify.com", "paypal-login.net", "google-alerts.info"]
DANGEROUS_EXTENSIONS = [".exe", ".bat", ".vbs", ".scr"]

def analyze_attachment(part):
    """Analiza un archivo adjunto utilizando reglas YARA y VirusTotal."""
    filename = part.get_filename()
    payload = part.get_payload(decode=True)

    if yara_rules:
        try:
            matches = yara_rules.match(data=payload)
            if matches:
                return {
                    "filename": filename,
                    "status": "suspicious",
                    "reason": f"Detectado como malicioso por regla YARA: {matches[0].rule}"
                }
        except Exception:
            pass

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if api_key:
        try:
            sha256_hash = hashlib.sha256(payload).hexdigest()
            vt_url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
            headers = {"x-apikey": api_key}
            response = requests.get(vt_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                    return {
                        "filename": filename,
                        "status": "suspicious",
                        "reason": "Detectado como malicioso por VirusTotal"
                    }
        except Exception:
            pass

    return {
        "filename": filename,
        "status": "clean",
        "reason": "Adjunto limpio"
    }
    
    
def analyze_eml_file(eml_file):
    start = time.time()
    try:
        
        raw_bytes = eml_file.read()
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        
        message_id = msg.get("Message-ID", "").strip()
        if correo_ya_analizado(message_id):
            return {
                "error": "Este correo ya ha sido analizado previamente."
            }
        subject = msg["subject"] or "(Sin asunto)"
        sender = msg["from"] or "(Remitente desconocido)"
        body = ""
        analyzed_attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" and not part.get_filename():
                    body += part.get_content()
                elif part.get_content_disposition() == "attachment":
                    analyzed_attachments.append(analyze_attachment(part))
        else:
            body = msg.get_content()

        # Autenticación SPF/DKIM/DMARC
        spf_result = "✅ Válido" if check_spf(sender) else "❌ Fallido"
        dkim_result = "✅ Válido" if check_dkim(raw_bytes) else "❌ Fallido"
        dmarc_result = "✅ Válido" if check_dmarc(sender) else "❌ Fallido"

        # Booleanos para puntuación
        spf_bool = spf_result.startswith("✅")
        dkim_bool = dkim_result.startswith("✅")
        dmarc_bool = dmarc_result.startswith("✅")

        # Análisis de phishing real
        resultado_enlaces = analizar_enlaces(body)
        resultado_cabeceras = analizar_cabeceras(raw_bytes)
        resultado_contenido = analizar_contenido(body)

        resultado_analisis = is_phishing({
            "body": body,
            "sender": sender,
            "subject": subject,
            "email_raw": raw_bytes,
            "spf": spf_bool,
            "dkim": dkim_bool,
            "dmarc": dmarc_bool,
            "attachments": analyzed_attachments,
            "enlaces": resultado_enlaces,
            "return_path_diff": resultado_cabeceras["return_path_diff"],
            "dominio_gratuito": resultado_cabeceras["dominio_gratuito"],
            "header_privada": resultado_cabeceras["header_privada"],
            "remitente_raro": resultado_cabeceras["remitente_raro"],
            "adjunto_raro": tiene_adjuntos_raros(analyzed_attachments),
            "urgente": resultado_contenido["urgente"],
            "html_excesivo": resultado_contenido["html_excesivo"]
        })



        is_phishing_result = resultado_analisis["estado"]
        score = resultado_analisis["score"]
        reasons = resultado_analisis["motivos"]

                

        # Convertimos adjuntos a formato texto con emojis
        final_attachments = []
        for att in analyzed_attachments:
            icon = "✅" if att["status"] == "clean" else "⚠️" if att["status"] == "suspicious" else "🚨"
            final_attachments.append(f"{icon} {att['filename']}")

        end = time.time()

        resultado = {
            "message_id": message_id,
            "subject": subject,
            "from": sender,
            "body": body,
            "spf_result": spf_result,
            "dkim_result": dkim_result,
            "dmarc_result": dmarc_result,
            "estado": is_phishing_result,
            "score":score,
            "reasons": reasons,
            "attachments": final_attachments,
            "tiempo_analisis": round(end - start, 2)
        }

        return resultado

        

    except Exception as e:
        return {"error": f"Error al analizar: {str(e)}"}
    
    end = time.time()
    resultado["tiempo_analisis"] = round(end - start, 2)





def analizar_enlaces(body):
    enlaces_analizados = []
    urls = re.findall(r"https?://[^\s]+", body)
    for url in urls:
        tipo = None
        host = urlparse(url).netloc.lower()
        if any(short in host for short in SHORT_URLS):
            tipo = "sospechoso"
        elif es_enlace_sospechoso(url):
            tipo = "ofuscado"
        elif re.match(r"https?://\d{1,3}(?:\.\d{1,3}){3}", url):
            tipo = "ip"
        
        if tipo:
            enlaces_analizados.append({"tipo": tipo, "url": url})

    return enlaces_analizados




def analizar_headers(raw_email_bytes):
    mensaje = email.message_from_bytes(raw_email_bytes)
    headers = dict(mensaje.items())
    motivos = []
    score = 0

    # Validaciones básicas
    if not any("received-spf" in k.lower() for k in headers):
        motivos.append("Falta cabecera Received-SPF")
        score += 1

    if not any("dkim-signature" in k.lower() for k in headers):
        motivos.append("Falta cabecera DKIM-Signature")
        score += 1

    if not any("authentication-results" in k.lower() for k in headers):
        motivos.append("Falta cabecera Authentication-Results")
        score += 1

    # Cabeceras Received
    received_headers = [v for k, v in headers.items() if k.lower() == "received"]
    if len(received_headers) < 2:
        motivos.append("Número reducido de cabeceras Received")
        score += 1

    # IPs sospechosas
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    for header in received_headers:
        ips = re.findall(ip_pattern, header)
        for ip in ips:
            if ip.startswith(("10.", "192.168.", "172.16.")):
                motivos.append(f"IP privada detectada: {ip}")
                score += 1

    # Inconsistencias
    from_header = headers.get("From", "")
    return_path = headers.get("Return-Path", "")
    if return_path and from_header:
        _, from_email = parseaddr(from_header)
        _, return_email = parseaddr(return_path)
        if from_email and return_email and not from_email.endswith(return_email.split("@")[-1]):
            motivos.append("Dominio del From no coincide con Return-Path")
            score += 2

    # Dominios sospechosos
    for v in headers.values():
        if any(domain in v.lower() for domain in [".tk", ".ml", ".cf", ".ga", ".gq"]):
            motivos.append(f"Dominio sospechoso en cabecera: {v}")
            score += 2

    return score, motivos




def analizar_cabeceras(raw_email_bytes):
    score, motivos = analizar_headers(raw_email_bytes)
    sender_name, sender_email = extract_display_name(email.message_from_bytes(raw_email_bytes).get("From", ""))

    remitente_raro = False
    if not sender_name or re.search(r"[^\w\s]", sender_name):
        remitente_raro = True

    return {
        "return_path_diff": any("Dominio del From no coincide con Return-Path" in motivo for motivo in motivos),
        "dominio_gratuito": any("Dominio sospechoso en cabecera" in motivo for motivo in motivos),
        "header_privada": any("IP privada detectada" in motivo for motivo in motivos),
        "remitente_raro": remitente_raro
    }




def analizar_contenido(body):
    urgente = any(palabra in body.lower() for palabra in THREAT_PHRASES + KEYWORDS)
    html_excesivo = len(re.findall(r"<[^>]+>", body)) > 20  # Umbral básico de HTML
    return {
        "urgente": urgente,
        "html_excesivo": html_excesivo
    }

def tiene_adjuntos_raros(attachments):
    return any(att["filename"].lower().endswith(tuple(DANGEROUS_EXTENSIONS)) for att in attachments)



def match_yara(content):
    if yara_rules:
        try:
            matches = yara_rules.match(data=content.encode() if isinstance(content, str) else content)
            return bool(matches)
        except Exception:
            return False
    return False


def extract_display_name(sender):
    name, email_addr = parseaddr(sender)
    return name, email_addr




def es_enlace_sospechoso(href):
    parsed = urlparse(href)
    host = parsed.netloc.lower()

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        return "Enlace apunta a IP directa"

    if "%" in href or "@" in href:
        return "Enlace contiene codificación ofuscada o '@'"

    if "xn--" in host:
        return "Enlace usa Punycode (posible suplantación)"

    return None  # Si no hay problemas, no penaliza




def is_phishing(email_data: dict) -> dict:
    """
    Analiza un correo y determina si es phishing, sospechoso o seguro.
    Retorna un diccionario con estado, score y motivos.
    """
    score = 0
    motivos = []

    

    # 1. Validaciones SPF/DKIM/DMARC
    if not email_data.get("spf", True):
        score += PESOS["auth_fail"]
        motivos.append("SPF fallido")
    if not email_data.get("dkim", True):
        score += PESOS["auth_fail"]
        motivos.append("DKIM fallido")
    if not email_data.get("dmarc", True):
        score += PESOS["auth_fail"]
        motivos.append("DMARC fallido")

    # 2. Análisis de enlaces
    for enlace in email_data.get("enlaces", []):
        if enlace.get("tipo") == "sospechoso":
            score += PESOS["enlace_sospechoso"]
            motivos.append(f"Enlace sospechoso: {enlace['url']}")
        elif enlace.get("tipo") == "ip":
            score += PESOS["enlace_ip"]
            motivos.append(f"Enlace con dirección IP: {enlace['url']}")
        elif enlace.get("tipo") == "ofuscado":
            score += PESOS["enlace_ofuscado"]
            motivos.append(f"Enlace ofuscado: {enlace['url']}")

    if len(email_data.get("enlaces", [])) >= 10:
        score += PESOS["exceso_enlaces"]
        motivos.append("Demasiados enlaces en el correo")

    # 3. Cabeceras
    if email_data.get("return_path_diff", False):
        score += PESOS["return_path_diff"]
        motivos.append("El Return-Path difiere del remitente")

    if email_data.get("dominio_gratuito", False):
        score += PESOS["dominio_gratuito"]
        motivos.append("El dominio del remitente es gratuito (tipo gmail, yahoo, etc.)")

    if email_data.get("header_privada", False):
        score += PESOS["header_privada"]
        motivos.append("Cabecera contiene IP privada o reservada")

    # 4. Remitente raro (nombre extraño o dominio sin relación)
    if email_data.get("remitente_raro", False):
        score += PESOS["remitente_raro"]
        motivos.append("Nombre o dirección del remitente no coincide con el dominio esperado")

    # 5. Adjunto peligroso
    if email_data.get("adjunto_raro", False):
        score += PESOS["adjunto_raro"]
        motivos.append("Adjunto con extensión inusual o peligrosa")

    # 6. Contenido
    if email_data.get("urgente", False):
        score += PESOS["mensaje_urgente"]
        motivos.append("Lenguaje de urgencia o presión detectado")

    if email_data.get("html_excesivo", False):
        score += PESOS["contenido_html"]
        motivos.append("Correo contiene HTML excesivo o sospechoso")

    # 7. Clasificación final según puntuación total

    estado = score_a_estado(score, motivos)




    return {
        "estado": estado,
        "score": score,
        "motivos": motivos,
        "spf": email_data.get("spf"),
        "dkim": email_data.get("dkim"),
        "dmarc": email_data.get("dmarc")
    }







def check_spf(sender):
    try:
        domain = sender.split("@")[-1]
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            if "v=spf1" in str(rdata):
                if "-all" in str(rdata) or "~all" in str(rdata):  # Política razonable
                    return True
        return False
    except Exception:
        return False


def check_dkim(raw_email):
    try:
        if isinstance(raw_email, str):
            raw_email = raw_email.encode("utf-8")
        return dkim.verify(raw_email)
    except Exception:
        return False

def check_dmarc(sender):
    try:
        domain = sender.split("@")[-1]
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            if "v=DMARC1" in str(rdata):
                if "p=reject" in str(rdata) or "p=quarantine" in str(rdata):
                    return True
        return False
    except Exception:
        return False

