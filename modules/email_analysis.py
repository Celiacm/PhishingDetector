import dns.resolver
import yara
import os, re
import requests
import re, time
from email.utils import parseaddr
from urllib.parse import urlparse
import hashlib
import email
import json
import tempfile
from email import policy
from email.parser import BytesParser
from email import message_from_bytes




# Carga reglas YARA (compila desde archivo si existe)
yara_rules = yara.compile(filepath="modules/yara_rules.yar") if os.path.exists("modules/yara_rules.yar") else None


PESOS = {
    "yara_match": 3,
    "display_fake": 2,
    "brand_spoof": 2,
    "short_url": 2,
    "suspicious_domain": 2,
    "suspicious_link": 2,
    "fake_link_text": 1,
    "dangerous_words": 1,
    "threat_phrases": 2,
    "bad_attachment": 3,
    "spf_fail": 2,
    "dkim_fail": 2,
    "dmarc_fail": 2
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
        is_phishing_result, reasons, score = is_phishing(
            body, sender, subject,
            email_raw=raw_bytes,
            spf=spf_bool,
            dkim=dkim_bool,
            dmarc=dmarc_bool,
            attachments=analyzed_attachments
        )

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




def analizar_headers(raw_email_bytes):
    """
    Análisis extendido de cabeceras SMTP para detectar inconsistencias, IPs sospechosas y ausencia de autenticaciones clave.
    """
    try:
        mensaje = email.message_from_bytes(raw_email_bytes)
        headers = dict(mensaje.items())
        motivos = []
        score = 0

        # --- 1. Validación de autenticación básica ---
        if not any("received-spf" in k.lower() for k in headers):
            motivos.append("❌ Falta la cabecera Received-SPF")
            score += 1
        if not any("dkim-signature" in k.lower() for k in headers):
            motivos.append("❌ Falta la cabecera DKIM-Signature")
            score += 1
        if not any("authentication-results" in k.lower() for k in headers):
            motivos.append("❌ Falta la cabecera Authentication-Results")
            score += 1

        # --- 2. Cabeceras Received ---
        received_headers = [v for k, v in headers.items() if k.lower() == "received"]
        if len(received_headers) < 2:
            motivos.append("⚠️ Número reducido de cabeceras 'Received'")
            score += 1

        # --- 3. Detección de IPs sospechosas ---
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        for header in received_headers:
            ips = re.findall(ip_pattern, header)
            for ip in ips:
                if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
                    motivos.append(f"⚠️ IP privada detectada en ruta: {ip}")
                    score += 1

        # --- 4. Análisis de inconsistencias dominio-remitente ---
        from_header = headers.get("From", "")
        return_path = headers.get("Return-Path", "")
        if return_path and from_header:
            _, from_email = parseaddr(from_header)
            _, return_email = parseaddr(return_path)
            if from_email and return_email and not from_email.endswith(return_email.split("@")[-1]):
                motivos.append("❌ Dominio del From no coincide con Return-Path")
                score += 2

        # --- 5. Revisión de servicios conocidos o gratuitos ---
        for k, v in headers.items():
            if any(domain in v.lower() for domain in [".tk", ".ml", ".cf", ".ga", ".gq"]):
                motivos.append(f"⚠️ Dominio sospechoso en cabecera: {v}")
                score += 2

        return score, motivos

    except Exception as e:
        return 1, [f"⚠️ Error al analizar cabeceras: {str(e)}"]



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


def is_phishing(body, sender, subject, email_raw, spf, dkim, dmarc, attachments=[]):
    score = 0
    motivos = []

    # --- Análisis de encabezados SMTP ---
    if email_raw:
        header_score, header_motivos = analizar_headers(email_raw)
        score += header_score
        motivos.extend(header_motivos)

    # --- YARA rules ---
    if match_yara(body):
        score += PESOS["yara_match"]
        motivos.append("Coincidencia con reglas YARA")

    # --- Display spoof ---
    display, real = extract_display_name(sender)
    if display and real and display.lower() != real.lower():
        score += PESOS["display_fake"]
        motivos.append("Nombre del remitente no coincide con email")

    # --- Brand spoof ---
    if any(b in sender.lower() or b in subject.lower() for b in BRAND_KEYWORDS):
        score += PESOS["brand_spoof"]
        motivos.append("Mención a marca suplantada")

    # --- Short URL ---
    if any(s in body for s in SHORT_URLS):
        score += PESOS["short_url"]
        motivos.append("Uso de acortadores de URL")

    # --- Dominio sospechoso ---
    parsed_sender = sender.split("@")[-1] if "@" in sender else sender
    if any(parsed_sender.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += PESOS["suspicious_domain"]
        motivos.append("Dominio sospechoso o gratuito")

    # --- Enlaces engañosos: texto visible vs destino real ---
    anchor_tags = re.findall(r'<a\s+(?:[^>]*?\s+)?href="([^"]+)"[^>]*>(.*?)</a>', body, re.IGNORECASE)
    for href, texto in anchor_tags:
        href_domain = urlparse(href).netloc.lower()
        text_domain = urlparse(texto).netloc.lower() if "http" in texto else texto.lower()

        if text_domain and text_domain not in href_domain:
            score += PESOS["fake_link_text"]
            motivos.append(f"⚠️ Enlace sospechoso: texto '{texto}' apunta a '{href}'")
            break  # solo penalizamos una vez

    if len(anchor_tags) > 5:
        score += 1
        motivos.append("⚠️ Número elevado de enlaces en el correo")
        
    
    # --- Enlace apunta a IP o contiene codificación ofuscada ---
    for href, _ in anchor_tags:
        parsed = urlparse(href)
        host = parsed.netloc

        # 1. Enlace a IP
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            score += PESOS["suspicious_link"]
            motivos.append(f"⚠️ Enlace apunta a una IP directa: {host}")
            break

        # 2. Enlace ofuscado
        if "%" in href or "@" in href:
            score += PESOS["suspicious_link"]
            motivos.append(f"⚠️ Enlace contiene codificación ofuscada o '@': {href}")
            break
        
        # 3. Enlace con punycode
        if "xn--" in host:
            score += PESOS["suspicious_link"]
            motivos.append(f"⚠️ Enlace usa Punycode (posible suplantación): {href}")
            break



    # --- Palabras peligrosas ---
    if any(k in body.lower() for k in KEYWORDS):
        score += PESOS["dangerous_words"]
        motivos.append("Palabras clave sospechosas")

    # --- Frases de amenaza ---
    if any(f in body.lower() for f in THREAT_PHRASES):
        score += PESOS["threat_phrases"]
        motivos.append("Frases que generan miedo o urgencia")

    # --- Adjuntos peligrosos ---
    for a in attachments:
        if a.get("status") == "suspicious":
            score += PESOS["bad_attachment"]
            motivos.append(a.get("reason", "Adjunto sospechoso"))

    # --- Autenticación ---
    if not spf:
        score += PESOS["spf_fail"]
        motivos.append("SPF fallido")
    if not dkim:
        score += PESOS["dkim_fail"]
        motivos.append("DKIM fallido")
    if not dmarc:
        score += PESOS["dmarc_fail"]
        motivos.append("DMARC fallido")

    max_score = 15
    score = min(score, max_score)

    if score >= 10:
        estado = "Phishing"
    elif score >= 5:
        estado = "Sospechoso"
    else:
        estado = "Seguro"



    return estado, motivos, score



def check_spf(sender):
    try:
        domain = sender.split("@")[-1]
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            if "v=spf1" in str(rdata):
                return True
        return False
    except Exception:
        return False

def check_dkim(raw_email):
    try:
        # Placeholder mientras no uses dkimpy u otro sistema
        return True
    except Exception:
        return False

def check_dmarc(sender):
    try:
        domain = sender.split("@")[-1]
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            if "v=DMARC1" in str(rdata):
                return True
        return False
    except Exception:
        return False


end = time.time()