import dns.resolver
import yara
import os
import requests
import re, time
from email.utils import parseaddr
from urllib.parse import urlparse
import hashlib
import email
import json
import os, time
import tempfile
from email import policy
from email.parser import BytesParser

# Carga reglas YARA (compila desde archivo si existe)
yara_rules = yara.compile(filepath="modules/yara_rules.yar") if os.path.exists("modules/yara_rules.yar") else None

# Nuevas listas para detección
SHORT_URLS = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "cutt.ly", "is.gd", "tiny.cc"]
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
            "subject": subject,
            "from": sender,
            "body": body,
            "spf_result": spf_result,
            "dkim_result": dkim_result,
            "dmarc_result": dmarc_result,
            "is_phishing": is_phishing_result,
            "reasons": reasons,
            "attachments": final_attachments,
            "tiempo_analisis": round(end - start, 2)
        }

        return resultado

        

    except Exception as e:
        return {"error": f"Error al analizar: {str(e)}"}
    
    end = time.time()
    resultado["tiempo_analisis"] = round(end - start, 2)



def is_phishing(body, sender, subject, email_raw=None, spf=None, dkim=None, dmarc=None, attachments=None):
    score = 0
    reasons = []
    body = body.lower() if body else ""
    sender = sender.lower() if sender else ""

    display_name, sender_addr = parseaddr(sender)
    display_name = display_name.lower() if display_name else ""
    sender_addr = sender_addr.lower() if sender_addr else ""
    sender_domain = sender_addr.split("@")[-1] if "@" in sender_addr else ""

    if yara_rules and email_raw:
        try:
            matches = yara_rules.match(data=email_raw)
        except Exception:
            matches = []
        for m in matches:
            description = m.meta.get('description') if hasattr(m, 'meta') else None
            reasons.append(description or f"Regla YARA detectada: {m.rule}")
            if m.rule in ["SuspiciousExecutable", "Office_Macro_Suspicious"]:
                score += 3
            elif m.rule in ["Phishing_HTML_Form", "Suspicious_HTML_Script", "HTML_AutoRedirect", "Suspicious_JS_Obfuscation"]:
                score += 2
            else:
                score += 1

    if display_name and "@" in display_name and display_name != sender_addr:
        score += 2
        reasons.append("Nombre del remitente contiene dirección engañosa")

    trusted_brands = {
        "amazon": "amazon.com",
        "paypal": "paypal.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "google": "google.com",
        "netflix": "netflix.com",
        "facebook": "facebook.com"
    }
    for brand, domain in trusted_brands.items():
        if brand in display_name or brand in sender_addr:
            if domain not in sender_domain:
                score += 2
                reasons.append(f"Posible suplantación de marca: {brand}")

    if sender_domain:
        blacklisted = ["scam.tk", "mail.ru", "phishingsite.com"]
        if any(sender_domain == b or sender_domain.endswith("." + b) for b in blacklisted):
            score += 3
            reasons.append(f"Dominio remitente bloqueado: {sender_domain}")

        tld = sender_domain.split(".")[-1]
        if tld in {"xyz", "tk", "gq", "ga", "cf"}:
            score += 1
            reasons.append(f"TLD sospechoso: .{tld}")

        if "xn--" in sender_domain:
            score += 2
            reasons.append("Dominio con codificación punycode (posible engaño visual)")

    urls = re.findall(r'https?://[^\s<">]+', body)
    if urls:
        score += 1
        reasons.append("Contiene enlaces externos")
        shorteners = SHORT_URLS
        for url in urls:
            if any(s in url for s in shorteners):
                score += 2
                reasons.append(f"Enlace acortado: {url}")
            domain = urlparse(url).netloc.lower()
            if any(sus in domain for sus in SUSPECT_DOMAINS):
                score += 3
                reasons.append(f"Dominio sospechoso detectado: {domain}")
            if "redirect=" in url or "redirect/" in url:
                score += 1
                reasons.append(f"Enlace con parámetro de redirección: {url}")

    anchor_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']>([^<]+)</a>', flags=re.IGNORECASE)
    for match in anchor_pattern.finditer(body):
        href, link_text = match.group(1).strip(), match.group(2).strip().lower()
        if re.search(r'(https?://|www\\.|\\.(com|net|org|io|gov|edu|co|info|me|ru|cn|de|uk|jp|es|fr|xyz|tk|gq))', link_text):
            href_domain = urlparse(href).netloc.lower()
            text_domain = urlparse(link_text).netloc.lower() if link_text.startswith("http") else link_text.split("/")[0].lower()
            if text_domain and href_domain and href_domain.replace("www.", "") != text_domain.replace("www.", ""):
                score += 2
                reasons.append(f"Enlace engañoso: texto muestra '{text_domain}' pero dirige a '{href_domain}'")

    keywords = ["verify", "password", "urgent", "click here", "bank", "confirm", "account", "login", "reset",
                "verifica", "contraseña", "urgente", "actualiza tu cuenta", "actualizar", "clave", "verifica tu cuenta"]
    if any(k in body for k in keywords):
        score += 1
        reasons.append("🔑 Palabras clave sospechosas en el contenido.")

    alarming = ["your account will be closed", "unauthorized access", "we detected unusual activity",
                "acceso no autorizado", "su cuenta será suspendida", "hemos detectado actividad inusual"]
    found = [p for p in alarming if p in body]
    score += len(found)
    if found:
        reasons.append(f"Frases alarmantes: {', '.join(found)}")

    flagged_attachments = [att for att in attachments if isinstance(att, dict) and att.get("status") == "suspicious"]
    if flagged_attachments:
        score += 3
        for att in flagged_attachments:
            reasons.append(f"Adjunto sospechoso: {att['filename']} ({att['reason']})")

    if spf is False:
        score += 1
        reasons.append("SPF inválido")
    if dkim is False:
        score += 1
        reasons.append("DKIM inválido")
    if dmarc is False:
        score += 1
        reasons.append("DMARC inválido")


    classification = "Seguro ✅ (Bajo riesgo)"
    if score >= 7:
        classification = "Phishing 🚨 (Alto riesgo)"
    elif score >= 4:
        classification = "Sospechoso ⚠️ (Riesgo moderado)"
    if flagged_attachments:
        classification = "Phishing 🚨 (Alto riesgo)"

    if classification != "Seguro ✅ (Bajo riesgo)" and not flagged_attachments:
        serious = any("suplantación" in r.lower() or "engañosa" in r.lower() or "bloqueado" in r.lower() or
                      "tld sospechoso" in r.lower() or "punycode" in r.lower() or "adjunto" in r.lower()
                      for r in reasons)
        if not serious:
            classification = "Seguro ✅ (Bajo riesgo)"

    return classification, reasons, score



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