# email_analysis.py
import dns.resolver
import yara
import os
import requests
import re
from email.utils import parseaddr
from urllib.parse import urlparse

# Carga reglas YARA (compila desde archivo si existe)
yara_rules = yara.compile(filepath="modules/yara_rules.yar") if os.path.exists("modules/yara_rules.yar") else None

def is_phishing(body, sender, subject, email_raw=None, spf=None, dkim=None, dmarc=None, attachments=None):
    score = 0
    reasons = []
    # Normalizar a minúsculas para análisis textual
    body = body.lower() if body else ""
    sender = sender.lower() if sender else ""
    
    # Separar nombre mostrado y dirección de correo del remitente
    display_name, sender_addr = parseaddr(sender)
    display_name = display_name.lower() if display_name else ""
    sender_addr = sender_addr.lower() if sender_addr else ""
    sender_domain = sender_addr.split("@")[1] if "@" in sender_addr else ""
    
    # 1. Evaluación por reglas YARA en el correo completo
    if yara_rules and email_raw:
        try:
            matches = yara_rules.match(data=email_raw)
        except Exception:
            matches = []
        for m in matches:
            # Usar la descripción de la regla YARA como justificación si existe
            description = m.meta.get('description') if hasattr(m, 'meta') else None
            if description:
                reasons.append(description)
            else:
                reasons.append(f"Regla YARA detectada: {m.rule}")
            # Asignar puntuación según la gravedad de la regla
            rule_name = m.rule
            if rule_name in ["SuspiciousExecutable", "Office_Macro_Suspicious"]:
                score += 3
            elif rule_name in ["Phishing_HTML_Form", "Suspicious_HTML_Script", "HTML_AutoRedirect", "Suspicious_JS_Obfuscation"]:
                score += 2
            else:
                score += 1
    
    # 2. Validación de nombre mostrado y dominio del remitente
    # 2.1 Nombre mostrado contiene otra dirección de correo (intento de engaño)
    if display_name:
        # Si el nombre mostrado aparenta ser una dirección de correo diferente al remitente real
        if "@" in display_name and display_name != sender_addr:
            score += 2
            reasons.append("Nombre del remitente contiene dirección engañosa")
    # 2.2 Suplantación de marca conocida en el remitente
    # Nota: Usar un dominio gratuito (ej. Gmail) no se marca como sospechoso por sí solo
    trusted_brands = {
        "amazon": "amazon.com",
        "paypal": "paypal.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "google": "google.com",
        "netflix": "netflix.com",
        "facebook": "facebook.com"
    }
    for brand, official_domain in trusted_brands.items():
        if brand in display_name or brand in sender_addr:
            if official_domain not in sender_domain:
                score += 2
                reasons.append(f"Posible suplantación de marca: {brand}")
    
    # 3. Detección de dominios bloqueados y TLDs sospechosos
    if sender_domain:
        # 3.1 Dominio remitente en lista negra
        blacklisted_domains = ["scam.tk", "mail.ru", "phishingsite.com"]
        for bad in blacklisted_domains:
            # Comparar dominio exacto o como subdominio
            if sender_domain == bad or sender_domain.endswith("." + bad):
                score += 3
                reasons.append(f"Dominio remitente bloqueado: {sender_domain}")
                break
        # 3.2 TLD sospechoso (dominios con terminaciones raras)
        suspicious_tlds = {"xyz", "tk", "gq", "ga", "cf"}
        domain_tld = sender_domain.split(".")[-1] if sender_domain else ""
        if domain_tld in suspicious_tlds:
            score += 1
            reasons.append(f"TLD sospechoso: .{domain_tld}")
        # 3.3 Caracteres Unicode o Punycode en dominio (posible engaño visual)
        if "xn--" in sender_domain:
            score += 2
            reasons.append("Dominio con codificación punycode (posible engaño visual)")
    
    # 4. Análisis de enlaces en el cuerpo del correo
    urls = re.findall(r'https?://[^\s<">]+', body)
    if urls:
        score += 1
        reasons.append("Contiene enlaces externos")
        # Detectar enlaces acortados y con redirecciones
        shortener_domains = ["bit.ly", "t.co", "tinyurl", "tiny.cc", "goo.gl", "ow.ly", "buff.ly", "cutt.ly", "is.gd"]
        for url in urls:
            # 4.1 Enlace acortado (servicios de redirección conocidos)
            if any(shortener in url for shortener in shortener_domains):
                score += 2
                reasons.append(f"Enlace acortado: {url}")
            # 4.2 Parámetro de redirección en la URL
            if "redirect=" in url or "redirect/" in url:
                score += 1
                reasons.append(f"Enlace con parámetro de redirección: {url}")
    # 4.3 Comparar texto visible y destino de enlaces para detectar engaños
    anchor_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']>([^<]+)</a>', flags=re.IGNORECASE)
    for match in anchor_pattern.finditer(body):
        href = match.group(1).strip()
        link_text = match.group(2).strip().lower()
        # Si el texto visible parece una URL o dominio
        if re.search(r'(https?://|www\.|\.(com|net|org|io|gov|edu|co|info|me|ru|cn|de|uk|jp|es|fr|xyz|tk|gq))', link_text):
            # Extraer dominio del href y del texto visible
            href_domain = urlparse(href).netloc.lower()
            text_domain = ""
            if link_text.startswith("http://") or link_text.startswith("https://"):
                text_domain = urlparse(link_text).netloc.lower()
            elif link_text.startswith("www."):
                text_domain = link_text[4:].split("/")[0].lower()
            else:
                # Si el texto es un dominio sin protocolo (ej: "example.com")
                text_domain = link_text.split("/")[0].lower()
            # Remover "www." inicial para comparación
            href_domain_cmp = href_domain[4:] if href_domain.startswith("www.") else href_domain
            text_domain_cmp = text_domain[4:] if text_domain.startswith("www.") else text_domain
            # Comparar dominios del texto vs enlace real
            if text_domain_cmp and href_domain_cmp and text_domain_cmp != href_domain_cmp:
                score += 2
                reasons.append(f"Enlace engañoso: texto muestra '{text_domain}' pero dirige a '{href_domain}'")
    
    # 5. Análisis de palabras clave sospechosas
    keywords = [
        "verify", "password", "urgent", "click here", "bank", "confirm", "account", "login", "reset",
        "verifica", "contraseña", "urgente", "actualiza tu cuenta", "actualizar", "clave"
    ]
    found_keywords = [kw for kw in keywords if kw in body]
    score += len(found_keywords)
    if found_keywords:
        reasons.append(f"Palabras sospechosas: {', '.join(found_keywords)}")
    # 5.1 Frases de alarma comunes
    alarming_phrases = [
        "your account will be closed", "unauthorized access", "we detected unusual activity",
        "acceso no autorizado", "su cuenta será suspendida", "hemos detectado actividad inusual"
    ]
    found_phrases = [phrase for phrase in alarming_phrases if phrase in body]
    score += len(found_phrases)
    if found_phrases:
        reasons.append(f"Frases alarmantes: {', '.join(found_phrases)}")
    
    # 6. Evaluación de adjuntos analizados (integración con YARA/VirusTotal)
    flagged_attachments = []
    if attachments:
        for result in attachments:
            if result.startswith("🚨"):
                # Extraer nombre de archivo si es posible
                parts = result.split(": ", 1)
                filename = parts[1] if len(parts) > 1 else result
                flagged_attachments.append(filename)
                score += 3
                reasons.append(f"Adjunto malicioso detectado: {filename}")
    
    # Verificación de autenticación SPF, DKIM, DMARC
    if spf and "no" in spf.lower():
        score += 1
        reasons.append("SPF inválido")
    if dkim and "no" in dkim.lower():
        score += 1
        reasons.append("DKIM inválido")
    if dmarc and "no" in dmarc.lower():
        score += 1
        reasons.append("DMARC inválido")
    
    # 7. Clasificación final del correo
    classification = "Seguro ✅ (Bajo riesgo)"
    if score >= 7:
        classification = "Phishing 🚨 (Alto riesgo)"
    elif score >= 4:
        classification = "Sospechoso ⚠️ (Riesgo moderado)"
    # Elevar a alto riesgo si hay adjuntos maliciosos
    if flagged_attachments:
        classification = "Phishing 🚨 (Alto riesgo)"
    # Evitar falso positivo: si solo hay indicios leves (contenido) y autenticación correcta
    if classification != "Seguro ✅ (Bajo riesgo)" and not flagged_attachments:
        serious_indicators = False
        for reason in reasons:
            r = reason.lower()
            if ("suplantación de marca" in r or "dirección engañosa" in r or "dominio remitente bloqueado" in r or
                "tld sospechoso" in r or "punycode" in r or "enlace acortado" in r or "enlace con parámetro" in r or
                "enlace engañoso" in r or "adjunto malicioso" in r or "spf inválido" in r or "dkim inválido" in r or "dmarc inválido" in r):
                serious_indicators = True
                break
        if not serious_indicators:
            classification = "Seguro ✅ (Bajo riesgo)"
    return classification, reasons

def check_spf(sender):
    """Verifica el registro SPF del dominio del remitente."""
    try:
        domain = sender.split("@")[1]
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            # Buscar cadena que empiece con 'v=spf1'
            for txt in rdata.strings:
                txt_str = txt.decode('utf-8') if isinstance(txt, bytes) else txt
                if txt_str.startswith("v=spf1"):
                    return "SPF válido"
        return "SPF no encontrado"
    except Exception:
        return "❌ Error en consulta SPF"

def check_dkim(raw_email):
    """Simula la verificación DKIM (no implementada completamente)."""
    try:
        # Implementación real de DKIM no disponible en este contexto
        return "DKIM sin verificar (simulado)"
    except Exception:
        return "❌ Error en consulta DKIM"

def check_dmarc(sender):
    """Verifica el registro DMARC del dominio del remitente."""
    try:
        domain = sender.split("@")[1]
        dmarc_domain = f"_dmarc.{domain}"
        dns.resolver.resolve(dmarc_domain, "TXT")
        return "DMARC válido"
    except Exception:
        return "❌ Error en consulta DMARC"

def analyze_attachment(part):
    """Analiza un archivo adjunto utilizando reglas YARA y VirusTotal."""
    filename = part.get_filename()
    payload = part.get_payload(decode=True)
    # Analizar adjunto con reglas YARA
    if yara_rules:
        try:
            matches = yara_rules.match(data=payload)
        except Exception:
            matches = []
        if matches:
            return f"🚨 Sospechoso: {filename}"
    # Integración con VirusTotal (si se dispone de API key)
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if api_key:
        try:
            import hashlib
            sha256_hash = hashlib.sha256(payload).hexdigest()
            vt_url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
            headers = {"x-apikey": api_key}
            vt_response = requests.get(vt_url, headers=headers)
            if vt_response.status_code == 200:
                data = vt_response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0 or suspicious > 0:
                    return f"🚨 Sospechoso: {filename}"
            # Si no hay datos previos, subir el archivo para análisis
            upload_response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files={"file": (filename, payload)}
            )
            if upload_response.status_code in (200, 201, 202):
                return f"⚠️ Analizado en VirusTotal: {filename}"
        except Exception:
            # En caso de error en la consulta a VirusTotal, continuar sin marcar
            pass
    # Si no se detectó nada sospechoso en el adjunto
    return f"✅ Limpio: {filename}"
