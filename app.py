import os
import csv
import io
import imaplib
import logging
from flask import Flask, redirect, url_for, session, request, render_template, jsonify, Response, send_file
from requests_oauthlib import OAuth2Session
from fpdf import FPDF
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from dotenv import load_dotenv
from modules.scheduler import run as start_scheduler
from modules.error_handler import init_error_handlers
from modules.db import get_email_by_id

# Importar módulos locales
import modules.db as db        # Funciones de base de datos
import modules.email_analysis as email_analysis  # Análisis de correos y adjuntos
import modules.utils as utils  # Utilidades generales (Telegram, etc.)


# Inicializar la aplicación Flask
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  # Clave secreta para sesiones Flask



# Configurar registro (logging) para información y errores
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cargar variables de entorno desde .env
load_dotenv()
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


start_scheduler()
init_error_handlers(app)





# Variables de entorno necesarias
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Permitir transporte inseguro para OAuth (solo desarrollo/testing)


# Inicializar la base de datos (crea tablas si no existen)
db.init_db()

# Cargar credenciales OAuth de Google desde archivo JSON
def load_credentials(filepath="client_secret.json"):
    """Carga las credenciales OAuth 2.0 de Google desde un archivo JSON."""
    try:
        import json
        with open(filepath) as f:
            creds = json.load(f)["web"]
        return creds
    except Exception as e:
        logger.error(f"Error cargando credenciales OAuth: {e}")
        return None

# Configuración de OAuth para Gmail
oauth_creds = load_credentials()
OAUTH_CONFIG = {
    "gmail": {
        "client_id": oauth_creds["client_id"] if oauth_creds else None,
        "client_secret": oauth_creds["client_secret"] if oauth_creds else None,
        "auth_url": oauth_creds["auth_uri"] if oauth_creds else None,
        "token_url": oauth_creds["token_uri"] if oauth_creds else None,
        "redirect_uri": "http://127.0.0.1:5000/callback/gmail",
        "scope": ["openid", "email", "profile", "https://mail.google.com/"],
        "imap_server": "imap.gmail.com"
    }
}

# Rutas de Autenticación (OAuth2 Google Gmail)
@app.route("/login/<provider>")
def login(provider):
    """Inicia el flujo OAuth con el proveedor especificado (por ahora, solo Gmail)."""
    if provider not in OAUTH_CONFIG:
        return "Proveedor OAuth no soportado.", 400
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
    """Callback de OAuth: procesa el token devuelto por el proveedor y guarda datos de sesión."""
    if provider not in OAUTH_CONFIG:
        return "Proveedor OAuth no soportado.", 400
    oauth = OAuth2Session(
        OAUTH_CONFIG[provider]["client_id"],
        state=session.get("oauth_state"),
        redirect_uri=OAUTH_CONFIG[provider]["redirect_uri"]
    )
    try:
        token = oauth.fetch_token(
            OAUTH_CONFIG[provider]["token_url"],
            client_secret=OAUTH_CONFIG[provider]["client_secret"],
            authorization_response=request.url
        )
    except Exception as e:
        logger.error(f"Error en callback OAuth: {e}")
        return "Error al obtener token OAuth.", 500
    # Obtener información del usuario (correo electrónico)
    user_info = oauth.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
    session["email"] = user_info.get("email")
    session["oauth_token"] = token
    if not session.get("email"):
        return "⚠️ No se pudo obtener el correo electrónico del usuario.", 400
    # Guardar también token y email en variables de entorno para uso fuera de sesión (escaneo automático)
    os.environ["OAUTH_ACCESS_TOKEN"] = token.get("access_token", "")
    os.environ["OAUTH_EMAIL"] = session["email"]
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    """Cierra la sesión del usuario (elimina tokens de sesión)."""
    session.clear()
    return redirect(url_for("index"))

# Funciones para obtener correos de Gmail
def get_emails():
    """
    Recupera los correos electrónicos de la bandeja de entrada mediante IMAP 
    usando el token OAuth de la sesión actual. Retorna una lista de diccionarios con datos de correos analizados.
    """
    provider = session.get("provider")
    if not provider:
        logger.warning("⚠️ No hay un proveedor autenticado en la sesión.")
        return []
    imap_server = OAUTH_CONFIG[provider]["imap_server"]
    token = session.get("oauth_token", {}).get("access_token")
    email_account = session.get("email")
    if not token or not email_account:
        logger.warning("⚠️ Token OAuth o email de usuario no disponibles en sesión.")
        return []
    emails = []
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        # Autenticación XOAUTH2 con el token de acceso
        mail.authenticate("XOAUTH2", lambda x: f"user={email_account}\1auth=Bearer {token}\1\1")
        mail.select("inbox")
        result, data = mail.search(None, "ALL")
        if result != "OK" or not data or not data[0]:
            logger.warning("⚠️ No se pudieron recuperar correos o la bandeja de entrada está vacía.")
            return []
        email_ids = data[0].split()  # Obtener todos los IDs de correo
        logger.info(f"📩 Se encontraron {len(email_ids)} correos en la bandeja de entrada.")
        for e_id in email_ids:
            result, msg_data = mail.fetch(e_id, "(RFC822)")
            if result != "OK":
                logger.warning(f"⚠️ Error al obtener el correo con ID {e_id}. Saltando...")
                continue
            # Procesar el contenido del mensaje
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg_bytes = response_part[1]
                    # Convertir bytes a objeto email
                    import email as email_module
                    from email import policy
                    msg = email_module.message_from_bytes(msg_bytes, policy=policy.default)
                    subject = msg.get("subject", "(Sin asunto)")
                    sender = msg.get("from", "Desconocido")
                    message_id = msg.get("Message-ID", "").strip()

                    # Obtener cuerpo del mensaje en texto plano
                    try:
                        if msg.is_multipart():
                            body = ""
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                                    break
                        else:
                            body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                    except Exception as e:
                        logger.error(f"⚠️ Error al procesar el contenido del correo ID {e_id}: {e}")
                        continue  # Saltar este correo si hay error en contenido
                    logger.info(f"📨 Procesando correo de: {sender} | Asunto: {subject}")
                    # Analizar archivos adjuntos del correo
                    attachments_analysis = []
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_maintype() == "multipart" or part.get_content_disposition() is None:
                                continue  # Saltar partes que no son adjuntos
                            result_attach = email_analysis.analyze_attachment(part)
                            attachments_analysis.append(result_attach)
                    # Analizar el correo para determinar si es phishing y obtener autenticaciones
                    try:
                        spf_status = email_analysis.check_spf(sender)
                        dkim_status = email_analysis.check_dkim(msg_bytes)
                        dmarc_status = email_analysis.check_dmarc(sender)
                        phishing_status, reasons = email_analysis.is_phishing(
                            body, sender, subject, email_raw=msg_bytes, spf=spf_status, dkim=dkim_status, dmarc=dmarc_status
                        )
                    except Exception as e:
                        logger.error(f"⚠️ Error durante el análisis del correo ID {e_id}: {e}")
                        continue
                    # Enviar alerta por Telegram si phishing de alto riesgo
                    if phishing_status.startswith("Phishing"):
                        utils.send_telegram_alert({"from": sender, "subject": subject}, phishing_status)
                    # Guardar resultados en la lista y en la base de datos
                    email_data = {
                        "subject": subject,
                        "from": sender,
                        "is_phishing": phishing_status,
                        "spf_result": spf_status,
                        "dkim_result": dkim_status,
                        "dmarc_result": dmarc_status,
                        "attachments": attachments_analysis,
                        "message_id": message_id,
                        "reasons": reasons  # ✅ Motivos añadidos
                    }


                    emails.append(email_data)
                    db.save_email_to_db(email_data)  # Registrar en la base de datos
        mail.logout()
        logger.info(f"✅ Correos procesados correctamente: {len(emails)} correos.")
    except Exception as e:
        logger.error(f"⚠️ Error general al obtener correos: {e}")
        return []
    return emails


# Rutas para análisis manual y visualización de datos
@app.route("/analyze_email", methods=["POST"])
def analyze_email():
    """
    Analiza un correo proporcionado manualmente a través del formulario en la página.
    Requiere campos: email_content, email_sender, email_subject, 
    opcionalmente modo_prueba y tipo_real (para pruebas de validación).
    """
    email_body = request.form.get("email_content")
    email_sender = request.form.get("email_sender")
    email_subject = request.form.get("email_subject")
    modo_prueba = request.form.get("modo_prueba") == "true"
    tipo_real = request.form.get("tipo_real")  # "phishing" o "legit" (legítimo)
    if not email_body or not email_sender or not email_subject:
        return "⚠️ Todos los campos son obligatorios.", 400
    # Analizar el correo para determinar si es phishing
    phishing_status = email_analysis.is_phishing(email_body, email_sender, email_subject)
    # Verificar autenticación de remitente (SPF, DKIM, DMARC)
    spf_status = email_analysis.check_spf(email_sender)
    dkim_status = "❌ No se puede verificar DKIM"  # No se dispone del correo original para DKIM
    dmarc_status = email_analysis.check_dmarc(email_sender)
    # Si está en modo prueba, guardar resultado en la tabla de resultados de test
    if modo_prueba and tipo_real:
        correcto = False
        if (tipo_real == "phishing" and phishing_status.startswith("Phishing")) or \
           (tipo_real == "legit" and phishing_status.startswith("Seguro")):
            correcto = True
        db.save_test_result(correcto, tipo_real, phishing_status)
    # Guardar el correo analizado en base de datos y refrescar la lista en pantalla
    db.save_email_to_db({
        "subject": email_subject,
        "from": email_sender,
        "is_phishing": phishing_status,
        "spf_result": spf_status,
        "dkim_result": dkim_status,
        "dmarc_result": dmarc_status
    })
    # Obtener lista actualizada de correos (incluyendo el analizado manualmente) y mostrar en index
    emails = get_emails()
    return render_template("index.html", emails=emails, phishing_result=phishing_status)

@app.route("/historial")
def historial():
    correos_raw = db.get_email_history()
    correos = []
    for row in correos_raw:
        correos.append({
            "id": row["id"],
            "subject": row["subject"],
            "sender": row["sender"],
            "estado": row["estado"],
            "spf": row["spf"],
            "dkim": row["dkim"],
            "dmarc": row["dmarc"],
            "adjuntos": row["adjuntos"],
            "reasons": row["reasons"],
            "fecha": row["fecha"]
        })
    return render_template("historial.html", correos=correos)


@app.route('/detalles_correo/<int:correo_id>')
def detalles_correo(correo_id):
    row = get_email_by_id(correo_id)
    if not row:
        return "Correo no encontrado", 404

    # Convertimos el row de SQLite a diccionario para usarlo fácilmente en el HTML
    email = {
        "subject": row["subject"],
        "from": row["sender"],
        "is_phishing": row["estado"],
        "spf_result": row["spf"],
        "dkim_result": row["dkim"],
        "dmarc_result": row["dmarc"],
        "attachments": eval(row["adjuntos"]) if row["adjuntos"] else [],
        "reasons": row["reasons"].split("; ") if row["reasons"] else []
    }

    return render_template("detalles_correo.html", email=email)



# Rutas para exportar datos

@app.route("/export_csv")
def export_csv():
    correos = db.get_all_emails()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["ID", "Asunto", "Remitente", "Estado", "SPF", "DKIM", "DMARC", "Fecha", "Motivos"])
    for c in correos:
        writer.writerow([c["id"], c["subject"], c["sender"], c["estado"], c["spf"], c["dkim"], c["dmarc"], c["fecha"], c["reasons"]])
    mem = io.BytesIO()
    mem.write(si.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="reporte_phishing.csv")





    
@app.route("/export_pdf")
def export_pdf():
    correos = db.get_all_emails()
    if not correos:
        return "No hay correos para exportar.", 400

    from fpdf import FPDF
    import io

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, "Reporte de Correos Analizados - PhishingDetector", ln=True, align="C")
    pdf.ln(10)

    for c in correos:
        pdf.set_font("Arial", size=10)
        texto = (
            f"ID: {c['id']}\n"
            f"Asunto: {c['subject']}\n"
            f"Remitente: {c['sender']}\n"
            f"Estado: {c['estado']}\n"
            f"SPF: {c['spf']} | DKIM: {c['dkim']} | DMARC: {c['dmarc']}\n"
            f"Fecha: {c['fecha']}\n"
            f"Motivos: {c['reasons']}"
        )
        # Reemplazar caracteres no compatibles con latin-1
        texto = texto.encode("latin-1", "replace").decode("latin-1")
        pdf.multi_cell(0, 8, texto, border=1)
        pdf.ln(2)

    # Exportar como string y luego convertir a bytes
    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    mem = io.BytesIO(pdf_bytes)
    mem.seek(0)
    return send_file(mem, mimetype="application/pdf", as_attachment=True, download_name="reporte_phishing.pdf")



# Rutas de estadísticas y métricas
@app.route("/reportes")
def reportes():
    """
    Devuelve estadísticas generales de los correos analizados en la sesión actual en formato JSON.
    Incluye conteo de tipos de correo (seguros, sospechosos, phishing), conteo de adjuntos por estado y tendencias por fecha.
    """
    emails = get_emails()
    if not emails:
        # Si no hay datos, devolver estructura vacía
        return jsonify({
            "error": "No hay datos disponibles",
            "phishing_stats": [0, 0, 0],
            "attachment_stats": [0, 0, 0],
            "trends": {"dates": [], "counts": []}
        }), 200
    # Contar estados de phishing en la lista de correos actual
    phishing_count = sum(1 for e in emails if e["is_phishing"].startswith("Phishing"))
    sospechoso_count = sum(1 for e in emails if e["is_phishing"].startswith("Sospechoso"))
    seguro_count = len(emails) - phishing_count - sospechoso_count
    # Contar adjuntos según su resultado de análisis
    archivos_limpios = sum(1 for e in emails for adj in e.get("attachments", []) if adj.startswith("✅"))
    archivos_sospechosos = sum(1 for e in emails for adj in e.get("attachments", []) if adj.startswith("⚠️"))
    archivos_peligrosos = sum(1 for e in emails for adj in e.get("attachments", []) if adj.startswith("🚨"))
    # Calcular tendencias de phishing por fecha (días con phishing alto riesgo)
    history = db.get_email_history()
    trend_dict = {}
    for fila in history:
        try:
            estado = fila[3]
            fecha = fila[-1]
            dia = str(fecha).split(" ")[0]
            if "Phishing" in estado:
                trend_dict[dia] = trend_dict.get(dia, 0) + 1
        except Exception as e:
            print(f"Error analizando fila del historial: {e}")

    trend_dates = list(trend_dict.keys())
    trend_counts = list(trend_dict.values())
    # Devolver datos en formato JSON
    return jsonify({
        "phishing_stats": [seguro_count, sospechoso_count, phishing_count],
        "attachment_stats": [archivos_limpios, archivos_sospechosos, archivos_peligrosos],
        "trends": {"dates": trend_dates, "counts": trend_counts}
    })

@app.route("/metricas")
def metricas():
    """
    Calcula métricas de desempeño del detector usando los datos almacenados.
    Retorna JSON con total de correos y porcentajes de precisión, sensibilidad y especificidad de detección de phishing.
    """
    estados = [row[0] for row in db.get_email_states()]
    phishing = estados.count("Phishing 🚨 (Alto riesgo)")
    sospechosos = estados.count("Sospechoso ⚠️ (Riesgo moderado)")
    seguros = estados.count("Seguro ✅ (Bajo riesgo)")
    total = len(estados)
    precision = (phishing / total * 100) if total else 0
    sensibilidad = (phishing / (phishing + sospechosos) * 100) if (phishing + sospechosos) else 0
    especificidad = (seguros / total * 100) if total else 0
    return jsonify({
        "total": total,
        "phishing": phishing,
        "sospechosos": sospechosos,
        "seguros": seguros,
        "precision": round(precision, 2),
        "sensibilidad": round(sensibilidad, 2),
        "especificidad": round(especificidad, 2)
    })

@app.route("/")
def index():
    """Página principal: lista correos analizados o redirige a login si no autenticado."""
    if "oauth_token" not in session:
        # Si el usuario no ha iniciado sesión OAuth, mostrar pantalla de login
        return redirect(url_for("login", provider="gmail"))
    emails = db.get_email_history()

    # Renderizar plantilla principal con la lista de emails analizados
    return render_template("index.html", emails=emails)

# Ejecutar la aplicación Flask (solo si se ejecuta directamente este archivo)
if __name__ == "__main__":
    app.run(debug=True)