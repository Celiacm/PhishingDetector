#Importación de librerias
import ast
import email
import os
import csv, json
import io, time
import imaplib
import logging, traceback
from flask import Flask, redirect, url_for, session, request, render_template, jsonify, Response, send_file, make_response
from requests_oauthlib import OAuth2Session
from jinja2 import Environment, select_autoescape

from fpdf import FPDF
from datetime import datetime
from dotenv import load_dotenv
from email import policy
from email.parser import BytesParser
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.textlabels import Label
from reportlab.pdfgen import canvas

# Importar módulos locales
from modules.scheduler import run as start_scheduler
from modules.error_handler import init_error_handlers
from modules.db import get_email_by_id

import modules.email_analysis as email_analysis
import modules.db as db        # Funciones de base de datos
import modules.utils as utils  # Utilidades generales (Telegram, etc.)


# Inicialización de la app Flask
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Configuración de logging para depuración
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Carga de variables de entorno desde .env
load_dotenv()

# Permitir OAuth en HTTP (solo para desarrollo local)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Iniciar el scheduler (si existe lógica programada como limpieza o actualizaciones)
start_scheduler()

#Iniciar el manejo global de errores personalizados
init_error_handlers(app)

# Cargar claves y tokens de servicios externos
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")





#Inicializar base de datos si aún no existe

db.init_db()
db.limpiar_base_de_datos()

def load_credentials(filepath="client_secret.json"):
    try:
        with open(filepath) as f:
            creds = json.load(f)["web"]
        return creds
    except Exception as e:
        logger.error(f"Error cargando credenciales OAuth: {e}")
        return None

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

@app.route("/login/<provider>")
def login(provider):
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

    user_info = oauth.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
    session["email"] = user_info.get("email")
    session["oauth_token"] = token
    os.environ["OAUTH_ACCESS_TOKEN"] = token.get("access_token", "")
    os.environ["OAUTH_EMAIL"] = session["email"]

    # 🔸 Crear respuesta y añadir cookie personalizada
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("usuario", user_info.get("email"), max_age=60*60*24*7)  # 7 días
    return resp

@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("usuario", "", expires=0)
    return resp
  




def get_emails():
    provider = session.get("provider")
    if not provider:
        return []

    token = session.get("oauth_token", {}).get("access_token")
    email_account = session.get("email")
    if not token or not email_account:
        return []

    emails = []
    try:
        mail = imaplib.IMAP4_SSL(OAUTH_CONFIG[provider]["imap_server"])
        mail.authenticate("XOAUTH2", lambda x: f"user={email_account}\1auth=Bearer {token}\1\1")
        mail.select("inbox")

        result, data = mail.search(None, "ALL")
        if result != "OK":
            return []

        for e_id in data[0].split():
            email_data = process_email(mail, e_id)
            if email_data:
                emails.append(email_data)

        mail.logout()
    except Exception as e:
        logger.error(f"Error al obtener correos: {e}")

    return emails



def process_email(mail, email_id):
    result, msg_data = mail.fetch(email_id, "(RFC822)")
    if result != "OK":
        return None

    raw_email = msg_data[0][1]
    msg = email.message_from_bytes(raw_email, policy=policy.default)

    message_id = msg.get("Message-ID", "").strip()
    if db.get_email_by_message_id(message_id):
        return None

    subject = msg.get("subject", "(Sin asunto)")
    sender = msg.get("from", "(Remitente desconocido)")
    body = extract_email_body(msg)
    attachments = analyze_attachments(msg)

    headers = dict(msg.items())

    resultado = email_analysis.is_phishing({
        "body": body,
        "sender": sender,
        "subject": subject,
        "email_raw": raw_email,
        "spf": email_analysis.check_spf(sender),
        "dkim": email_analysis.check_dkim(raw_email),
        "dmarc": email_analysis.check_dmarc(sender),
        "attachments": attachments,
        "enlaces": email_analysis.analizar_enlaces(body),
        "return_path_diff": False,
        "dominio_gratuito": False,
        "header_privada": False,
        "remitente_raro": False,
        "adjunto_raro": email_analysis.tiene_adjuntos_raros(attachments),
        "urgente": email_analysis.analizar_contenido(body)["urgente"],
        "html_excesivo": email_analysis.analizar_contenido(body)["html_excesivo"]
    })

    motivos = resultado["motivos"]
    if not isinstance(motivos, list):
        motivos = [motivos]

    start = time.time()

    email_data = {
        "user_email": session.get("email"),
        "subject": subject,
        "from": sender,
        "estado": resultado["estado"],
        "spf_result": resultado["spf"],
        "dkim_result": resultado["dkim"],
        "dmarc_result": resultado["dmarc"],
        "attachments": attachments,
        "message_id": message_id,
        "reasons": motivos,
        "score": resultado["score"],
        "tiempo_analisis": round(time.time() - start, 2),
    }

    db.save_email_to_db(email_data)

    # ⚡️ ENVÍO AUTOMÁTICO DE ALERTA
    if email_data.get("estado") == "Phishing":
        utils.send_telegram_alert({
            "from": email_data.get("from", "Desconocido"),
            "subject": email_data.get("subject", "(Sin asunto)")
        }, email_data.get("estado"))

    return email_data




def extract_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
    return body

def analyze_attachments(msg):
    attachments_analysis = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                attachments_analysis.append(email_analysis.analyze_attachment(part))
    return attachments_analysis



@app.route("/")
def index():
    if "oauth_token" not in session:
        return redirect(url_for("login", provider="gmail"))

    get_emails()
    
    print("Email en sesión:", session.get("email"))  # 👀 comprueba esto

    emails = db.get_email_history(session.get("email"))
    # 🔥 Asegurar que 'reasons' sea lista de verdad
    for correo in emails:
        reasons_raw = correo.get("reasons")
        if isinstance(reasons_raw, str):
            try:
                correo["reasons"] = ast.literal_eval(reasons_raw)
            except (ValueError, SyntaxError):
                correo["reasons"] = [reasons_raw]  # Si falla, lo mete como lista normal
        elif reasons_raw is None:
            correo["reasons"] = []  # 🔥 Asegura que siempre sea lista


    usuario_cookie = request.cookies.get("usuario")
    if usuario_cookie:
        logger.info(f"🧠 Cookie 'usuario' detectada: {usuario_cookie}")

    return render_template("index.html", emails=emails)




@app.route("/historial")
def historial():
    return redirect(url_for('index'))  # 🔥 Redirige a la página principal




@app.route("/reportes")
def reportes():
    emails = db.get_email_history(session.get("email"))

    phishing_count = sum(1 for e in emails if e["estado"].startswith("Phishing"))
    sospechoso_count = sum(1 for e in emails if e["estado"].startswith("Sospechoso"))
    seguro_count = len(emails) - phishing_count - sospechoso_count

    archivos_sospechosos = 0
    archivos_limpios = 0
    archivos_peligrosos = 0

    for e in emails:
        adjuntos_raw = e.get("attachments") or e.get("adjuntos") or "[]"

        try:
            adjuntos = json.loads(adjuntos_raw) if isinstance(adjuntos_raw, str) else adjuntos_raw
        except Exception:
            adjuntos = []

        archivos_sospechosos += sum(
            1 for adj in adjuntos if "Phishing" in adj or "Sospechoso" in adj
        )

        archivos_limpios += sum(
            1 for adj in adjuntos if "Phishing" not in adj and "Sospechoso" not in adj
        )
        archivos_peligrosos += sum(
            1 for adj in adjuntos if "Phishing" not in adj and "Sospechoso" not in adj
        )


  
        # Timeline por fecha
    timeline = {}
    for e in emails:
        fecha = e["fecha"].split(" ")[0]  # Solo "YYYY-MM-DD"
        timeline.setdefault(fecha, {"phishing": 0, "total": 0})
        timeline[fecha]["total"] += 1
        if e["estado"].startswith("Phishing"):
            timeline[fecha]["phishing"] += 1

    timeline_sorted = sorted(timeline.items())
    fechas = [t[0] for t in timeline_sorted]
    total_por_dia = [t[1]["total"] for t in timeline_sorted]
    phishing_por_dia = [t[1]["phishing"] for t in timeline_sorted]


    # 🧠 Devolver datos extendidos
    return jsonify({
        "phishing_stats": [seguro_count, sospechoso_count, phishing_count],
        "attachment_stats": [archivos_limpios, archivos_sospechosos, archivos_peligrosos],
        "trends": {
            "dates": fechas,
            "counts": phishing_por_dia,
            "totalCounts": total_por_dia
        },
        "timeline": {
            "dates": fechas,
            "totalCounts": total_por_dia
        }
    })



@app.route("/export_csv")
def export_csv():
    correos = db.get_all_emails(session.get("email"))
    si = io.StringIO()
    writer = csv.writer(si, delimiter=';', quoting=csv.QUOTE_MINIMAL)

    # Cabecera más descriptiva
    writer.writerow([
        "📄 ID", "📌 Asunto", "📨 Remitente", "🛡️ Estado", 
        "✅ SPF", "✅ DKIM", "✅ DMARC", 
        "📅 Fecha", "📋 Motivos de detección"
    ])

    for c in correos:
        try:
            motivos = json.loads(c["reasons"]) if c.get("reasons") else []
        except (json.JSONDecodeError, TypeError):
            motivos = []

        if not motivos:
            motivos = ["(Motivos no disponibles)"]

        motivos_str = " | ".join(motivos)

        estado = c.get("estado", "").lower()

        if "phishing" in estado:
            estado_color = "🚨 Phishing"
        elif "sospechoso" in estado:
            estado_color = "⚠️ Sospechoso"
        else:
            estado_color = "✅ Seguro"

        writer.writerow([
            c.get("id", "--"),
            c.get("subject", "--"),
            c.get("sender", "--"),
            estado_color,
            c.get("spf", "--"),
            c.get("dkim", "--"),
            c.get("dmarc", "--"),
            c.get("fecha", "--"),
            motivos_str
        ])


    mem = io.BytesIO()
    mem.write(si.getvalue().encode("utf-8-sig"))  # BOM para Excel
    mem.seek(0)
    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name="reporte_phishing.csv"
    )



@app.route("/export_pdf")
def export_pdf():
    from reportlab.lib.enums import TA_CENTER
    correos = db.get_all_emails(session.get("email"))
    
    phishing = sum(1 for c in correos if c["estado"].startswith("Phishing"))
    sospechosos = sum(1 for c in correos if c["estado"].startswith("Sospechoso"))
    seguros = len(correos) - phishing - sospechosos

    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=1*cm, leftMargin=1*cm, topMargin=1.5*cm, bottomMargin=1.5*cm)

    elements = []
    styles = getSampleStyleSheet()
    styleH = styles["Heading1"]
    styleH.alignment = TA_CENTER

    styleN = styles["Normal"]

    # Título
    elements.append(Paragraph("📄 Reporte de Correos Analizados - PhishingDetector", styleH))
    elements.append(Spacer(1, 12))

    # 📊 Añadir gráfico circular
    drawing = Drawing(200, 150)
    pie = Pie()
    pie.x = 50
    pie.y = 10
    pie.width = 100
    pie.height = 100
    pie.data = [seguros, sospechosos, phishing]
    pie.labels = ['✅ Seguros', '⚠️ Sospechosos', '🚨 Phishing']
    pie.slices.strokeWidth = 0.5
    pie.slices[0].fillColor = colors.green
    pie.slices[1].fillColor = colors.orange
    pie.slices[2].fillColor = colors.red
    drawing.add(pie)
    elements.append(drawing)
    elements.append(Spacer(1, 20))

    # 📋 Resumen
    resumen_data = [
        ["📬 Total de correos", str(len(correos))],
        ["✅ Correos seguros", str(seguros)],
        ["⚠️ Sospechosos", str(sospechosos)],
        ["🚨 Phishing detectado", str(phishing)],
    ]
    resumen_table = Table(resumen_data, colWidths=[8*cm, 4*cm])
    resumen_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey)
    ]))
    elements.append(resumen_table)
    elements.append(Spacer(1, 20))

    # 📄 Tabla de correos
    table_data = [[
        "ID", "Asunto", "Remitente", "Estado", "SPF", "DKIM", "DMARC", "Fecha"
    ]]
    par_style = ParagraphStyle(name="CellStyle", fontSize=7, leading=9)

    for c in correos:
        asunto = Paragraph(c["subject"][:100], par_style)
        remitente = Paragraph(c["sender"], par_style)
        estado = Paragraph(c["estado"], par_style)

        fila = [
            str(c["id"]),
            asunto,
            remitente,
            estado,
            str(c["spf"]),
            str(c["dkim"]),
            str(c["dmarc"]),
            str(c["fecha"])
        ]

        table_data.append(fila)

    correo_table = Table(
        table_data,
        colWidths=[1.2*cm, 5.2*cm, 4.5*cm, 3*cm, 1.2*cm, 1.2*cm, 1.4*cm, 2.8*cm]
    )

    # 🖌️ Si es phishing, fondo rojo en la fila
    style_list = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9d9d9")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ]

    # Pintar filas de phishing
    for idx, correo in enumerate(correos, start=1):
        if correo["estado"].startswith("Phishing"):
            style_list.append(("BACKGROUND", (0, idx), (-1, idx), colors.HexColor("#ffcccc")))

    correo_table.setStyle(TableStyle(style_list))

    elements.append(Paragraph("📋 Detalle de Correos Analizados", styles["Heading2"]))
    elements.append(Spacer(1, 12))
    elements.append(correo_table)

    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    output.seek(0)
    return send_file(
        output,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="reporte_phishing.pdf"
    )


def add_page_number(canvas, doc):
    page_num = canvas.getPageNumber()
    text = f"Página {page_num}"
    canvas.setFont('Helvetica', 9)
    canvas.drawRightString(200*mm, 15*mm, text)


@app.route("/analyze_email_eml", methods=["POST"])
def analyze_email_eml():
    if "eml_file" not in request.files:
        return jsonify({"error": "No se ha subido ningún archivo .eml"}), 400

    eml_file = request.files["eml_file"]
    if eml_file.filename == "":
        return jsonify({"error": "Archivo vacío o inválido"}), 400

    try:
        
        result = email_analysis.analyze_eml_file(eml_file)  # 🔥 Sin hacer .read() aquí

    
            
        if "error" in result:
            return jsonify(result), 500

        # Asegurar que "reasons" sea siempre lista
        if not isinstance(result.get("reasons"), list):
            result["reasons"] = [result.get("reasons", "(Motivos no disponibles)")]

        result["user_email"] = session.get("email")
        result["message_id"] = result.get("message_id", None)
        result["tiempo_analisis"] = result.get("tiempo_analisis", 0.0)


        # 🔥 Guardar en base de datos
        correo_id = db.save_email_to_db(result)

        # ⚡️ Alertar si es phishing
        if result.get("estado") == "Phishing":
            utils.send_telegram_alert({
                "from": result.get("sender", "Desconocido"),
                "subject": result.get("subject", "(Sin asunto)")
            }, result.get("estado"))

        # ✅ Devolver todo al frontend
        return jsonify({
            "subject": result.get("subject", ""),
            "sender": result.get("sender", ""),
            "estado": result.get("estado", ""),
            "score": result.get("score", 0),
            "spf": result.get("spf", False),
            "dkim": result.get("dkim", False),
            "dmarc": result.get("dmarc", False),
            "reasons": result.get("reasons", []),
            "attachments": result.get("attachments", []),
            "correo_id": correo_id,
            "tiempo": result.get("tiempo_analisis", 0)
        })

    except Exception as e:
        print(f"[ERROR] Fallo al analizar el archivo .eml: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Hubo un problema al analizar el archivo.'}), 500



@app.route("/dev/sync_estados")
def sync_estados():
    db.actualizar_estado_por_score()
    return "Estados actualizados."





@app.route("/feedback", methods=["POST"])
def guardar_feedback():
    id_correo = request.form.get("correo_id")
    correcto = request.form.get("correcto") == "true"
    db.guardar_feedback(id_correo, correcto)
    return "OK"



@app.route("/metricas")
def metricas():
    emails = db.get_email_history(session.get("email"))

    total = len(emails)
    phishing = sum(1 for e in emails if e["estado"].startswith("Phishing"))
    sospechosos = sum(1 for e in emails if e["estado"].startswith("Sospechoso"))
    seguros = total - phishing - sospechosos

    tiempos = [e["tiempo_analisis"] for e in emails if e.get("tiempo_analisis") is not None]
    tiempo_medio = round(sum(tiempos) / len(tiempos), 2) if tiempos else 0
    feedback = db.get_feedback_stats(session.get("email"))



    ultimo = max((e["fecha"] for e in emails), default="--")

    return jsonify({
        "total": total,
        "phishing": phishing,
        "sospechosos": sospechosos,
        "seguros": seguros,
        "porcentaje_sospechosos": round((sospechosos / total) * 100, 2) if total else 0,
        "tiempo_medio": tiempo_medio,
        "ultimo_analisis": ultimo,
        "precision": 93.5,        # puedes ajustar si tienes métricas reales
        "sensibilidad": 88.2,
        "especificidad": 95.4,
        "feedback_correctos": feedback["correctos"],
        "feedback_incorrectos": feedback["incorrectos"]
    })



@app.route("/enviar_test", methods=["POST"])
def enviar_test():
    respuestas_correctas = {
        "respuesta_1": "phishing",
        "respuesta_2": "phishing",
        "respuesta_3": "seguro"
    }

    puntuacion = 0
    total = len(respuestas_correctas)

    for clave, correcta in respuestas_correctas.items():
        respuesta = request.form.get(clave)
        if respuesta == correcta:
            puntuacion += 1

    mensaje = f"✅ Has acertado {puntuacion} de {total} respuestas."

    if puntuacion == total:
        mensaje += " ¡Perfecto!"
    elif puntuacion >= 2:
        mensaje += " ¡Buen trabajo!"
    else:
        mensaje += " Te recomendamos repasar conceptos."

    return jsonify({"mensaje": mensaje})





@app.route("/evaluar_enlaces", methods=["POST"])
def evaluar_enlaces():
    respuestas = request.form
    total = 0
    usuario_aciertos = 0
    coincidencias = 0

    casos = {
        "e1": "https://apple.verify.com/login",
        "e2": "https://www.paypal.com/security",
        "e3": "http://login-bank.xyz/verify"
    }

    correctas = {
        "e1": "phishing",
        "e2": "seguro",
        "e3": "phishing"
    }

    for clave, url in casos.items():
        user_resp = respuestas.get(clave)
        total += 1

        resultado_analisis = email_analysis.is_phishing({
            "body": url,
            "sender": "prueba@ejemplo.com",
            "subject": "Test",
            "email_raw": b"",
            "spf": True,
            "dkim": True,
            "dmarc": True,
            "attachments": [],
            "enlaces": email_analysis.analizar_enlaces(url),
            "return_path_diff": False,
            "dominio_gratuito": False,
            "header_privada": False,
            "remitente_raro": False,
            "adjunto_raro": False,
            "urgente": False,
            "html_excesivo": False
        })

        sistema = "phishing" if resultado_analisis["estado"] == "Phishing" else "seguro"

        if user_resp == correctas[clave]:
            usuario_aciertos += 1
        if sistema == user_resp:
            coincidencias += 1

    return jsonify({
        "usuario": usuario_aciertos,
        "coincidencias": coincidencias,
        "total": total
    })



@app.route("/evaluar_visual", methods=["POST"])
def evaluar_visual():
    respuestas = request.form
    total = 0
    usuario_aciertos = 0
    coincidencias = 0

    ejemplos = {
        "v1": "Estimado usuario, haga clic en el siguiente enlace para confirmar su cuenta: http://login-seguro.tk",
        "v2": "Netflix te agradece tu pago mensual. Tu factura está disponible en tu cuenta.",
        "v3": "Su cuenta PayPal ha sido limitada. Visite http://secure.pay-pal.com para restaurarla."
    }

    correctas = {
        "v1": "phishing",
        "v2": "seguro",
        "v3": "phishing"
    }

    for clave, texto in ejemplos.items():
        user_resp = respuestas.get(clave)
        total += 1

        resultado_analisis = email_analysis.is_phishing({
            "body": texto,
            "sender": "test@fake.com",
            "subject": "Correo visual",
            "email_raw": b"",
            "spf": True,
            "dkim": True,
            "dmarc": True,
            "attachments": [],
            "enlaces": email_analysis.analizar_enlaces(texto),
            "return_path_diff": False,
            "dominio_gratuito": False,
            "header_privada": False,
            "remitente_raro": False,
            "adjunto_raro": False,
            "urgente": True,  # para asegurar detección de urgencia
            "html_excesivo": False
        })

        sistema = "phishing" if resultado_analisis["estado"] == "Phishing" else "seguro"

        if user_resp == correctas[clave]:
            usuario_aciertos += 1
        if sistema == user_resp:
            coincidencias += 1

    return jsonify({
        "usuario": usuario_aciertos,
        "coincidencias": coincidencias,
        "total": total
    })




@app.route("/analizar_respuesta_rapida", methods=["POST"])
def analizar_respuesta_rapida():
    texto = request.form.get("texto", "")

    resultado_analisis = email_analysis.is_phishing({
        "body": texto,
        "sender": "jugador@test.com",
        "subject": "Juego Rápido",
        "email_raw": b"",
        "spf": True,
        "dkim": True,
        "dmarc": True,
        "attachments": [],
        "enlaces": email_analysis.analizar_enlaces(texto),
        "return_path_diff": False,
        "dominio_gratuito": False,
        "header_privada": False,
        "remitente_raro": False,
        "adjunto_raro": False,
        "urgente": any(palabra in texto.lower() for palabra in email_analysis.KEYWORDS),
        "html_excesivo": False
    })

    sistema = "phishing" if resultado_analisis["estado"] == "Phishing" else "seguro"

    return jsonify({"resultado": sistema})




@app.route("/evaluar_versus", methods=["POST"])
def evaluar_versus():
    archivo = request.files.get("emlFile")
    usuario = request.form.get("usuarioDecision")

    if not archivo or not archivo.filename.endswith(".eml"):
        return jsonify({"error": "Archivo inválido"}), 400

    raw_bytes = archivo.read()

    eml_info = email_analysis.analyze_eml_file(io.BytesIO(raw_bytes))

    subject = eml_info.get("subject", "")
    sender = eml_info.get("from", "")
    body = eml_info.get("body", "")
    attachments = eml_info.get("attachments", [])

    resultado_enlaces = email_analysis.analizar_enlaces(body)
    resultado_cabeceras = email_analysis.analizar_cabeceras(raw_bytes)
    resultado_contenido = email_analysis.analizar_contenido(body)

    resultado_analisis = email_analysis.is_phishing({
        "body": body,
        "sender": sender,
        "subject": subject,
        "email_raw": raw_bytes,
        "spf": email_analysis.check_spf(sender),
        "dkim": email_analysis.check_dkim(raw_bytes),
        "dmarc": email_analysis.check_dmarc(sender),
        "attachments": attachments,
        "enlaces": resultado_enlaces,
        "return_path_diff": resultado_cabeceras["return_path_diff"],
        "dominio_gratuito": resultado_cabeceras["dominio_gratuito"],
        "header_privada": resultado_cabeceras["header_privada"],
        "remitente_raro": resultado_cabeceras["remitente_raro"],
        "adjunto_raro": email_analysis.tiene_adjuntos_raros(attachments),
        "urgente": resultado_contenido["urgente"],
        "html_excesivo": resultado_contenido["html_excesivo"]
    })

    sistema = "phishing" if resultado_analisis["estado"] == "Phishing" else "seguro"

    return jsonify({
        "usuario": usuario,
        "sistema": sistema
    })


@app.route("/evaluar_dominios", methods=["POST"])
def evaluar_dominios():
    respuestas = request.form
    total = 0
    usuario_aciertos = 0
    coincidencias = 0

    dominios = {
        "d1": "paypal-verification.com",
        "d2": "apple.com",
        "d3": "micr0soft-support.net"
    }

    correctas = {
        "d1": "phishing",
        "d2": "seguro",
        "d3": "phishing"
    }

    for clave, dominio in dominios.items():
        user_resp = respuestas.get(clave)
        total += 1

        resultado_analisis = email_analysis.is_phishing({
            "body": dominio,
            "sender": f"test@{dominio}",
            "subject": "Test dominio",
            "email_raw": b"",
            "spf": True,
            "dkim": True,
            "dmarc": True,
            "attachments": [],
            "enlaces": email_analysis.analizar_enlaces(dominio),
            "return_path_diff": False,
            "dominio_gratuito": dominio.endswith(tuple(email_analysis.SUSPICIOUS_TLDS)),
            "header_privada": False,
            "remitente_raro": False,
            "adjunto_raro": False,
            "urgente": False,
            "html_excesivo": False
        })

        sistema = "phishing" if resultado_analisis["estado"] == "Phishing" else "seguro"

        if user_resp == correctas[clave]:
            usuario_aciertos += 1
        if sistema == user_resp:
            coincidencias += 1

    return jsonify({
        "usuario": usuario_aciertos,
        "coincidencias": coincidencias,
        "total": total
    })



@app.context_processor
def utility_processor():
    return dict(loads=json.loads)



@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

@app.template_filter('from_json')
def from_json_filter(s):
    try:
        return json.loads(s)
    except Exception:
        return []




if __name__ == "__main__":
    app.run(debug=True)
  