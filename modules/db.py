import json
import sqlite3
import os

from modules.helpers import score_a_estado


conn_global = None  #para pruebas de integración


DB_NAME = "phishing_detector.db"
FEEDBACK_CORRECTO = "Correcto"
FEEDBACK_INCORRECTO = "Incorrecto"

def get_connection():
    global conn_global
    return conn_global or sqlite3.connect(DB_NAME)

def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT,
                subject TEXT,
                sender TEXT,
                estado TEXT,
                spf BOOLEAN,
                dkim BOOLEAN,
                dmarc BOOLEAN,
                adjuntos TEXT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                message_id TEXT UNIQUE,
                reasons TEXT,
                score INTEGER DEFAULT 0,
                tiempo_analisis REAL, 
                feedback_usuario TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resultados_test (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                correcto BOOLEAN,
                tipo_real TEXT,
                tipo_detectado TEXT,
                correo_id INTEGER,
                FOREIGN KEY (correo_id) REFERENCES correos(id)
            )
        ''')
        conn.commit()
        
        
def guardar_feedback(id_correo, correcto):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE correos SET feedback_usuario = ? WHERE id = ?", 
                    ("Correcto" if correcto else "Incorrecto", id_correo))
        conn.commit()


def get_feedback_stats(user_email):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN feedback_usuario = 'Correcto' THEN 1 ELSE 0 END) AS correctos,
                SUM(CASE WHEN feedback_usuario = 'Incorrecto' THEN 1 ELSE 0 END) AS incorrectos
            FROM correos
            WHERE user_email = ?
        """, (user_email,))
        result = cursor.fetchone()
        return {"correctos": result[0] or 0, "incorrectos": result[1] or 0}





def correo_ya_analizado(message_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id FROM correos WHERE message_id = ?", (message_id,))
    existe = c.fetchone() is not None
    return existe




def save_email_to_db(data):
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            # ✅ Solo calcular estado si no viene en los datos

            score = data.get("score", 0)

            motivos = data.get("reasons", [])
            data["estado"] = score_a_estado(score, motivos)

            if isinstance(motivos, str):
                try:
                    motivos = json.loads(motivos)
                except Exception:
                    motivos = [motivos]

            cursor.execute('''INSERT INTO correos 
                (user_email, subject, sender, estado, spf, dkim, dmarc, adjuntos, message_id, reasons, score, tiempo_analisis)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                data.get("user_email"),
                data.get("subject"),
                data.get("from"),
                data.get("estado"),
                bool(data.get("spf_result", False)),
                bool(data.get("dkim_result", False)),
                bool(data.get("dmarc_result", False)),

                json.dumps(data.get("attachments", [])),
                data.get("message_id"),
                json.dumps(data.get("reasons", [])),
                data.get("score", 0),
                data.get("tiempo_analisis", 0.0)
            ))

            conn.commit()
            return cursor.lastrowid  # Devuelve el ID del correo guardado
        except sqlite3.IntegrityError:
            print(f"📌 Correo con ID {data.get('message_id')} ya existe. No se guarda.")
            return None




def get_email_history(user_email=None):
    with get_connection() as conn:
        cursor = conn.cursor()
        if user_email:
            cursor.execute("""
                SELECT id, subject, sender, estado, spf, dkim, dmarc, adjuntos, message_id, reasons, score, fecha 
                FROM correos 
                WHERE LOWER(TRIM(user_email)) = LOWER(TRIM(?)) 
                ORDER BY id DESC
            """, (user_email,))
        else:
            cursor.execute("""
                SELECT id, subject, sender, estado, spf, dkim, dmarc, adjuntos, message_id, reasons, score, fecha 
                FROM correos 
                ORDER BY id DESC
            """)

        emails = []
        for row in cursor.fetchall():
            try:
                motivos = json.loads(row[9]) if row[9] else []
            except json.JSONDecodeError:
                motivos = [row[9]] if row[9] else []

            correo = {
                "id": row[0],
                "subject": row[1],
                "sender": row[2],
                "estado": row[3],
                "spf": bool(row[4]),
                "dkim": bool(row[5]),
                "dmarc": bool(row[6]),
                "attachments": json.loads(row[7]) if row[7] else [],
                "message_id": row[8],
                "reasons": motivos,  # <-- ✅ OJO AQUÍ, usa "reasons" no "motivos"
                "score": min(row[10], 15),
                "fecha": row[11]
            }
            emails.append(correo)

        return emails





def existe_remitente(sender_email):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM correos WHERE sender = ?", (sender_email,))
        resultado = cursor.fetchone()
        return resultado and resultado[0] > 0

    


def get_email_states(user_email):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT estado FROM correos WHERE user_email = ?", (user_email,))
        return cursor.fetchall()

def save_test_result(correcto, tipo_real, tipo_detectado, correo_id=None):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO resultados_test (correcto, tipo_real, tipo_detectado, correo_id)
                          VALUES (?, ?, ?, ?)''', (correcto, tipo_real, tipo_detectado, correo_id))
        conn.commit()

def get_test_results():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT fecha, correcto, tipo_real, tipo_detectado, correo_id FROM resultados_test ORDER BY fecha DESC")
        return cursor.fetchall()

def get_email_by_id(correo_id):
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM correos WHERE id = ?", (correo_id,))
        email = cursor.fetchone()
        return email

def get_all_emails(user_email):
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM correos WHERE user_email = ? ORDER BY id DESC", (user_email,))
        rows = cursor.fetchall()
        emails = []
        for row in rows:
            correo = dict(row)
            correo["spf"] = correo["spf"] == "True" or correo["spf"] == 1
            correo["dkim"] = correo["dkim"] == "True" or correo["dkim"] == 1
            correo["dmarc"] = correo["dmarc"] == "True" or correo["dmarc"] == 1
            correo["attachments"] = json.loads(correo["adjuntos"]) if correo.get("adjuntos") else []
            correo["reasons"] = json.loads(correo["reasons"]) if correo.get("reasons") else []
            emails.append(correo)

        return emails



def get_email_by_message_id(message_id):
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM correos WHERE message_id = ?", (message_id,))
        email = cursor.fetchone()
        return dict(email) if email else None



def actualizar_estado_por_score():
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row 
        cursor = conn.cursor()
        cursor.execute("SELECT id, score FROM correos")
        rows = cursor.fetchall()

        for row in rows:
            score = row["score"]
            nuevo_estado = "Phishing" if score >= 10 else "Sospechoso" if score >= 5 else "Seguro"
            cursor.execute("UPDATE correos SET estado = ? WHERE id = ?", (nuevo_estado, row["id"]))

        conn.commit()

# Función para limpiar completamente la tabla de correos
def limpiar_base_de_datos():
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM correos")
        correos = cursor.fetchall()

        for correo in correos:
            id_correo = correo["id"]
            spf = correo["spf"]
            dkim = correo["dkim"]
            dmarc = correo["dmarc"]
            reasons = correo["reasons"]
            score = correo["score"]

            # 1. Corrige motivos
            try:
                reasons_list = json.loads(reasons) if reasons else []
            except json.JSONDecodeError:
                reasons_list = [reasons] if reasons else []

            # Limpia motivos incorrectos
            reasons_limpios = []
            for motivo in reasons_list:
                if "SPF fallido" in motivo and spf == 1:
                    continue
                if "DKIM fallido" in motivo and dkim == 1:
                    continue
                if "DMARC fallido" in motivo and dmarc == 1:
                    continue
                reasons_limpios.append(motivo)

            # 2. Corrige estado si score cambiado
            if score >= 10:
                nuevo_estado = "Phishing"
            elif score >= 5:
                nuevo_estado = "Sospechoso"
            else:
                nuevo_estado = "Seguro"

            # 3. Guarda correcciones en la base de datos
            cursor.execute("""
                UPDATE correos
                SET reasons = ?, estado = ?
                WHERE id = ?
            """, (json.dumps(reasons_limpios), nuevo_estado, id_correo))

        conn.commit()
        print("✅ Base de datos limpiada y corregida correctamente.")