import json
import sqlite3
import os

from modules.helpers import score_a_estado




DB_NAME = "phishing_detector.db"
FEEDBACK_CORRECTO = "Correcto"
FEEDBACK_INCORRECTO = "Incorrecto"


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
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
    with sqlite3.connect(DB_NAME) as con:
        cur = con.cursor()
        cur.execute("UPDATE correos SET feedback_usuario = ? WHERE id = ?", 
                    ("Correcto" if correcto else "Incorrecto", id_correo))
        con.commit()


def get_feedback_stats(user_email):
    with sqlite3.connect(DB_NAME) as conn:
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
    conn.close()
    return existe




def save_email_to_db(data):
    with sqlite3.connect(DB_NAME) as conn:
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
    with sqlite3.connect(DB_NAME) as conn:
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
                reasons = json.loads(row[9]) if row[9] else []
            except json.JSONDecodeError:
                reasons = [row[9]] if row[9] else []

            correo = {
                "id": row[0],
                "subject": row[1],
                "sender": row[2],
                "estado": score_a_estado(row[10], reasons),
                "spf": bool(row[4]),
                "dkim": bool(row[5]),
                "dmarc": bool(row[6]),
                "attachments": json.loads(row[7]) if row[7] else [],
                "message_id": row[8],
                "reasons_parsed": reasons,
                "score": min(row[10], 15),
                "fecha": row[11]
            }
            emails.append(correo)

        return emails




def existe_remitente(sender_email):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM correos WHERE sender = ?", (sender_email,))
        resultado = cursor.fetchone()
        return resultado and resultado[0] > 0

    


def get_email_states(user_email):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT estado FROM correos WHERE user_email = ?", (user_email,))
        return cursor.fetchall()

def save_test_result(correcto, tipo_real, tipo_detectado, correo_id=None):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO resultados_test (correcto, tipo_real, tipo_detectado, correo_id)
                          VALUES (?, ?, ?, ?)''', (correcto, tipo_real, tipo_detectado, correo_id))
        conn.commit()

def get_test_results():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT fecha, correcto, tipo_real, tipo_detectado, correo_id FROM resultados_test ORDER BY fecha DESC")
        return cursor.fetchall()

def get_email_by_id(correo_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM correos WHERE id = ?", (correo_id,))
    email = cursor.fetchone()
    conn.close()
    return email

def get_all_emails(user_email):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM correos WHERE user_email = ? ORDER BY id DESC", (user_email,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_email_by_message_id(message_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM correos WHERE message_id = ?", (message_id,))
    email = cursor.fetchone()
    conn.close()
    return dict(email) if email else None



def actualizar_estado_por_score():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # ✅ Esto convierte las filas en diccionarios
    cursor = conn.cursor()
    cursor.execute("SELECT id, score FROM correos")
    rows = cursor.fetchall()

    for row in rows:
        score = row["score"]
        nuevo_estado = "Phishing" if score >= 10 else "Sospechoso" if score >= 5 else "Seguro"
        cursor.execute("UPDATE correos SET estado = ? WHERE id = ?", (nuevo_estado, row["id"]))

    conn.commit()
    conn.close()

