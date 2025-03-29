import json
import sqlite3
import os

DB_NAME = "phishing_detector.db"

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
                tiempo_analisis REAL
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

def save_email_to_db(data):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''INSERT INTO correos 
                (user_email, subject, sender, estado, spf, dkim, dmarc, adjuntos, message_id, reasons, score, tiempo_analisis)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                data.get("user_email"),
                data.get("subject"),
                data.get("from"),
                data.get("is_phishing"),
                bool(data.get("spf_result", False)),
                bool(data.get("dkim_result", False)),
                bool(data.get("dmarc_result", False)),
                json.dumps(data.get("attachments", [])),
                data.get("message_id"),
                "; ".join(data.get("reasons", [])),
                data.get("score", 0),
                data.get("tiempo_analisis",0.0)
            ))

            conn.commit()
        except sqlite3.IntegrityError:
            print(f"📌 Correo con ID {data.get('message_id')} ya existe. No se guarda.")

def get_email_history(user_email):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM correos WHERE user_email = ? ORDER BY fecha DESC", (user_email,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

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