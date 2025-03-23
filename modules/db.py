import sqlite3
import os

DB_NAME = "phishing_detector.db"

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT,
                sender TEXT,
                estado TEXT,
                spf TEXT,
                dkim TEXT,
                dmarc TEXT,
                adjuntos TEXT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                message_id TEXT UNIQUE,
                reasons TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resultados_test (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                correcto BOOLEAN,
                tipo_real TEXT,
                tipo_detectado TEXT
            )
        ''')
        conn.commit()

def save_email_to_db(data):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''INSERT INTO correos 
                (subject, sender, estado, spf, dkim, dmarc, adjuntos, fecha, message_id, reasons)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)''', (
                data.get("subject"),
                data.get("from"),
                data.get("is_phishing"),
                data.get("spf_result"),
                data.get("dkim_result"),
                data.get("dmarc_result"),
                str(data.get("attachments", [])),
                data.get("message_id"),
                "; ".join(data.get("reasons", []))
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            print(f"📌 Correo con ID {data.get('message_id')} ya existe. No se guarda.")

def get_email_history():
    conn = sqlite3.connect("phishing_detector.db")
    conn.row_factory = sqlite3.Row  # Permite acceder a columnas por nombre
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, subject, sender, estado, spf, dkim, dmarc, adjuntos, reasons, fecha
        FROM correos ORDER BY fecha DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]  # ← Esto lo convierte a lista de diccionarios


def get_email_states():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT estado FROM correos")
        return cursor.fetchall()

def save_test_result(correcto, tipo_real, tipo_detectado):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO resultados_test (correcto, tipo_real, tipo_detectado)
                          VALUES (?, ?, ?)''', (correcto, tipo_real, tipo_detectado))
        conn.commit()

def get_test_results():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT fecha, correcto, tipo_real, tipo_detectado FROM resultados_test ORDER BY fecha DESC")
        return cursor.fetchall()

def get_email_by_id(correo_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM correos WHERE id = ?", (correo_id,))
    email = cursor.fetchone()
    
    conn.close()
    return email


def get_all_emails():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM correos ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
