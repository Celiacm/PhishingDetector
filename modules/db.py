import sqlite3
import logging

logger = logging.getLogger(__name__)

DB_PATH = "phishing_detector.db"

def init_db():
    """Crea la base de datos (si no existe) y las tablas necesarias."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Tabla de correos analizados
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS correos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asunto TEXT,
                remitente TEXT,
                estado TEXT,
                spf TEXT,
                dkim TEXT,
                dmarc TEXT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Tabla de resultados de pruebas (modo prueba de análisis)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS resultados_test (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                correcto BOOLEAN,
                tipo_real TEXT,
                tipo_detectado TEXT
            )
        """)
        conn.commit()
    except Exception as e:
        logger.error(f"Error al inicializar la base de datos: {e}")
    finally:
        conn.close()

def save_email_to_db(email_data):
    """Inserta un registro de correo analizado en la tabla 'correos'."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO correos (asunto, remitente, estado, spf, dkim, dmarc)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            email_data.get("subject"),
            email_data.get("from"),
            email_data.get("is_phishing"),
            email_data.get("spf_result"),
            email_data.get("dkim_result"),
            email_data.get("dmarc_result")
        ))
        conn.commit()
    except Exception as e:
        logger.error(f"Error al guardar correo en BD: {e}")
    finally:
        conn.close()

def save_test_result(correcto, tipo_real, tipo_detectado):
    """Guarda un resultado de prueba (validación manual) en la tabla 'resultados_test'."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO resultados_test (correcto, tipo_real, tipo_detectado)
            VALUES (?, ?, ?)
        """, (correcto, tipo_real, tipo_detectado))
        conn.commit()
    except Exception as e:
        logger.error(f"Error al guardar resultado de test en BD: {e}")
    finally:
        conn.close()

def get_email_history():
    """Recupera todos los correos analizados almacenados, ordenados por fecha descendente."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM correos ORDER BY fecha DESC")
    correos = cursor.fetchall()
    conn.close()
    return correos

def get_test_results():
    """Recupera todos los resultados de pruebas de detección almacenados."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT fecha, correcto, tipo_real, tipo_detectado FROM resultados_test")
    resultados = cursor.fetchall()
    conn.close()
    return resultados

def get_email_states():
    """Recupera la lista de estados de todos los correos analizados (para cálculos estadísticos)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT estado FROM correos")
    estados = cursor.fetchall()
    conn.close()
    return estados
