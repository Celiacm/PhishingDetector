# -*- coding: utf-8 -*-
import unittest
import os
import json
import sqlite3
from io import BytesIO
from app import app
from modules import db
from modules.helpers import score_a_estado

class TestIntegracion(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

        # Base de datos en memoria
        self.conn = sqlite3.connect(":memory:")
        db.conn_global = self.conn  # ✅ Usamos la conexión en memoria durante las pruebas

        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE correos (
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
        self.conn.commit()

    def test_subida_eml_y_almacenamiento(self):
        """Caso 12: Subir correo y almacenar en base de datos"""
        contenido_eml = (
            b"From: test@example.com\r\n"
            b"Subject: Test Mail\r\n"
            b"Message-ID: <msg-id-test>\r\n"
            b"Authentication-Results: spf=pass; dkim=pass; dmarc=pass\r\n"
            b"\r\n"
            b"Este es un correo legitimo de prueba."
        )

        eml = BytesIO(contenido_eml)
        eml.name = "correo_legitimo.eml"

        response = self.client.post('/analyze_email_eml', data={'eml_file': eml}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        self.assertIn("subject", response.data.decode())

        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM correos")
        count = cursor.fetchone()[0]
        self.assertGreaterEqual(count, 1)

    def test_alerta_telegram_en_phishing(self):
        """Caso 13: Simula alerta por phishing"""
        phishing_data = {
            "user_email": "test@user.com",
            "subject": "Alerta urgente",
            "from": "phisher@mal.com",
            "spf_result": False,
            "dkim_result": False,
            "dmarc_result": False,
            "attachments": [],
            "message_id": "phish-id-001",
            "reasons": ["Phishing detectado"],
            "score": 15,
            "tiempo_analisis": 1.5,
            "estado": "Phishing"
        }

        db.save_email_to_db(phishing_data)

        cursor = self.conn.cursor()
        cursor.execute("SELECT score, estado FROM correos WHERE message_id = ?", ("phish-id-001",))
        fila = cursor.fetchone()
        self.assertEqual(fila[0], 15)
        self.assertEqual(fila[1], "Phishing")


    def test_lectura_oauth_y_historial(self):
        """Caso 14: Simula lectura automática vía OAuth"""

        with self.client.session_transaction() as sess:
            sess["oauth_token"] = {"access_token": "fake_token"}
            sess["email"] = "auto@oauth.com"

        db.save_email_to_db({
            "user_email": "auto@oauth.com",
            "subject": "Test OAuth",
            "from": "noreply@safe.com",
            "spf_result": True,
            "dkim_result": True,
            "dmarc_result": True,
            "attachments": [],
            "message_id": "oauth-id-002",
            "reasons": [],
            "score": 2,
            "tiempo_analisis": 1.2,
            "estado": score_a_estado(2, [])
        })

        response = self.client.get('/historial')
        self.assertEqual(response.status_code, 200)




    def test_metrica_dashboard(self):
        """Caso 15: Verifica que se actualicen las métricas del sistema"""
        for i in range(3):
            db.save_email_to_db({
                "user_email": "metrica@test.com",
                "subject": f"Correo {i}",
                "from": "user@test.com",
                "spf_result": True,
                "dkim_result": False,
                "dmarc_result": True,
                "attachments": [],
                "message_id": f"msg-{i}",
                "reasons": [],
                "score": i * 5,
                "tiempo_analisis": 1.0,
                "estado": score_a_estado(i * 5, [])
            })

        response = self.client.get("/metricas")
        self.assertEqual(response.status_code, 200)
        datos = json.loads(response.data.decode())
        self.assertIn("total", datos)
        self.assertGreaterEqual(datos["total"], 3)

if __name__ == '__main__':
    unittest.main()
