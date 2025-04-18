import unittest
import sqlite3
import json
from modules import db

import tempfile
import os


class TestDBModule(unittest.TestCase):

    def setUp(self):
        # Crear archivo temporal de base de datos
        self.db_file = tempfile.NamedTemporaryFile(delete=False)
        db.DB_NAME = self.db_file.name
        db.init_db()

    def tearDown(self):
        try:
            os.unlink(self.db_file.name)
        except PermissionError:
            pass  # Windows a veces mantiene el archivo bloqueado


    def test_save_and_get_email(self):
        sample_data = {
            "user_email": "test@example.com",
            "subject": "Test Subject",
            "from": "phisher@mal.com",
            "spf_result": True,
            "dkim_result": False,
            "dmarc_result": True,
            "attachments": [{"filename": "malware.exe", "status": "suspicious"}],
            "message_id": "12345",
            "reasons": ["Phishing detectado"],
            "score": 12,
            "tiempo_analisis": 1.23
        }

        email_id = db.save_email_to_db(sample_data)
        self.assertIsNotNone(email_id)

        email = db.get_email_by_id(email_id)
        self.assertEqual(email["subject"], "Test Subject")
        self.assertEqual(email["score"], 12)

    def test_feedback_stats(self):
        # Añadir 2 correos con feedback manual
        db.init_db()
        cursor = sqlite3.connect(db.DB_NAME).cursor()
        cursor.execute("INSERT INTO correos (user_email, subject, sender, message_id, feedback_usuario) VALUES (?, ?, ?, ?, ?)",
                       ("user@test.com", "A", "a@test.com", "id1", "Correcto"))
        cursor.execute("INSERT INTO correos (user_email, subject, sender, message_id, feedback_usuario) VALUES (?, ?, ?, ?, ?)",
                       ("user@test.com", "B", "b@test.com", "id2", "Incorrecto"))
        cursor.connection.commit()

        stats = db.get_feedback_stats("user@test.com")
        self.assertEqual(stats["correctos"], 1)
        self.assertEqual(stats["incorrectos"], 1)

    def test_guardar_feedback(self):
        db.init_db()
        conn = sqlite3.connect(db.DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO correos (subject, message_id) VALUES (?, ?)", ("Feedback Test", "f1"))
        correo_id = cursor.lastrowid
        conn.commit()

        db.guardar_feedback(correo_id, True)
        correo = db.get_email_by_id(correo_id)
        self.assertEqual(correo["feedback_usuario"], "Correcto")

    def test_get_email_by_message_id(self):
        db.init_db()
        conn = sqlite3.connect(db.DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO correos (message_id, subject) VALUES (?, ?)", ("unique-id-xyz", "Test subject"))
        conn.commit()

        email = db.get_email_by_message_id("unique-id-xyz")
        self.assertIsNotNone(email)
        self.assertEqual(email["subject"], "Test subject")

    def test_save_test_result_and_get(self):
        db.save_test_result(True, "Phishing", "Phishing", None)
        results = db.get_test_results()
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0][1], 1)  # correcto = True

if __name__ == "__main__":
    unittest.main()
