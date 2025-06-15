import unittest
from app import app
from flask import session


class AppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test_secret'
        self.client = app.test_client()

    def test_index_redirects_without_login(self):
        """Debe redirigir al login si no hay sesión OAuth"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/gmail', response.location)

    def test_logout_clears_session_and_cookie(self):
        """Logout debe limpiar la sesión y redirigir al index"""
        with self.client.session_transaction() as sess:
            sess['email'] = 'test@correo.com'
        response = self.client.get('/logout', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/', response.location)

    def test_sync_estados_route(self):
        """La ruta de sincronización debe devolver confirmación"""
        response = self.client.get('/dev/sync_estados')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"actualizados", response.data)

    def test_guardar_feedback_post(self):
        """Simula un POST de feedback sin errores (id inventado para test)"""
        response = self.client.post('/feedback', data={
            'correo_id': '1',
            'correcto': 'true'
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'OK')

    def test_enviar_test_valid(self):
        """Comprueba puntuación completa en test"""
        response = self.client.post('/enviar_test', data={
            'respuesta_1': 'phishing',
            'respuesta_2': 'phishing',
            'respuesta_3': 'seguro'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Has acertado 3 de 3", response.data)


if __name__ == '__main__':
    unittest.main()
