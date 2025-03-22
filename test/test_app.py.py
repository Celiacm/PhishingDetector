from app import app

def test_index_route():
    tester = app.test_client()
    response = tester.get('/')
    assert response.status_code in [200, 302]  # Redirige si no logueado
