# error_handler.py
from flask import render_template

def init_error_handlers(app):
    @app.errorhandler(404)
    def not_found_error(error):
        return "<h1>Error 404</h1><p>Página no encontrada.</p>", 404

    @app.errorhandler(500)
    def internal_error(error):
        return "<h1>Error 500</h1><p>Error interno del servidor.</p>", 500