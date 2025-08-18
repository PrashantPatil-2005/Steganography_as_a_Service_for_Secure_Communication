# Initializes the Flask application and extensions
from flask import Flask

def create_app():
    app = Flask(__name__)

    @app.route('/health')
    def health_check():
        return "Server is running!", 200

    return app