# Creates the Flask app (App Factory)
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import os
from .config import Config

# Initialize the database extension
db = SQLAlchemy()
jwt = JWTManager()

# Application Factory Function
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure folders exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['STEGO_TEMP_FOLDER'], exist_ok=True)

    # Extensions
    db.init_app(app)
    jwt.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Import and register the blueprint from routes.py
    from .routes import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    return app