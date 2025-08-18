# Creates the Flask app (App Factory)
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from .config import Config

# Initialize the database extension
db = SQLAlchemy()

# Application Factory Function
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Link the database to the app
    db.init_app(app)

    # Import and register the blueprint from routes.py
    from .routes import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    return app