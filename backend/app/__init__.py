# Creates the Flask app (App Factory)
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import os
import logging
from .config import Config

# Initialize JWT manager
jwt = JWTManager()

# Application Factory Function
def create_app():
    # Disable Flask's default static handler so we can serve React build under /static
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)

    # Ensure folders exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['STEGO_TEMP_FOLDER'], exist_ok=True)

    # Extensions
    jwt.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Import and register the blueprint from routes.py
    from .routes import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    # Logging configuration (DEBUG level by default)
    if not app.logger.handlers:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s %(name)s - %(message)s')
    app.logger.setLevel(logging.DEBUG)
    app.logger.debug('Application created and configured')

    # Serve frontend build if available
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    build_dir = os.path.join(project_root, 'frontend', 'build')

    @app.route('/')
    @app.route('/<path:path>')
    def serve_frontend(path: str = None):
        # If requesting API, do nothing here (handled by blueprint)
        if path and path.startswith('api/'):
            app.logger.debug('Bypassing frontend route for API path')
            return jsonify({'message': 'Not Found'}), 404

        if os.path.isdir(build_dir):
            # Serve static files if they exist
            if path and os.path.exists(os.path.join(build_dir, path)):
                app.logger.debug(f'Serving static asset: {path}')
                return send_from_directory(build_dir, path)
            index_path = os.path.join(build_dir, 'index.html')
            if os.path.exists(index_path):
                app.logger.debug('Serving frontend index.html')
                return send_from_directory(build_dir, 'index.html')

        app.logger.debug('Frontend build not found; returning backend info JSON')
        return jsonify({
            'message': 'Backend running',
            'api_base': '/api',
            'health': '/api/health',
            'frontend_hint': 'Build UI not found. Run npm build in frontend.'
        }), 200

    return app