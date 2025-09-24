# Configuration settings
import os
from dotenv import load_dotenv

# This line loads the variables from your .env file
load_dotenv()

# This class holds all the configuration variables for your app
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join(os.getcwd(), 'uploads'))
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    ALLOWED_EXTENSIONS = {ext.strip().lower() for ext in os.environ.get('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,bmp').split(',')}
    STEGO_TEMP_FOLDER = os.environ.get('STEGO_TEMP_FOLDER', os.path.join(os.getcwd(), 'stego_tmp'))