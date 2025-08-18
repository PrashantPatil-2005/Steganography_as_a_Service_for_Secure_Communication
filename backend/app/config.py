# Configuration settings
import os
from dotenv import load_dotenv

# This line loads the variables from your .env file
load_dotenv()

# This class holds all the configuration variables for your app
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False