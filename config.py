import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'your-secret-key-here'  # Change this to a secure secret key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'ewo.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False
    # Replace these with your local PC's IP and MySQL credentials
    DB_HOST = os.environ.get('DB_HOST', '192.168.1.100')  # Replace with your PC's IP
    DB_USER = os.environ.get('DB_USER', 'ewo_user')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'ewo_password')
    DB_NAME = os.environ.get('DB_NAME', 'ewo_db')
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
