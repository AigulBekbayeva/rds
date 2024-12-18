import os

class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:aigul@localhost/fire_incidents'
    #SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///local.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-default-fallback-secret-key'
    WTF_CSRF_ENABLED = False
    #UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads') 
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Ограничение на размер файла: 16MB

