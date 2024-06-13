import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'urba')
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:1234@172.20.0.3/47urblapaz'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'urba')
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
