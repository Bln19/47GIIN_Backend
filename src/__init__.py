from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import os

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object("src.config.Config")

    CORS(app, supports_credentials=True)
    jwt = JWTManager(app)

    db.init_app(app)

    # Crea carpeta de subida de archivos si no existe
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])

    # Registra las rutas
    from .routes import register_routes
    
    register_routes(app)
    
    return app
