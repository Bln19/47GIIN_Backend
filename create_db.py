from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import mysql.connector
from src.models import db

app = Flask(__name__)

# Llamamos a config
app.config.from_object('src.config.Config')

# Crea la conexión para crear la base de datos
def create_database():
    connection = mysql.connector.connect(
        host="172.20.0.3",
        user="root",
        password="1234",
    )
    cursor = connection.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS 47urblapaz")
    cursor.close()
    connection.close()

# Llamamos a la función para crear la base de datos
create_database()

# Inicializar SQLAlchemy
db.init_app(app)

# Crea las tablas
with app.app_context():
    db.create_all()
    print("All tables created successfully!")
