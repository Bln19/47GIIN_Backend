import mysql.connector
from .models import Rol

# Función para obtener el ID del rol por nombre
def get_role_id(role_name):
    role = Rol.query.filter_by(nombre=role_name).first()
    return role.id_rol if role else None

# Crear una conexión a la base de datos MySQL
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host="172.20.0.3",
            user="root",
            password="1234",
            database="47urblapaz"
        )
        print("Conexión a la base de datos establecida")
        return connection
    except mysql.connector.Error as err:
        print(f"Error de conexión: {err}")
        return None
