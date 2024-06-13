import mysql.connector
from werkzeug.security import generate_password_hash

def create_initial_superadmin():

    database = mysql.connector.connect(
        host="172.20.0.3",
        user='root',
        password="1234",
        database='47urblapaz'
    )

    cursor = database.cursor(dictionary=True)


    username = 'superAdmin'
    plain_password = '0123'
    nombre = 'Marcos'
    apellidos = 'Tur Barrera'
    telefono = '664589740'
    email = 'admin01@example.com'

    hashed_password = generate_password_hash(plain_password)
    print(f"contraseña {hashed_password} creado ")

    cursor.execute("SELECT id_rol FROM rol WHERE nombre = %s", ('superadmin',))
    role_data = cursor.fetchone()
    if not role_data:
        print("El rol 'superadmin' no existe. Debes crearlo primero en la tabla 'rol'.")
        return

    superadmin_id = role_data['id_rol']

    try:

        cursor.execute("""
            INSERT INTO user (nombreUsuario, contrasena, id_rol, nombre, apellidos, telefono, email) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (username, hashed_password, superadmin_id, nombre, apellidos, telefono, email))
        database.commit()
        print(f"Superadmin {username} creado con éxito.")
    except Exception as e:
        print(f"Error al crear el superadmin: {e}")
    finally:
        cursor.close()
        database.close()

if __name__ == "__main__":
    create_initial_superadmin()
