from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import database as db

# acceder a index.html para que pueda ser lanzado
template_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
template_dir = os.path.join(template_dir, 'src', 'templates')

# inicializar flask
app = Flask(__name__, template_folder=template_dir)
CORS(app, supports_credentials=True)

# Configuraciones de JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET_KEY', 'urba')  # Clave secreta para JWT
jwt = JWTManager(app)

# Rutas de la aplicación

# RUTA PRINCIPAL
@app.route('/')
def home():
    return render_template('index.html')

# REGISTRO - PROPITARIO y EMPLEADO -
@app.route('/register', methods=['POST'])
@jwt_required()
def register():
    current_user_id = get_jwt_identity()
    
    # Obtener la urbanización del administrador
    cursor = db.database.cursor(dictionary=True)
    cursor.execute("SELECT id_urbanizacion FROM users WHERE id_perfilUsuario = %s", (current_user_id,))
    urbanization_data = cursor.fetchone()
    
    if not urbanization_data:
        return jsonify({'error': 'Urbanización no encontrada para el administrador'}), 404

    urbanization_id = urbanization_data['id_urbanizacion']

    data = request.get_json()
    print("Datos recibidos:", data)

    username = data.get('username')
    plain_password = data.get('contrasena')
    role = data.get('rol')
    nombre = data.get('nombre')
    apellidos = data.get('apellidos')
    telefono = data.get('telefono')
    email = data.get('email')

    print(f"username: {username}")
    print(f"plain_password: {plain_password}")
    print(f"role: {role}")
    print(f"nombre: {nombre}")
    print(f"apellidos: {apellidos}")
    print(f"telefono: {telefono}")
    print(f"email: {email}")

    role_id = get_role_id(role)
    print("Rol ID:", role_id)

    if not all([username, plain_password, role, nombre, apellidos, telefono, email]):
        print("Faltan datos para el registro")
        return jsonify({'error': 'Faltan datos para el registro'}), 400

    hashed_password = generate_password_hash(plain_password)

    try:
        cursor = db.database.cursor()
        cursor.execute("""
            INSERT INTO users (nombreUsuario, contrasena, id_rol, id_urbanizacion, nombre, apellidos, telefono, email) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (username, hashed_password, role_id, urbanization_id, nombre, apellidos, telefono, email))
        db.database.commit()
        print(f"Usuario {username} registrado con éxito.")
    except Exception as e:
        print(f"Error al guardar en la base de datos: {e}")
        return jsonify({'error': 'Error al registrar el usuario'}), 500

    return jsonify({'success': True}), 201



# LOGIN
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'error': 'El cuerpo de la petición no es JSON válido'}), 400

    data = request.get_json()
    username = data.get('username')
    contrasena = data.get('password')

    if not username or not contrasena:
        return jsonify({'error': 'Faltan datos para el login'}), 400

    try:
        cursor = db.database.cursor(dictionary=True)
        query = """
        SELECT u.id_perfilUsuario AS user_id, u.contrasena AS password, u.id_rol, u.id_urbanizacion, 
            urb.cif, urb.nombre, urb.direccion, urb.cod_postal, urb.url_logo, r.nombre AS role
        FROM users u
        JOIN urbanizacion urb ON u.id_urbanizacion = urb.id_urbanizacion
        JOIN rol r ON u.id_rol = r.id_rol
        WHERE u.nombreUsuario = %s
        """
        cursor.execute(query, (username,))
        user = cursor.fetchone()

    except Exception as e:
        print(f"Error de base de datos: {e}")
        return jsonify({'error': 'Error de conexión con la base de datos'}), 500

    if user and check_password_hash(user['password'], contrasena):
        access_token = create_access_token(identity=user['user_id'])
        return jsonify({
            "access_token": access_token,
            "user": {
                "id": user['user_id'],
                "rol": user['id_rol'],
                "username": username,
                "role": user['role']
            },
            "urbanizacion": {
                "id": user['id_urbanizacion'],
                "cif": user['cif'],
                "nombre": user['nombre'],
                "direccion": user['direccion'],
                "cod_postal": user['cod_postal'],
                "url_logo": user['url_logo']
            }
        }), 200
    else:
        return jsonify({"error": "Usuario no encontrado o contraseña incorrecta"}), 401
    

#PROPIETARIOS

#Listar Propietarios
@app.route('/propietarios', methods=['GET'])
@jwt_required()
def get_propietarios():
    current_user_id = get_jwt_identity()
    cursor = db.database.cursor(dictionary=True)
    
    # Obtener la urbanización del administrador
    cursor.execute("SELECT id_urbanizacion FROM users WHERE id_perfilUsuario = %s", (current_user_id,))
    urbanizacion_id = cursor.fetchone().get('id_urbanizacion')
    if not urbanizacion_id:
        return jsonify({'error': 'Urbanización no encontrada para el administrador'}), 404
    
    # Obtener lista de propietarios de la urbanización
    cursor.execute("""
        SELECT u.id_perfilUsuario, u.nombreUsuario AS username, u.nombre, u.apellidos, u.telefono, u.email
        FROM users u
        WHERE u.id_urbanizacion = %s AND u.id_rol = (SELECT id_rol FROM rol WHERE nombre = 'propietario')
    """, (urbanizacion_id,))
    propietarios = cursor.fetchall()
    return jsonify(propietarios), 200

#Listar Propietario
@app.route('/propietarios/<int:id>', methods=['GET'])
@jwt_required()
def get_propietario(id):
    cursor = db.database.cursor(dictionary=True)
    
    # Obtener datos del propietario
    cursor.execute("""
        SELECT id_perfilUsuario, nombreUsuario AS username, nombre, apellidos, telefono, email
        FROM users
        WHERE id_perfilUsuario = %s AND id_rol = (SELECT id_rol FROM rol WHERE nombre = 'propietario')
    """, (id,))
    propietario = cursor.fetchone()
    
    if not propietario:
        return jsonify({'error': 'Propietario no encontrado'}), 404
    
    return jsonify(propietario), 200


#Editar Propietario
@app.route('/propietarios/<int:id>', methods=['PUT'])
@jwt_required()
def update_propietario(id):
    cursor = db.database.cursor(dictionary=True)

    # Obtener los datos del propietario a actualizar
    data = request.get_json()
    updates = []
    fields = []

    if 'nombre' in data:
        updates.append(data['nombre'])
        fields.append("nombre = %s")
    if 'apellidos' in data:
        updates.append(data['apellidos'])
        fields.append("apellidos = %s")
    if 'telefono' in data:
        updates.append(data['telefono'])
        fields.append("telefono = %s")
    if 'email' in data:
        updates.append(data['email'])
        fields.append("email = %s")

    query = "UPDATE users SET " + ", ".join(fields) + " WHERE id_perfilUsuario = %s AND id_rol = (SELECT id_rol FROM rol WHERE nombre = 'propietario')"
    updates.append(id)

    cursor.execute(query, tuple(updates))
    db.database.commit()
    return jsonify({'success': True}), 200

# Eliminar Propietario
@app.route('/propietarios/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_propietario(id):
    cursor = db.database.cursor(dictionary=True)
    # Eliminar el propietario
    cursor.execute("DELETE FROM users WHERE id_perfilUsuario = %s", (id,))
    db.database.commit()
    
    return jsonify({'success': True}), 200


#EMPLEADOS

#Listar Empleados
@app.route('/empleados', methods=['GET'])
@jwt_required()
def get_empleados():
    current_user_id = get_jwt_identity()
    cursor = db.database.cursor(dictionary=True)
    
    # Obtener la urbanización del administrador
    cursor.execute("SELECT id_urbanizacion FROM users WHERE id_perfilUsuario = %s", (current_user_id,))
    urbanizacion_id = cursor.fetchone().get('id_urbanizacion')
    if not urbanizacion_id:
        return jsonify({'error': 'Urbanización no encontrada para el administrador'}), 404
    
    # Obtener lista de empleados de la urbanización
    cursor.execute("""
        SELECT u.id_perfilUsuario, u.nombreUsuario AS username, u.nombre, u.apellidos, u.telefono, u.email
        FROM users u
        WHERE u.id_urbanizacion = %s AND u.id_rol = (SELECT id_rol FROM rol WHERE nombre = 'empleado')
    """, (urbanizacion_id,))
    empleados = cursor.fetchall()
    return jsonify(empleados), 200

#Listar Empleados
@app.route('/empleados/<int:id>', methods=['GET'])
@jwt_required()
def get_empleado(id):
    cursor = db.database.cursor(dictionary=True)
    
    # Obtener datos del propietario
    cursor.execute("""
        SELECT id_perfilUsuario, nombreUsuario AS username, nombre, apellidos, telefono, email
        FROM users
        WHERE id_perfilUsuario = %s AND id_rol = (SELECT id_rol FROM rol WHERE nombre = 'empleado')
    """, (id,))
    propietario = cursor.fetchone()
    
    if not propietario:
        return jsonify({'error': 'Empleado no encontrado'}), 404
    
    return jsonify(propietario), 200

#Editar Empleado
@app.route('/empleados/<int:id>', methods=['PUT'])
@jwt_required()
def update_empleado(id):
    cursor = db.database.cursor(dictionary=True)

    # Obtener los datos del empleado a actualizar
    data = request.get_json()
    updates = []
    fields = []

    if 'nombre' in data:
        updates.append(data['nombre'])
        fields.append("nombre = %s")
    if 'apellidos' in data:
        updates.append(data['apellidos'])
        fields.append("apellidos = %s")
    if 'telefono' in data:
        updates.append(data['telefono'])
        fields.append("telefono = %s")
    if 'email' in data:
        updates.append(data['email'])
        fields.append("email = %s")

    query = "UPDATE users SET " + ", ".join(fields) + " WHERE id_perfilUsuario = %s AND id_rol = (SELECT id_rol FROM rol WHERE nombre = 'empleado')"
    updates.append(id)

    cursor.execute(query, tuple(updates))
    db.database.commit()
    return jsonify({'success': True}), 200

# Eliminar Empleado
@app.route('/empleados/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_empleado(id):
    cursor = db.database.cursor(dictionary=True)
    # Eliminar el empleado
    cursor.execute("DELETE FROM users WHERE id_perfilUsuario = %s", (id,))
    db.database.commit()
    
    return jsonify({'success': True}), 200


# URBANIZACION
@app.route('/urbanizacion/<int:id>', methods=['GET'])
@jwt_required()
def get_urbanizacion(id):
    try:
        cursor = db.database.cursor(dictionary=True)
        query = "SELECT * FROM urbanizacion WHERE id_urbanizacion = %s"
        cursor.execute(query, (id,))
        urbanizacion = cursor.fetchone()
        if urbanizacion:
            return jsonify(urbanizacion), 200
        else:
            return jsonify({'error': 'Urbanización no encontrada'}), 404
    except Exception as e:
        print(f"Error de base de datos: {e}")
        return jsonify({'error': 'Error de conexión con la base de datos'}), 500


def get_role_id(role_name):
    cursor = db.database.cursor(dictionary=True)
    cursor.execute("SELECT id_rol FROM rol WHERE nombre = %s", (role_name,))
    role = cursor.fetchone()
    return role['id_rol'] if role else None

# Lanzar aplicación
if __name__ == '__main__':
    app.run(debug=True, port=4000)


