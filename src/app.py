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

# REGISTRO
@app.route('/register', methods=['POST'])
@jwt_required()
def register():


    data = request.get_json()
    username = data.get('username')
    plain_password = data.get('contrasena')
    role = data.get('rol')
    urbanization_id = data.get('urbanization_id')
    role_id = get_role_id(role)

    if not username or not plain_password or role is None:
        return jsonify({'error': 'Faltan datos para el registro'}), 400

    hashed_password = generate_password_hash(plain_password)
   

    try:
        cursor = db.database.cursor()
        cursor.execute("INSERT INTO users (nombreUsuario, contrasena, id_rol, id_urbanizacion) VALUES (%s, %s, %s, %s)",
                       (username, hashed_password, role_id, urbanization_id))
        db.database.commit()
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


