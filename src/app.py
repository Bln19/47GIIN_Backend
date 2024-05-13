from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from flask_cors import CORS
from flask_session import Session  # Importa Session de flask_session
from werkzeug.security import check_password_hash, generate_password_hash
import os
import database as db

# acceder a index.html para que pueda ser lanzado
template_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
template_dir = os.path.join(template_dir, 'src', 'templates')

# inicializar flask
app = Flask(__name__, template_folder=template_dir)
# CORS(app, resources={r"/*": {"origins": "http://localhost:8080"}})
CORS(app)

# Configuraciones de la sesión
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)  # Inicializa la gestión de sesiones

app.secret_key = os.environ.get('SECRET_KEY', 'urba')


# Rutas de la aplicación

# ruta principal
@app.route('/')
def home():
    return render_template('index.html')

#REGISTRO

@app.route('/register', methods=['POST'])
def register():
    username = request.form['nombreusuario']
    plain_password = request.form['contrasena']
    role_id = request.form['id_rol']
    urbanization_id = request.form['id_urbanizacion']
    hashed_password = generate_password_hash(plain_password)
    
    try:
        cursor = db.database.cursor()
        cursor.execute("INSERT INTO users (nombreusuario, contrasena, id_rol, id_urbanizacion) VALUES (%s, %s, %s, %s)", (username, hashed_password, role_id, urbanization_id))
        db.database.commit()
    except Exception as e:
        print(f"Error al guardar en la base de datos: {e}")
        flash('Error al registrar el usuario')
        return redirect(url_for('register'))
    
    flash('Usuario registrado exitosamente')
    return redirect(url_for('home'))

# LOGIN
@app.route('/login', methods=['POST'])
def login():
    print (request.json)
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
        SELECT u.id_perfilUsuario, u.contrasena, u.id_rol, u.id_urbanizacion, 
               urb.cif, urb.nombre, urb.direccion, urb.cod_postal, urb.url_logo
        FROM users u
        JOIN urbanizacion urb ON u.id_urbanizacion = urb.id_urbanizacion
        WHERE u.nombreusuario = %s
        """
        cursor.execute(query, (username,))
        user = cursor.fetchone()
    except Exception as e:
        print(f"Error de base de datos: {e}")
        return jsonify({'error': 'Error de conexión con la base de datos'}), 500
    
    if user and check_password_hash(user['contrasena'], contrasena):
        session['user_id'] = user['id_perfilUsuario']
        session['role_id'] = user['id_rol']
        session['urbanizacion_id'] = user['id_urbanizacion']
        # Enviar datos de la urbanización al frontend
        return jsonify({
            "success": True,
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

# Lanzar aplicación
if __name__ == '__main__':
    app.run(debug=True, port=4000)
