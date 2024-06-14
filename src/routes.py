from flask import jsonify, request, render_template
from flask_cors import cross_origin
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from werkzeug.security import check_password_hash, generate_password_hash
from .models import db, User, Rol, Permiso, Urbanizacion
from .helpers import get_db_connection, get_role_id
import os

def register_routes(app):
    # RUTA PRINCIPAL
    @app.route('/')
    def home():
        return render_template('index.html')

    # LOGIN
    @app.route('/login', methods=['POST'])
    @cross_origin()
    def login():
        if not request.is_json:
            return jsonify({'error': 'El cuerpo de la petición no es JSON válido'}), 400

        data = request.get_json()
        username = data.get('username')
        contrasena = data.get('password')

        if not username or not contrasena:
            return jsonify({'error': 'Faltan datos para el login'}), 400

        connection = get_db_connection()
        if connection is None:
            return jsonify({'error': 'No se pudo establecer conexión con la base de datos'}), 500

        cursor = connection.cursor(dictionary=True)
        try:
            
            query = """
            SELECT u.id_perfilUsuario AS user_id, u.contrasena AS password, u.id_rol, u.id_urbanizacion, 
                urb.cif, urb.nombre, urb.direccion, urb.cod_postal, urb.url_logo, r.nombre AS role
            FROM user u
            LEFT JOIN urbanizacion urb ON u.id_urbanizacion = urb.id_urbanizacion
            JOIN rol r ON u.id_rol = r.id_rol
            WHERE u.nombreUsuario = %s
            """
            cursor.execute(query, (username,))
            user = cursor.fetchone()

        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error de conexión con la base de datos: {e}'}), 500

        if user and check_password_hash(user['password'], contrasena):
            user_role = user['role']
            print(f"User Role: {user_role}")  # Depuración
            access_token = create_access_token(identity=user['user_id'], expires_delta=None)
            response_data = {
                "access_token": access_token,
                "user": {
                    "id": user['user_id'],
                    "rol": user['id_rol'],
                    "username": username,
                    "role": user['role']
                }
            }

            if user['role'] != 'superadmin':
                response_data["urbanizacion"] = {
                    "id": user['id_urbanizacion'],
                    "cif": user.get('cif'),
                    "nombre": user.get('nombre'),
                    "direccion": user.get('direccion'),
                    "cod_postal": user.get('cod_postal'),
                    "url_logo": user.get('url_logo')
                }

            cursor.close()
            connection.close()
            return jsonify(response_data), 200
        else:
            cursor.close()
            connection.close()
            return jsonify({"error": "Usuario no encontrado o contraseña incorrecta"}), 401
        
        
    # REGISTRO - Propietario y Empleado

    @app.route('/register', methods=['POST'])
    @jwt_required()
    @cross_origin()
    def register():
        current_user_id = get_jwt_identity()
        print(f"Current User ID: {current_user_id}")
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar que el usuario actual es administrador
        cursor.execute("""
            SELECT r.nombre AS role 
            FROM user u 
            JOIN rol r ON u.id_rol = r.id_rol 
            WHERE u.id_perfilUsuario = %s
        """, (current_user_id,))
        role_data = cursor.fetchone()
        print(f"Role Data: {role_data}")

        if not role_data or role_data['role'] != 'administrador':
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado. Solo los administradores pueden registrar nuevos usuarios.'}), 403

        # Obtener la urbanización del administrador
        cursor.execute("SELECT id_urbanizacion FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        urbanization_data = cursor.fetchone()
        print(f"Urbanization Data: {urbanization_data}")  # Depuración

        if not urbanization_data or not urbanization_data['id_urbanizacion']:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Urbanización no encontrada para el administrador'}), 404

        urbanization_id = urbanization_data['id_urbanizacion']
        print(f"Urbanization ID: {urbanization_id}")  # Depuración

        data = request.get_json()
        username = data.get('username')
        plain_password = data.get('contrasena')
        role = data.get('rol')
        nombre = data.get('nombre')
        apellidos = data.get('apellidos')
        telefono = data.get('telefono')
        email = data.get('email')

        role_id = get_role_id(role)
        print(f"Role ID: {role_id}")  # Depuración

        if not all([username, plain_password, role, nombre, apellidos, telefono, email]):
            cursor.close()
            connection.close()
            return jsonify({'error': 'Faltan datos para el registro'}), 400

        hashed_password = generate_password_hash(plain_password)
        print(f"Hashed Password: {hashed_password}")  # Depuración

        try:
            cursor.execute("""
                INSERT INTO user (nombreUsuario, contrasena, id_rol, id_urbanizacion, nombre, apellidos, telefono, email) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (username, hashed_password, role_id, urbanization_id, nombre, apellidos, telefono, email))
            connection.commit()
            print("User registered successfully")  # Depuración
        except Exception as e:
            print(f"Error al registrar el usuario: {e}")  # Depuración
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al registrar el usuario: {e}'}), 500

        cursor.close()
        connection.close()
        return jsonify({'success': True}), 201
    
    
    # REGISTRO - Admin

    @app.route('/register_admin', methods=['POST'])
    @jwt_required()
    @cross_origin()
    def register_admin():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404

        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        username = data.get('username')
        plain_password = data.get('contrasena')
        role = 'admin'
        nombre = data.get('nombre')
        apellidos = data.get('apellidos')
        telefono = data.get('telefono')
        email = data.get('email')
        id_urbanizacion = data.get('id_urbanizacion')

        role_id = get_role_id(role)

        if not all([username, plain_password, nombre, apellidos, telefono, email, id_urbanizacion]):
            cursor.close()
            connection.close()
            return jsonify({'error': 'Faltan datos para el registro'}), 400

        hashed_password = generate_password_hash(plain_password)

        try:
            cursor.execute("""
                INSERT INTO user (nombreUsuario, contrasena, id_rol, id_urbanizacion, nombre, apellidos, telefono, email) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (username, hashed_password, role_id, id_urbanizacion, nombre, apellidos, telefono, email))
            connection.commit()
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al registrar el administrador: {e}'}), 500

        cursor.close()
        connection.close()
        return jsonify({'success': True}), 201
    

    # REGISTRO - Superadmin

    @app.route('/register_superadmin', methods=['POST'])
    @jwt_required()
    @cross_origin()
    def register_superadmin():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404

        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        username = data.get('username')
        plain_password = data.get('contrasena')
        nombre = data.get('nombre')
        apellidos = data.get('apellidos')
        telefono = data.get('telefono')
        email = data.get('email')

        if not all([username, plain_password, nombre, apellidos, telefono, email]):
            cursor.close()
            connection.close()
            return jsonify({'error': 'Faltan datos para el registro'}), 400

        hashed_password = generate_password_hash(plain_password)

        try:
            cursor.execute("""
                INSERT INTO user (nombreUsuario, contrasena, id_rol, nombre, apellidos, telefono, email) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (username, hashed_password, superadmin_id, nombre, apellidos, telefono, email))
            connection.commit()
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al registrar el superadmin: {e}'}), 500

        cursor.close()
        connection.close()
        return jsonify({'success': True}), 201

    
    # PROPIETARIOS
    
    @app.route('/propietarios', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_propietarios():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Obtener la urbanización
        cursor.execute("SELECT id_urbanizacion FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        urbanizacion_id = cursor.fetchone().get('id_urbanizacion')
        if not urbanizacion_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Urbanización no encontrada para el administrador'}), 404
        
        # Obtener lista de propietarios de la urbanización
        cursor.execute("""
            SELECT u.id_perfilUsuario, u.nombreUsuario AS username, u.nombre, u.apellidos, u.telefono, u.email
            FROM user u
            WHERE u.id_urbanizacion = %s AND u.id_rol = (SELECT id_rol FROM rol WHERE nombre = 'propietario')
        """, (urbanizacion_id,))
        propietarios = cursor.fetchall()
        
        cursor.close()
        connection.close()
        return jsonify(propietarios), 200

    @app.route('/propietarios/<int:id>', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_propietario(id):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Obtener datos del propietario
        cursor.execute("""
            SELECT id_perfilUsuario, nombreUsuario AS username, nombre, apellidos, telefono, email
            FROM user
            WHERE id_perfilUsuario = %s AND id_rol = (SELECT id_rol FROM rol WHERE nombre = 'propietario')
        """, (id,))
        propietario = cursor.fetchone()
        
        cursor.close()
        connection.close()
        if not propietario:
            return jsonify({'error': 'Propietario no encontrado'}), 404
        
        return jsonify(propietario), 200

    @app.route('/propietarios/<int:id>', methods=['PUT'])
    @jwt_required()
    @cross_origin()
    def update_propietario(id):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Obtener los datos del propietario a editar
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

        query = "UPDATE user SET " + ", ".join(fields) + " WHERE id_perfilUsuario = %s AND id_rol = (SELECT id_rol FROM rol WHERE nombre = 'propietario')"
        updates.append(id)

        cursor.execute(query, tuple(updates))
        connection.commit()
        
        cursor.close()
        connection.close()
        return jsonify({'success': True}), 200

    @app.route('/propietarios/<int:id>', methods=['DELETE'])
    @jwt_required()
    @cross_origin()
    def delete_propietario(id):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Eliminar el propietario
        cursor.execute("DELETE FROM user WHERE id_perfilUsuario = %s", (id,))
        connection.commit()
        
        cursor.close()
        connection.close()
        return jsonify({'success': True}), 200

    # EMPLEADOS
    
    @app.route('/empleados', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_empleados():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Obtener la urbanización
        cursor.execute("SELECT id_urbanizacion FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        urbanizacion_data = cursor.fetchone()

        if not urbanizacion_data or not urbanizacion_data.get('id_urbanizacion'):
            cursor.close()
            connection.close()
            return jsonify({'error': 'Urbanización no encontrada para el administrador'}), 404

        urbanizacion_id = urbanizacion_data['id_urbanizacion']
        
        # Obtener lista de empleados de la urbanización
        cursor.execute("""
            SELECT u.id_perfilUsuario, u.nombreUsuario AS username, u.nombre, u.apellidos, u.telefono, u.email
            FROM user u
            WHERE u.id_urbanizacion = %s AND u.id_rol = (SELECT id_rol FROM rol WHERE nombre = 'empleado')
        """, (urbanizacion_id,))
        empleados = cursor.fetchall()
        
        cursor.close()
        connection.close()
        return jsonify(empleados), 200


    @app.route('/empleados/<int:id>', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_empleado(id):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Obtener datos del propietario
        cursor.execute("""
            SELECT id_perfilUsuario, nombreUsuario AS username, nombre, apellidos, telefono, email
            FROM user
            WHERE id_perfilUsuario = %s AND id_rol = (SELECT id_rol FROM rol WHERE nombre = 'empleado')
        """, (id,))
        propietario = cursor.fetchone()
        
        cursor.close()
        connection.close()
        if not propietario:
            return jsonify({'error': 'Empleado no encontrado'}), 404
        
        return jsonify(propietario), 200

    @app.route('/empleados/<int:id>', methods=['PUT'])
    @jwt_required()
    @cross_origin()
    def update_empleado(id):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

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

        query = "UPDATE user SET " + ", ".join(fields) + " WHERE id_perfilUsuario = %s AND id_rol = (SELECT id_rol FROM rol WHERE nombre = 'empleado')"
        updates.append(id)

        cursor.execute(query, tuple(updates))
        connection.commit()
        
        cursor.close()
        connection.close()
        return jsonify({'success': True}), 200

    @app.route('/empleados/<int:id>', methods=['DELETE'])
    @jwt_required()
    @cross_origin()
    def delete_empleado(id):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Eliminar el empleado
        cursor.execute("DELETE FROM user WHERE id_perfilUsuario = %s", (id,))
        connection.commit()
        
        cursor.close()
        connection.close()
        return jsonify({'success': True}), 200

    # ROLES

    @app.route('/roles/all', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_all_roles():
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT id_rol, nombre FROM rol")
        roles = cursor.fetchall()
        
        cursor.close()
        connection.close()
        return jsonify(roles), 200

    @app.route('/roles', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_roles():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Obtener la urbanización del administrador
        cursor.execute("SELECT id_urbanizacion FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        urbanizacion_id = cursor.fetchone().get('id_urbanizacion')
        if not urbanizacion_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Urbanización no encontrada para el administrador'}), 404
        
        # Obtener roles que existen en la urbanización
        cursor.execute("""
            SELECT r.id_rol, r.nombre
            FROM rol r
            JOIN user u ON u.id_rol = r.id_rol
            WHERE u.id_urbanizacion = %s
            GROUP BY r.id_rol, r.nombre
        """, (urbanizacion_id,))
        roles = cursor.fetchall()
        
        cursor.close()
        connection.close()
        return jsonify(roles), 200

    @app.route('/roles/<int:id>', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_rol(id):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            query = "SELECT id_rol, nombre FROM rol WHERE id_rol = %s"
            cursor.execute(query, (id,))
            rol = cursor.fetchone()
            
            if not rol:
                cursor.close()
                connection.close()
                return jsonify({'error': 'Rol no encontrado'}), 404

            cursor.close()
            connection.close()
            return jsonify(rol), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error de conexión con la base de datos'}), 500

    @app.route('/roles', methods=['POST'])
    @jwt_required()
    @cross_origin()
    def add_rol():
        current_user_id = get_jwt_identity()
        data = request.get_json()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        nombre = data.get('nombre')

        if not nombre:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Nombre es requerido'}), 400

        try:
            # Obtener la urbanización del administrador
            cursor.execute("SELECT id_urbanizacion FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
            result = cursor.fetchone()
            if result is None:
                cursor.close()
                connection.close()
                return jsonify({'error': 'Urbanización no encontrada para el administrador'}), 404
            
            urbanizacion_id = result.get('id_urbanizacion')

            # Añadir el nuevo rol
            insert_rol_query = """
                INSERT INTO rol (nombre) 
                VALUES (%s)
            """
            cursor.execute(insert_rol_query, (nombre,))
            connection.commit()

            cursor.close()
            connection.close()
            return jsonify({'success': 'Rol creado exitosamente', 'id_urbanizacion': urbanizacion_id}), 201
        except Exception as e:
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al crear el rol'}), 500

    @app.route('/roles/<int:id>', methods=['PUT'])
    @jwt_required()
    @cross_origin()
    def update_rol(id):
        current_user_id = get_jwt_identity()
        data = request.get_json()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        nombre = data.get('nombre')

        if not nombre:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Nombre es requerido'}), 400

        try:
            # Actualizar el rol
            update_rol_query = """
                UPDATE rol 
                SET nombre = %s
                WHERE id_rol = %s
            """
            cursor.execute(update_rol_query, (nombre, id))
            connection.commit()

            if cursor.rowcount == 0:
                cursor.close()
                connection.close()
                return jsonify({'error': 'Rol no encontrado'}), 404

            cursor.close()
            connection.close()
            return jsonify({'success': 'Rol actualizado exitosamente'}), 200
        except Exception as e:
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al actualizar el rol'}), 500

    @app.route('/roles/<int:rol_id>', methods=['DELETE'])
    @jwt_required()
    @cross_origin()
    def delete_rol(rol_id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            # Eliminar las asociaciones en la tabla rol_permiso
            delete_rol_permiso_query = """
                DELETE FROM rol_permiso 
                WHERE id_rol = %s
            """
            cursor.execute(delete_rol_permiso_query, (rol_id,))

            # Eliminar las asociaciones en la tabla users
            update_users_query = """
                UPDATE user 
                SET id_rol = NULL 
                WHERE id_rol = %s
            """
            cursor.execute(update_users_query, (rol_id,))

            # Eliminar el rol en la tabla rol
            delete_rol_query = """
                DELETE FROM rol 
                WHERE id_rol = %s
            """
            cursor.execute(delete_rol_query, (rol_id,))

            connection.commit()

            if cursor.rowcount == 0:
                cursor.close()
                connection.close()
                return jsonify({'error': 'Rol no encontrado'}), 404

            cursor.close()
            connection.close()
            return jsonify({'success': 'Rol eliminado exitosamente'}), 200
        except Exception as e:
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al eliminar el rol'}), 500


    # PERMISOS

    @app.route('/permisos', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_all_permisos():
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            query = "SELECT id_permiso, nombre, descripcion FROM permiso"
            cursor.execute(query)
            permisos = cursor.fetchall()

            cursor.close()
            connection.close()
            if not permisos:
                return jsonify({'error': 'No se encontraron permisos'}), 404

            return jsonify(permisos), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error de conexión con la base de datos'}), 500

    @app.route('/permisos/<int:id>', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_permiso(id):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            permiso_query = "SELECT id_permiso, nombre, descripcion FROM permiso WHERE id_permiso = %s"
            cursor.execute(permiso_query, (id,))
            permiso = cursor.fetchone()

            if not permiso:
                cursor.close()
                connection.close()
                return jsonify({'error': 'Permiso no encontrado'}), 404

            roles_query = """
                SELECT r.id_rol, r.nombre 
                FROM rol r
                JOIN rol_permiso rp ON r.id_rol = rp.id_rol
                WHERE rp.id_permiso = %s
            """
            cursor.execute(roles_query, (id,))
            roles = cursor.fetchall()

            permiso['roles'] = [role['id_rol'] for role in roles]

            cursor.close()
            connection.close()
            return jsonify(permiso), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error de conexión con la base de datos'}), 500

    @app.route('/permisos/<int:id>', methods=['PUT'])
    @jwt_required()
    @cross_origin()
    def update_permiso(id):
        current_user_id = get_jwt_identity()
        data = request.get_json()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        nombre = data.get('nombre')
        descripcion = data.get('descripcion')
        roles = data.get('roles')

        if not nombre and not descripcion and roles is None:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Al menos un campo debe ser proporcionado '}), 400

        updates = []
        params = []

        if nombre:
            updates.append("nombre = %s")
            params.append(nombre)
        if descripcion:
            updates.append("descripcion = %s")
            params.append(descripcion)

        params.append(id)
        query = f"UPDATE permiso SET {', '.join(updates)} WHERE id_permiso = %s"

        try:
            if updates:
                cursor.execute(query, tuple(params))

            # Actualizar roles asociados
            if roles is not None:
                delete_rol_permiso_query = "DELETE FROM rol_permiso WHERE id_permiso = %s"
                cursor.execute(delete_rol_permiso_query, (id,))

                insert_rol_permiso_query = "INSERT INTO rol_permiso (id_rol, id_permiso) VALUES (%s, %s)"
                for rol_id in roles:
                    cursor.execute(insert_rol_permiso_query, (rol_id, id))

            connection.commit()

            if cursor.rowcount == 0:
                cursor.close()
                connection.close()
                return jsonify({'error': 'Permiso no encontrado'}), 404

            cursor.close()
            connection.close()
            return jsonify({'success': 'Permiso actualizado exitosamente'}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error de conexión con la base de datos'}), 500

    @app.route('/roles/<int:id>/permisos', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_permisos_by_rol(id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            query = """
                SELECT p.id_permiso, p.nombre, p.descripcion, r.nombre as rol_nombre
                FROM permiso p
                JOIN rol_permiso rp ON p.id_permiso = rp.id_permiso
                JOIN rol r ON r.id_rol = rp.id_rol
                WHERE rp.id_rol = %s
            """
            cursor.execute(query, (id,))
            permisos = cursor.fetchall()

            if not permisos:
                cursor.close()
                connection.close()
                return jsonify({'error': 'No se encontraron permisos para el rol especificado'}), 404

            rol_nombre = permisos[0]['rol_nombre'] if permisos else None
            response = {
                'permisos': permisos,
                'rol_nombre': rol_nombre
            }

            cursor.close()
            connection.close()
            return jsonify(response), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error de conexión con la base de datos'}), 500

    @app.route('/permisos', methods=['POST'])
    @jwt_required()
    @cross_origin()
    def add_permiso():
        current_user_id = get_jwt_identity()
        data = request.get_json()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        nombre = data.get('nombre')
        descripcion = data.get('descripcion')
        roles = data.get('roles')

        if not nombre or not descripcion or not roles:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Nombre, Descripción y Roles son requeridos'}), 400

        try:
            # Obtener la urbanización
            cursor.execute("SELECT id_urbanizacion FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
            result = cursor.fetchone()
            if result is None:
                cursor.close()
                connection.close()
                return jsonify({'error': 'Urbanización no encontrada para el administrador'}), 404

            urbanizacion_id = result.get('id_urbanizacion')

            # Añadir nuevo permiso
            insert_permiso_query = """
                INSERT INTO permiso (nombre, descripcion) 
                VALUES (%s, %s)
            """
            cursor.execute(insert_permiso_query, (nombre, descripcion))
            permiso_id = cursor.lastrowid

            # Asociar el permiso con los roles
            insert_rol_permiso_query = """
                INSERT INTO rol_permiso (id_rol, id_permiso)
                VALUES (%s, %s)
            """
            for rol_id in roles:
                cursor.execute(insert_rol_permiso_query, (rol_id, permiso_id))

            connection.commit()

            cursor.close()
            connection.close()
            return jsonify({'success': 'Permiso creado exitosamente', 'id_urbanizacion': urbanizacion_id}), 201
        except Exception as e:
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al crear el permiso'}), 500

    @app.route('/permisos/<int:permiso_id>', methods=['DELETE'])
    @jwt_required()
    @cross_origin()
    def delete_permiso(permiso_id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            # Eliminar las asociaciones en la tabla rol_permiso
            delete_rol_permiso_query = """
                DELETE FROM rol_permiso 
                WHERE id_permiso = %s
            """
            cursor.execute(delete_rol_permiso_query, (permiso_id,))

            # Eliminar el permiso en la tabla permiso
            delete_permiso_query = """
                DELETE FROM permiso 
                WHERE id_permiso = %s
            """
            cursor.execute(delete_permiso_query, (permiso_id,))

            connection.commit()

            if cursor.rowcount == 0:
                cursor.close()
                connection.close()
                return jsonify({'error': 'Permiso no encontrado'}), 404

            cursor.close()
            connection.close()
            return jsonify({'success': 'Permiso eliminado exitosamente'}), 200
        except Exception as e:
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al eliminar el permiso'}), 500

    # URBANIZACION

    # Obtener Urbanizaciones

    @app.route('/urbanizaciones', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_urbanizaciones():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute("SELECT * FROM urbanizacion")
            urbanizaciones = cursor.fetchall()
            
            cursor.close()
            connection.close()
            return jsonify(urbanizaciones), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al obtener las urbanizaciones: {e}'}), 500

    # Obtener Urbanizacion por Id

    @app.route('/urbanizacion/<int:id>', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_urbanizacion(id):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            query = "SELECT * FROM urbanizacion WHERE id_urbanizacion = %s"
            cursor.execute(query, (id,))
            urbanizacion = cursor.fetchone()

            cursor.close()
            connection.close()
            if urbanizacion:
                return jsonify(urbanizacion), 200
            else:
                return jsonify({'error': 'Urbanización no encontrada'}), 404
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error de conexión con la base de datos'}), 500

    
    #Añadir Urbanizacion 

    @app.route('/register_urbanizacion', methods=['POST'])
    @jwt_required()
    @cross_origin()
    def add_urbanizacion():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        nombre_urbanizacion = request.form.get('nombre')
        cif = request.form.get('cif')
        direccion = request.form.get('direccion')
        cod_postal = request.form.get('cod_postal')
        id_ciudad = request.form.get('id_ciudad')
        logo = request.files.get('logo')

        if not all([nombre_urbanizacion, cif, direccion, cod_postal, id_ciudad]):
            cursor.close()
            connection.close()
            return jsonify({'error': 'Faltan datos'}), 400

        try:
            # Guardar el archivo de logo si existe
            logo_path = None
            if logo:
                logo_filename = secure_filename(logo.filename)
                logo_path = os.path.join(app.config['UPLOAD_FOLDER'], logo_filename)
                logo.save(logo_path)

            # Añadir urbanización
            cursor.execute("""
                INSERT INTO urbanizacion (nombre, cif, direccion, cod_postal, url_logo, id_ciudad) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (nombre_urbanizacion, cif, direccion, cod_postal, logo_path, id_ciudad))
            connection.commit()
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al registrar la urbanización: {e}'}), 500

        cursor.close()
        connection.close()
        return jsonify({'success': True}), 201

    def secure_filename(filename):
        return filename

    #Editar Urbanizacion
    
    @app.route('/urbanizacion/<int:id>', methods=['PUT'])
    @jwt_required()
    @cross_origin()
    def edit_urbanizacion(id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        #Obtener los datos del formulario
        nombre = request.form.get('nombre')
        cif = request.form.get('cif')
        direccion = request.form.get('direccion')
        cod_postal = request.form.get('cod_postal')
        id_ciudad = request.form.get('id_ciudad')
        logo = request.files.get('logo')

        updates = []
        params = []

        if nombre:
            updates.append("nombre = %s")
            params.append(nombre)
        if cif:
            updates.append("cif = %s")
            params.append(cif)
        if direccion:
            updates.append("direccion = %s")
            params.append(direccion)
        if cod_postal:
            updates.append("cod_postal = %s")
            params.append(cod_postal)
        if id_ciudad:
            updates.append("id_ciudad = %s")
            params.append(id_ciudad)
        if logo:
            logo_filename = secure_filename(logo.filename)
            logo_path = os.path.join(app.config['UPLOAD_FOLDER'], logo_filename)
            logo.save(logo_path)
            updates.append("url_logo = %s")
            params.append(logo_path)

        if not updates:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No se han proporcionado datos para actualizar'}), 400

        params.append(id)
        update_query = f"UPDATE urbanizacion SET {', '.join(updates)} WHERE id_urbanizacion = %s"

        try:
            cursor.execute(update_query, tuple(params))
            connection.commit()
            
            cursor.close()
            connection.close()
            if cursor.rowcount == 0:
                return jsonify({'error': 'Urbanización no encontrada'}), 404
            return jsonify({'success': 'Urbanización actualizada exitosamente'}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al actualizar la urbanización: {e}'}), 500
    
    #Eliminar Urbanizacion

    @app.route('/urbanizacion/<int:id>', methods=['DELETE'])
    @jwt_required()
    @cross_origin()
    def delete_urbanizacion(id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404

        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        try:
            # Eliminar la urbanización
            cursor.execute("DELETE FROM urbanizacion WHERE id_urbanizacion = %s", (id,))
            connection.commit()
            
            cursor.close()
            connection.close()
            if cursor.rowcount == 0:
                return jsonify({'error': 'Urbanización no encontrada'}), 404
            return jsonify({'success': 'Urbanización eliminada exitosamente'}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al eliminar la urbanización: {e}'}), 500

    # PAIS

    @app.route('/paises', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_paises():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        try:
            cursor.execute("""
                SELECT DISTINCT id_pais, nombre, capital
                FROM pais
            """)
            paises = cursor.fetchall()
            
            cursor.close()
            connection.close()
            return jsonify(paises), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al obtener los países: {e}'}), 500

    @app.route('/pais/<int:id>', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_pais(id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        try:
            cursor.execute("SELECT * FROM pais WHERE id_pais = %s", (id,))
            pais = cursor.fetchone()

            cursor.close()
            connection.close()
            if not pais:
                return jsonify({'error': 'País no encontrado'}), 404
            return jsonify(pais), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al obtener los detalles del país: {e}'}), 500

    @app.route('/paises', methods=['POST'])
    @jwt_required()
    @cross_origin()
    def add_pais():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        nombre = data.get('nombre')
        capital = data.get('capital')

        if not nombre or not capital:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Faltan datos'}), 400

        try:
            cursor.execute("""
                INSERT INTO pais (nombre, capital) 
                VALUES (%s, %s)
            """, (nombre, capital))
            connection.commit()
            
            cursor.close()
            connection.close()
            return jsonify({'success': 'País añadido'}), 201
        except Exception as e:
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al añadir el país: {e}'}), 500

    @app.route('/pais/<int:id>', methods=['PUT'])
    @jwt_required()
    @cross_origin()
    def edit_pais(id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        nombre = data.get('nombre')
        capital = data.get('capital')

        if not nombre and not capital:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Al menos un campo (nombre o capital) debe ser actualizado.'}), 400

        updates = []
        params = []

        if nombre:
            updates.append("nombre = %s")
            params.append(nombre)
        if capital:
            updates.append("capital = %s")
            params.append(capital)

        params.append(id)
        update_query = f"UPDATE pais SET {', '.join(updates)} WHERE id_pais = %s"

        try:
            cursor.execute(update_query, tuple(params))
            connection.commit()
            
            cursor.close()
            connection.close()
            if cursor.rowcount == 0:
                return jsonify({'error': 'País no encontrado'}), 404
            return jsonify({'success': True}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al actualizar los detalles del país: {e}'}), 500

    @app.route('/pais/<int:id>', methods=['DELETE'])
    @jwt_required()
    @cross_origin()
    def delete_pais(id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        try:
            # Verificar si existen ciudades asociadas al país
            cursor.execute("""
                SELECT COUNT(*) AS count 
                FROM ciudad c 
                JOIN urbanizacion u ON c.id_ciudad = u.id_ciudad 
                WHERE c.id_pais = %s
            """, (id,))
            count_data = cursor.fetchone()
            if count_data['count'] > 0:
                cursor.close()
                connection.close()
                return jsonify({'error': 'No se pueden eliminar países en los que existen ciudades con urbanizaciones'}), 400

            # Verificar si existen ciudades sin urbanizaciones
            cursor.execute("SELECT COUNT(*) AS count FROM ciudad WHERE id_pais = %s", (id,))
            count_data = cursor.fetchone()
            if count_data['count'] > 0:
                cursor.close()
                connection.close()
                return jsonify({'error': 'No se pueden eliminar países en los que existen ciudades'}), 400

            # Eliminar el país
            cursor.execute("DELETE FROM pais WHERE id_pais = %s", (id,))
            connection.commit()
            
            cursor.close()
            connection.close()
            if cursor.rowcount == 0:
                return jsonify({'error': 'País no encontrado'}), 404
            return jsonify({'success': 'País eliminado exitosamente'}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al eliminar el país: {e}'}), 500


    # CIUDAD

    #Obtener ciudad por id
    @app.route('/ciudad/<int:id>', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_ciudad(id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        try:
            cursor.execute("SELECT * FROM ciudad WHERE id_ciudad = %s", (id,))
            ciudad = cursor.fetchone()

            cursor.close()
            connection.close()
            if not ciudad:
                return jsonify({'error': 'Ciudad no encontrada'}), 404
            return jsonify(ciudad), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al obtener los datos de la ciudad: {e}'}), 500


    #Obtener ciudades
    @app.route('/ciudades', methods=['GET'])
    @jwt_required()
    @cross_origin()
    def get_ciudades():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
                
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        try:
            cursor.execute("""
                SELECT c.id_ciudad, c.nombre AS ciudad_nombre, p.nombre AS pais_nombre
                FROM ciudad c
                JOIN pais p ON c.id_pais = p.id_pais
            """)
            ciudades = cursor.fetchall()
            
            cursor.close()
            connection.close()
            return jsonify(ciudades), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al obtener las ciudades: {e}'}), 500

    #Añadir ciudades
    @app.route('/add_ciudad', methods=['POST'])
    @jwt_required()
    @cross_origin()
    def add_ciudad():
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
            
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        nombre = data.get('nombre')
        id_pais = data.get('id_pais')

        if not nombre or not id_pais:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Faltan datos'}), 400

        try:
            cursor.execute("""
                INSERT INTO ciudad (nombre, id_pais) 
                VALUES (%s, %s)
            """, (nombre, id_pais))
            connection.commit()
            
            cursor.close()
            connection.close()
            return jsonify({'success': 'Ciudad añadida exitosamente'}), 201
        except Exception as e:
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al añadir la ciudad: {e}'}), 500

    @app.route('/ciudad/<int:id>', methods=['PUT'])
    @jwt_required()
    @cross_origin()
    def edit_ciudad(id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        data = request.get_json()
        nombre = data.get('nombre')
        id_pais = data.get('id_pais')

        if not nombre and not id_pais:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Al menos un campo debe ser proporcionado'}), 400

        updates = []
        params = []

        if nombre:
            updates.append("nombre = %s")
            params.append(nombre)
        if id_pais:
            updates.append("id_pais = %s")
            params.append(id_pais)

        params.append(id)
        update_query = f"UPDATE ciudad SET {', '.join(updates)} WHERE id_ciudad = %s"

        try:
            cursor.execute(update_query, tuple(params))
            connection.commit()
            
            cursor.close()
            connection.close()
            if cursor.rowcount == 0:
                return jsonify({'error': 'Ciudad no encontrada'}), 404
            return jsonify({'success': True}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al actualizar los datos de la ciudad: {e}'}), 500


    @app.route('/ciudad/<int:id>', methods=['DELETE'])
    @jwt_required()
    @cross_origin()
    def delete_ciudad(id):
        current_user_id = get_jwt_identity()
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verificar si el usuario actual es superadmin
        cursor.execute("SELECT id_rol FROM user WHERE id_perfilUsuario = %s", (current_user_id,))
        role_data = cursor.fetchone()
        if not role_data:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Error al cargar role_data'}), 404
        
        superadmin_id = get_role_id('superadmin')
        if role_data['id_rol'] != superadmin_id:
            cursor.close()
            connection.close()
            return jsonify({'error': 'No autorizado'}), 403

        try:
            # Verificar si existen urbanizaciones asociadas a la ciudad
            cursor.execute("SELECT COUNT(*) AS count FROM urbanizacion WHERE id_ciudad = %s", (id,))
            count_data = cursor.fetchone()
            if count_data['count'] > 0:
                cursor.close()
                connection.close()
                return jsonify({'error': 'No se pueden eliminar ciudades en las que existen urbanizaciones.'}), 400
            
            # Eliminar la ciudad
            cursor.execute("DELETE FROM ciudad WHERE id_ciudad = %s", (id,))
            connection.commit()
            
            cursor.close()
            connection.close()
            if cursor.rowcount == 0:
                return jsonify({'error': 'Ciudad no encontrada'}), 404
            return jsonify({'success': 'Ciudad eliminada exitosamente'}), 200
        except Exception as e:
            cursor.close()
            connection.close()
            return jsonify({'error': f'Error al eliminar la ciudad: {e}'}), 500
