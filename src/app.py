from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import check_password_hash
import os
import database as db

#acceder a index.html para que pueda ser lanzado
template_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
template_dir = os.path.join(template_dir, 'src', 'templates')

#inicializar flask
app = Flask(__name__, template_folder = template_dir)

# Configuración de la clave secreta para los mensajes flash
app.secret_key = 'tu_clave_secreta'

#Rutas de la aplicacion

#ruta principal
@app.route('/')
def home ():
    return render_template('index.html')



#LOGIN
@app.route('/login', methods=['POST'])
def login():
    username = request.form['nombreusuario']
    contrasena = request.form['contrasena']

    cursor = db.database.cursor()
    cursor.execute("SELECT contrasena FROM users WHERE nombreusuario = %s", (username,))
    user = cursor.fetchone()

    if user and check_password_hash(user[0], contrasena):
        return redirect(url_for('home'))  # Redirigir al inicio si es correcto
    else:
        flash('Usuario o contraseña incorrectos')
        return redirect(url_for('home')) #mantener en pagina
    


#Lanzar aplicacion
if __name__ == '__main__':
    app.run(debug=True, port=4000)