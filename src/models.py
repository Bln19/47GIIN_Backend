from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Urbanizacion(db.Model):
    __tablename__ = 'urbanizacion'
    id_urbanizacion = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cif = db.Column(db.String(100))
    cod_postal = db.Column(db.Integer)
    direccion = db.Column(db.String(255))
    id_ciudad = db.Column(db.Integer, db.ForeignKey('ciudad.id_ciudad'))
    nombre = db.Column(db.String(100))
    url_logo = db.Column(db.String(255), nullable=True)

class Pais(db.Model):
    __tablename__ = 'pais'
    id_pais = db.Column(db.Integer, primary_key=True, autoincrement=True)
    capital = db.Column(db.String(100))
    nombre = db.Column(db.String(100))

class Ciudad(db.Model):
    __tablename__ = 'ciudad'
    id_ciudad = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_pais = db.Column(db.Integer, db.ForeignKey('pais.id_pais'))
    nombre = db.Column(db.String(100))

class Permiso(db.Model):
    __tablename__ = 'permiso'
    id_permiso = db.Column(db.Integer, primary_key=True, autoincrement=True)
    descripcion = db.Column(db.String(400))
    nombre = db.Column(db.String(200))

class Rol(db.Model):
    __tablename__ = 'rol'
    id_rol = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombre = db.Column(db.String(100))

class RolPermiso(db.Model):
    __tablename__ = 'rol_permiso'
    id_rol_permiso = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_permiso = db.Column(db.Integer, db.ForeignKey('permiso.id_permiso'))
    id_rol = db.Column(db.Integer, db.ForeignKey('rol.id_rol'))

class ServicioExterno(db.Model):
    __tablename__ = 'servicio_externo'
    id_servicioExterno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cif = db.Column(db.String(100))
    descripcion = db.Column(db.String(400))
    nombre = db.Column(db.String(100))
    telefono = db.Column(db.String(100))

class EspacioComun(db.Model):
    __tablename__ = 'espacio_comun'
    id_espacio = db.Column(db.Integer, primary_key=True, autoincrement=True)
    descripcion = db.Column(db.String(300))
    nombre = db.Column(db.String(100))

class UrbanizacionEspacio(db.Model):
    __tablename__ = 'urbanizacion_espacio'
    id_urbanizacion_espacio = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cantidad = db.Column(db.Integer)
    id_espacio = db.Column(db.Integer, db.ForeignKey('espacio_comun.id_espacio'))
    id_urbanizacion = db.Column(db.Integer, db.ForeignKey('urbanizacion.id_urbanizacion'))

class UrbanizacionServicio(db.Model):
    __tablename__ = 'urbanizacion_servicio'
    id_urbanizacion_servicio = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_servicioExterno = db.Column(db.Integer, db.ForeignKey('servicio_externo.id_servicioExterno'))
    id_urbanizacion = db.Column(db.Integer, db.ForeignKey('urbanizacion.id_urbanizacion'))

class User(db.Model):
    __tablename__ = 'user'
    id_perfilUsuario = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombre = db.Column(db.String(100))
    apellidos = db.Column(db.String(100))
    contrasena = db.Column(db.String(1000))
    email = db.Column(db.String(100))
    id_rol = db.Column(db.Integer, db.ForeignKey('rol.id_rol'))
    id_urbanizacion = db.Column(db.Integer, db.ForeignKey('urbanizacion.id_urbanizacion'), nullable=True) 
    nombreUsuario = db.Column(db.String(100))
    telefono = db.Column(db.String(100))