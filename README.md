
# Proyecto Urb - La Paz

## Descripción

Este apartado describe cómo configurar el entorno virtual utilizando `venv`, instalando todas las dependencias necesarias en un entorno virtual.

## Prerrequisitos

- Python 3.10 o superior
- Pip (el gestor de paquetes de Python)
- MySQL

## Instalación

Sigue los siguientes pasos para configurar y ejecutar el proyecto en tu entorno local.

### 1. Crear un entorno virtual
Crea un entorno virtual llamado lapaz_env:

```sh
python (o python3)  -m venv lapaz_env
```
### 2. Activar el entorno virtual:

```sh
source lapaz_env/bin/activate
```

### 3. Instalar las dependencias necesarias mediante el archivo requirements.txt

```sh
pip install -r requirements.txt

```

# Configuración con Docker

Este proyecto utiliza Flask para el backend y MySQL como base de datos. Para facilitar la configuración, utilizamos Docker para manejar los contenedores de MySQL y phpMyAdmin.

## Requisitos

- Docker
- Docker Compose (opcional, pero recomendado)

## Contenedores Necesarios

1. **MySQL**
2. **phpMyAdmin**

## Configuración de Contenedores

### 1. MySQL

En primer lugar, es necesario crear una red en docker:

```bash
docker network create --subnet=172.20.0.0/16 lapaz_network
```

A continuación, se ejecuta el siguiente comando para crear y ejecutar un contenedor de MySQL en la red creada:

```bash
docker run --name mysql-container --network lapaz_network --ip 172.20.0.3 -e MYSQL_ROOT_PASSWORD=1234 -d mysql:latest
```

### 2. phpMyAdmin

Para crear un contedor con phpmyadmin accesible desde el puerto 8888 en localhost (http://localhost:8888), haremos lo siguiente:

```bash
docker run --name phpmyadmin-container --network lapaz_network -e PMA_HOST=172.20.0.3 -p 8888:80 -d phpmyadmin/phpmyadmin
```

#### 2.1. Acceso a phpMyAdmin

Mediante el navegador, hay que acceder a http://localhost:8888. Las credenciales para iniciar sesión en phpMyAdmin:

Servidor: db
Usuario: root
Contraseña: 1234



### 3. Test de la base de datos

Para testear la base de datos se ha creado el siguiente script:


```bash
import mysql.connector

try:
    connection = mysql.connector.connect(
        host="172.20.0.3",
        user="root",
        password="1234",
        database="47urblapaz"
    )
    print("Conexión exitosa a la base de datos 47urblapaz")
    connection.close()
except mysql.connector.Error as err:
    print(f"Error: {err}")
```

El script se ejecuta en la raiz del proyecto de backend con el siguiente comando:

```bash
python (o python3) test_db_connection.py
```


### 4. Crear la base de datos de la aplicación

La base de datos se creará automaticamente mediante el siguiente script ubicado en la carpeta raíz del backend:

```bash
python (o python3) create_db.py
```

NOTA: Es necesario asegurarse que en el archivo config.py está bien configurado el conector:


```bash
SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:1234@172.20.0.3/47urblapaz'
```

# Iniciar aplicación


## Backend

Acceder a la carpeta del backend e introducir el siguiente comando:

```bash
python (o python3) run.py
```


## Frontend

Acceder a la carpeta del backend e introducir el siguiente comando:

```bash
npm run serve
```


## Evitar problema CORS

Abrir terminal y ejecutar:

```bash
google-chrome --disable-web-security --user-data-dir=/tmp/chrome_dev
```