#conectar a la base de datos
import mysql.connector

#establecer datos de acceso a bd
database = mysql.connector.connect(
    host = 'localhost',
    user = 'root',
    database = '47urblapaz'
)