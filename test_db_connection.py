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