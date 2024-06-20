import mysql.connector
from .models import Rol
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import io
# Función para obtener el ID del rol por nombre
def get_role_id(role_name):
    role = Rol.query.filter_by(nombre=role_name).first()
    return role.id_rol if role else None

# Crear una conexión a la base de datos MySQL
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host="172.20.0.3",
            user="root",
            password="1234",
            database="47urblapaz"
        )
        print("Conexión a la base de datos establecida")
        return connection
    except mysql.connector.Error as err:
        print(f"Error de conexión: {err}")
        return None

# Generar PDF urbanizacion Urbanizaciones
def generar_reporte_pdf(urbanizaciones):
    pdf_buffer = io.BytesIO()
    document = SimpleDocTemplate(pdf_buffer, pagesize=A4)

    elements = []

    data = [['ID', 'Nombre', 'CIF', 'Dirección', 'Código Postal', 'Ciudad', 'País']] + \
        [[urb['id_urbanizacion'], urb['nombre'], urb['cif'], urb['direccion'], urb['cod_postal'], urb['ciudad'], urb['pais']]
            for urb in urbanizaciones]

    table = Table(data)
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ])
    table.setStyle(style)

    elements.append(table)
    document.build(elements)

    pdf_buffer.seek(0)
    return pdf_buffer

# Generar PDF urbanizacion Propietarios
def generar_reporte_propietarios_pdf(nombre_urbanizacion, propietarios):
    pdf_buffer = io.BytesIO()
    document = SimpleDocTemplate(pdf_buffer, pagesize=A4)

    elements = []
    styles = getSampleStyleSheet()

    # Añadir el título del reporte
    title = Paragraph(f"Reporte de Propietarios - {nombre_urbanizacion}", styles['Title'])
    elements.append(title)

    data = [['ID', 'Nombre', 'Apellidos', 'Email', 'Teléfono']] + \
        [[prop['id_perfilUsuario'], prop['nombre'], prop['apellidos'], prop['email'], prop['telefono']]
            for prop in propietarios]

    table = Table(data)
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ])
    table.setStyle(style)

    elements.append(table)
    document.build(elements)

    pdf_buffer.seek(0)
    return pdf_buffer