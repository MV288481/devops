import time
import boto3
import requests

# Inicializar clientes
ec2 = boto3.client('ec2')
ssm = boto3.client('ssm')

instance_id = 'i-09aaf1ec6d19acdaa'

# Comando para instalar Apache y configurar página
command = '''#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
echo "¡Sitio personalizado desde SSM!" > /var/www/html/index.html
'''

# Enviar comando vía SSM
response = ssm.send_command(
    InstanceIds=[instance_id],
    DocumentName="AWS-RunShellScript",
    Parameters={"commands": [command]}
)

command_id = response['Command']['CommandId']
print(f"Comando enviado. ID: {command_id}")

# Esperar unos segundos para que se ejecute
time.sleep(30)

# Obtener IP pública
instance_info = ec2.describe_instances(InstanceIds=[instance_id])
public_ip = instance_info['Reservations'][0]['Instances'][0]['PublicIpAddress']
print(f"IP pública: {public_ip}")

# Probar respuesta HTTP
try:
    r = requests.get(f"http://{public_ip}", timeout=10)
    print("Código HTTP:", r.status_code)
    print("Contenido:", r.text)
except Exception as e:
    print("Error al conectar:", e)