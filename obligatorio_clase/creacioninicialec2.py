import boto3
from botocore.exceptions import ClientError

ec2 = boto3.client('ec2')

# 1. PRIMERO - Crear Security Group
sg_name = 'web-sg-rrhh'
sg_id = None

try:
    response = ec2.create_security_group(
        GroupName=sg_name,
        Description='Permitir trafico web desde cualquier IP'
    )
    sg_id = response['GroupId']
    print(f"✓ Security Group creado: {sg_id}")
    
    # Agregar regla HTTP
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    print(f"✓ Regla HTTP agregada")
    
except ClientError as e:
    error_code = e.response['Error']['Code']
    if error_code == 'InvalidGroup.Duplicate':
        sg_response = ec2.describe_security_groups(GroupNames=[sg_name])
        sg_id = sg_response['SecurityGroups'][0]['GroupId']
        print(f"ℹ Security Group ya existe: {sg_id}")
    else:
        raise

# 2. SEGUNDO - Crear instancia CON el Security Group
user_data = '''#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
echo "¡Sitio personalizado!" > /var/www/html/index.html
'''

image_id = 'ami-0fa3fe0fa7920f68e'

response = ec2.run_instances(
    ImageId=image_id,
    MinCount=1,
    MaxCount=1,
    InstanceType='t2.micro',
    IamInstanceProfile={'Name': 'LabInstanceProfile'},
    SecurityGroupIds=[sg_id],  # ← AGREGAR ESTA LÍNEA
    UserData=user_data
)

instance_id = response['Instances'][0]['InstanceId']
print(f"✓ Instancia creada: {instance_id}")

# Agregar tag
ec2.create_tags(
    Resources=[instance_id],
    Tags=[{'Key': 'Name', 'Value': 'webserver-rrhh'}]
)

instance_info = ec2.describe_instances(InstanceIds=[instance_id])
public_ip = instance_info['Reservations'][0]['Instances'][0].get('PublicIpAddress')

if public_ip:
    print(f"\n🌐 Accede a: http://{public_ip}")
    print(f"\n⏳ Espera 1-2 minutos para que Apache termine de instalarse")
else:
    print("⚠ No se pudo obtener IP pública")