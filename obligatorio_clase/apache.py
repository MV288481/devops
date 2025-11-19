import boto3

ec2 = boto3.client('ec2')

user_data = '''#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
echo "¡Sitio inicial personalizado!" > /var/www/html/index.html
'''

response = ec2.run_instances(
    ImageId= 'ami-0ecb62995f68bb549',
    MinCount=1,
    MaxCount=1,
    InstanceType='c7i-flex.large',
    IamInstanceProfile={'Name': 'LabInstanceProfile'},
    UserData=user_data
)

# Agregar tag Name: webserver-rrhh
instance_id = response['Instances'][0]['InstanceId']
ec2.create_tags(
    Resources=[instance_id],
    Tags=[{'Key': 'Name', 'Value': 'webserver-rrhh'}]
)
print(f"Instancia creada con ID: {instance_id} y tag 'webserver-rrhh'")