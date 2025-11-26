#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Despliegue seguro "desde cero" para la app RRHH (PHP + MySQL) en AWS:
- Crea primero Security Groups (web y DB) en la VPC default
- Crea bucket S3 seguro y sube archivos del profe (LOCAL_DIR -> s3://bucket/webapp/)
- Crea Secrets (DB y APP) con valores por defecto admin/admin123
- Crea RDS MySQL (no público, cifrado)
- Crea EC2 t2.micro con LabInstanceProfile y User Data que:
  * Instala Apache+PHP+MySQL client
  * Sincroniza S3 al webroot
  * Genera /var/www/.env con datos de DB y APP
  * Ejecuta init_db.sql (ajustado a DB_NAME/DB_USER/DB_PASS)
  * Configura CloudWatch Agent para logs básicos
- Crea CloudWatch Log Group y Alarms (CPU y status checks)
"""

import os
import json
import time
import boto3
from botocore.exceptions import ClientError

# ------------------- Parámetros del proyecto -------------------
PROJECT             = "rrhh-obligatorio"
REGION              = "us-east-1"            # fijo por el lab
VPC_ID              = None                   # None => VPC default
WEB_LOCAL_DIR       = "./Archivos_de_Pagina_Web"  # cambia si tu carpeta local es otra
S3_PREFIX           = "webapp/"
S3_BUCKET_NAME      = f"{PROJECT}-web-{int(time.time())}"  # único por timestamp

# RDS
DB_IDENTIFIER       = f"{PROJECT}-db"
DB_ENGINE           = "mysql"
DB_INSTANCE_CLASS   = "db.t3.micro"
DB_NAME             = "rrhh"
DB_USER_DEFAULT     = "admin"
DB_PASS_DEFAULT     = "admin123"  # por consigna del profe
BACKUP_RETENTION    = 7

# EC2
EC2_INSTANCE_TYPE   = "t2.micro"
INSTANCE_PROFILE    = "LabInstanceProfile"   # impuesto por el lab
EC2_KEY_NAME        = None                   # opcional si quieres SSH
EBS_VOLUME_SIZE_GB  = 8

# Secrets (guardamos valores por defecto en Secrets Manager)
DB_SECRET_NAME      = f"{PROJECT}/db/master"         # contiene {"username": "...", "password": "..."}
APP_SECRET_NAME     = f"{PROJECT}/app/credentials"   # contiene {"APP_USER": "admin", "APP_PASS": "admin123"}

# CloudWatch
LOG_GROUP_NAME      = f"/{PROJECT}/ec2"
LOG_RETENTION_DAYS  = 7

# ------------------- Clientes -------------------
ec2        = boto3.client("ec2", region_name=REGION)
rds        = boto3.client("rds", region_name=REGION)
s3         = boto3.client("s3", region_name=REGION)
iam        = boto3.client("iam", region_name=REGION)
secrets    = boto3.client("secretsmanager", region_name=REGION)
ssm        = boto3.client("ssm", region_name=REGION)
logs       = boto3.client("logs", region_name=REGION)
cloudwatch = boto3.client("cloudwatch", region_name=REGION)

# ------------------- Utilidades -------------------
def get_default_vpc_id():
    resp = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None

def latest_al2023_ami():
    # AL2023 x86_64
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]

def ensure_log_group():
    try:
        logs.create_log_group(logGroupName=LOG_GROUP_NAME)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise
    logs.put_retention_policy(logGroupName=LOG_GROUP_NAME, retentionInDays=LOG_RETENTION_DAYS)

def upload_folder_to_s3(local_dir, bucket, prefix):
    if not os.path.isdir(local_dir):
        raise RuntimeError(f"La carpeta local NO existe: {local_dir}")
    for root, _, files in os.walk(local_dir):
        for fname in files:
            fullpath = os.path.join(root, fname)
            key_rel = os.path.relpath(fullpath, local_dir).replace("\\", "/")
            s3_key = f"{prefix}{key_rel}"
            print(f"Subiendo: {fullpath} -> s3://{bucket}/{s3_key}")
            s3.upload_file(fullpath, bucket, s3_key)

# ------------------- Paso 1: Security Groups (primero) -------------------
def create_security_groups(vpc_id):
    print("[SG] Creando SGs en VPC:", vpc_id)
    # SG Web
    try:
        sg_web = ec2.create_security_group(
            GroupName=f"{PROJECT}-web-sg",
            Description="SG Web RRHH (HTTP/HTTPS)",
            VpcId=vpc_id
        )
        sg_web_id = sg_web["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_web_id,
            IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTP público"}]},
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS público"}]}
            ]
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.Duplicate":
            sg_web_id = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [f"{PROJECT}-web-sg"]},
                         {"Name": "vpc-id", "Values": [vpc_id]}]
            )["SecurityGroups"][0]["GroupId"]
        else:
            raise

    # SG DB: MySQL solo desde SG Web
    try:
        sg_db = ec2.create_security_group(
            GroupName=f"{PROJECT}-db-sg",
            Description="SG DB RRHH (MySQL solo desde SG Web)",
            VpcId=vpc_id
        )
        sg_db_id = sg_db["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_db_id,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                "UserIdGroupPairs": [{"GroupId": sg_web_id}]
            }]
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.Duplicate":
            sg_db_id = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [f"{PROJECT}-db-sg"]},
                         {"Name": "vpc-id", "Values": [vpc_id]}]
            )["SecurityGroups"][0]["GroupId"]
        else:
            raise

    print(f"✓ SGs creados: web={sg_web_id}, db={sg_db_id}")
    return sg_web_id, sg_db_id

# ------------------- Paso 2: S3 seguro -------------------
def create_secure_bucket(bucket_name):
    print(f"[S3] Creando bucket {bucket_name}...")
    try:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": REGION} if REGION != "us-east-1" else {}
        )
        print("✓ Bucket creado")
    except ClientError as e:
        if e.response["Error"]["Code"] == "BucketAlreadyOwnedByYou":
            print("ℹ Bucket ya existe")
        else:
            raise

    # Bloqueo de acceso público
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )
    # Cifrado por defecto SSE-S3
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    )
    # TLS-only policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "HttpsOnly",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}
        }]
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    print("✓ S3 endurecido (cifrado, bloqueo público, TLS-only)")
    return bucket_name

# ------------------- Paso 3: Secrets (DB y APP) -------------------
def upsert_secret(name, payload):
    try:
        resp = secrets.create_secret(Name=name, SecretString=json.dumps(payload))
        return resp["ARN"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceExistsException":
            secrets.put_secret_value(SecretId=name, SecretString=json.dumps(payload))
            desc = secrets.describe_secret(SecretId=name)
            return desc["ARN"]
        raise

def create_secrets():
    print("[Secrets] Creando/actualizando secretos...")
    db_arn  = upsert_secret(DB_SECRET_NAME, {"username": DB_USER_DEFAULT, "password": DB_PASS_DEFAULT})
    app_arn = upsert_secret(APP_SECRET_NAME, {"APP_USER": "admin", "APP_PASS": "admin123"})
    print(f"✓ Secrets OK: {DB_SECRET_NAME}, {APP_SECRET_NAME}")
    return db_arn, app_arn

# ------------------- Paso 4: RDS MySQL -------------------
def create_rds_instance(sg_db_id):
    print("[RDS] Creando instancia MySQL (no pública, cifrada)...")
    creds = json.loads(secrets.get_secret_value(SecretId=DB_SECRET_NAME)["SecretString"])
    params = {
        "DBInstanceIdentifier": DB_IDENTIFIER,
        "DBInstanceClass": DB_INSTANCE_CLASS,
        "Engine": DB_ENGINE,
        "MasterUsername": creds["username"],
        "MasterUserPassword": creds["password"],
        "DBName": DB_NAME,
        "AllocatedStorage": 20,
        "StorageType": "gp3",
        "StorageEncrypted": True,
        "VpcSecurityGroupIds": [sg_db_id],
        "BackupRetentionPeriod": BACKUP_RETENTION,
        "PubliclyAccessible": False,
        "AutoMinorVersionUpgrade": True,
        "DeletionProtection": False,
        "Tags": [
            {"Key": "Application", "Value": "RRHH"},
            {"Key": "DataClassification", "Value": "Confidential"}
        ]
    }
    try:
        rds.create_db_instance(**params)
        print("✓ RDS creada, esperando disponibilidad...")
        waiter = rds.get_waiter("db_instance_available")
        waiter.wait(DBInstanceIdentifier=DB_IDENTIFIER)
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBInstanceAlreadyExists":
            print("ℹ RDS ya existe, continuando")
        else:
            raise

    info = rds.describe_db_instances(DBInstanceIdentifier=DB_IDENTIFIER)
    endpoint = info["DBInstances"][0]["Endpoint"]["Address"]
    print(f"✓ RDS disponible en: {endpoint}:3306")
    return endpoint

# ------------------- Paso 5: EC2 + User Data -------------------
def launch_ec2(sg_web_id, db_endpoint, bucket):
    ami = latest_al2023_ami()
    print("[EC2] Lanzando instancia t2.micro (AL2023) con LabInstanceProfile...")

    # CloudWatch Agent config (logs básicos)
    cw_agent_json = r"""
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          { "file_path": "/var/log/messages", "log_group_name": "%s", "log_stream_name": "{instance_id}/messages", "timezone": "UTC" },
          { "file_path": "/var/log/httpd/access_log", "log_group_name": "%s", "log_stream_name": "{instance_id}/httpd_access", "timezone": "UTC" },
          { "file_path": "/var/log/httpd/error_log", "log_group_name": "%s", "log_stream_name": "{instance_id}/httpd_error", "timezone": "UTC" }
        ]
      }
    },
    "log_stream_name": "{instance_id}/default"
  }
}
""" % (LOG_GROUP_NAME, LOG_GROUP_NAME, LOG_GROUP_NAME)

    user_data = f"""#!/bin/bash
set -euxo pipefail

# Actualiza e instala paquetes (Apache + PHP + MySQL client + awscli + jq + CloudWatch Agent)
dnf clean all
dnf makecache
dnf -y update
dnf -y install httpd php php-cli php-fpm php-common php-mysqlnd mariadb105 awscli jq amazon-cloudwatch-agent

systemctl enable --now httpd
systemctl enable --now php-fpm

# Configurar Apache -> PHP-FPM (alineado al README del profe)  # ver config.php/.env fuera del webroot  [1](https://fi365-my.sharepoint.com/personal/mv288481_fi365_ort_edu_uy/Documents/Archivos%20de%20chat%20de%20Microsoft%C2%A0Copilot/config.php)
cat >/etc/httpd/conf.d/php-fpm.conf <<'CONF'
<FilesMatch \.php$>
  SetHandler "proxy:unix:/run/php-fpm/www.sock|fcgi://localhost/"
</FilesMatch>
CONF

# Sincronizar contenido web desde S3 al webroot
rm -rf /var/www/html/*
aws s3 sync s3://{bucket}/{S3_PREFIX} /var/www/html/

# Mover init_db.sql fuera del webroot si vino en el paquete del profe
if [ -f /var/www/html/init_db.sql ]; then
  cp /var/www/html/init_db.sql /var/www/init_db.sql
fi

# Obtener secretos (DB y APP) desde Secrets Manager (sin hardcode en AMI)
DB_JSON=$(aws secretsmanager get-secret-value --secret-id {DB_SECRET_NAME} --query SecretString --output text)
APP_JSON=$(aws secretsmanager get-secret-value --secret-id {APP_SECRET_NAME} --query SecretString --output text)

DB_USER=$(echo "$DB_JSON" | jq -r '.username')
DB_PASS=$(echo "$DB_JSON" | jq -r '.password')
APP_USER=$(echo "$APP_JSON" | jq -r '.APP_USER')
APP_PASS=$(echo "$APP_JSON" | jq -r '.APP_PASS')

# Crear .env fuera del webroot (como espera config.php)  [1](https://fi365-my.sharepoint.com/personal/mv288481_fi365_ort_edu_uy/Documents/Archivos%20de%20chat%20de%20Microsoft%C2%A0Copilot/config.php)
cat >/var/www/.env <<EOT
DB_HOST={db_endpoint}
DB_NAME={DB_NAME}
DB_USER=$DB_USER
DB_PASS=$DB_PASS
APP_USER=$APP_USER
APP_PASS=$APP_PASS
EOT
chown apache:apache /var/www/.env
chmod 600 /var/www/.env

# Ajustar y ejecutar init_db.sql del profe si existe (convierte demo_db/demo_user/demo_pass -> DB_NAME/DB_USER/DB_PASS)  [2](https://fi365-my.sharepoint.com/personal/mv288481_fi365_ort_edu_uy/Documents/Archivos%20de%20chat%20de%20Microsoft%C2%A0Copilot/init_db.sql)
if [ -f /var/www/init_db.sql ]; then
  cp /var/www/init_db.sql /var/www/init_db.sql.orig
  sed -e "s/demo_db/{DB_NAME}/g" -e "s/demo_user/$DB_USER/g" -e "s/demo_pass/$DB_PASS/g" /var/www/init_db.sql.orig > /var/www/init_db.sql.adj
  mysql -h {db_endpoint} -u "$DB_USER" -p"$DB_PASS" {DB_NAME} < /var/www/init_db.sql.adj || true
fi

# Permisos y reinicio servicios
chown -R apache:apache /var/www/html
chmod -R 755 /var/www/html
systemctl restart httpd php-fpm

# CloudWatch Agent: escribir config y arrancar
mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
cat >/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'JSON'
{cw_json}
JSON

# reemplazar {instance_id} en config con el ID real
IID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
sed -i "s/{{instance_id}}/$IID/g" /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
sed -i "s/{{instance_id}}/$IID/g" /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s || true

# Página de salud
echo "<?php echo 'RRHH OK'; ?>" > /var/www/html/health.php
""".replace("{cw_json}", cw_agent_json)

    run = ec2.run_instances(
        ImageId=ami,
        InstanceType=EC2_INSTANCE_TYPE,
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[sg_web_id],
        IamInstanceProfile={"Name": INSTANCE_PROFILE},
        KeyName=EC2_KEY_NAME,
        UserData=user_data,
        BlockDeviceMappings=[{
            "DeviceName": "/dev/xvda",
            "Ebs": {"VolumeSize": EBS_VOLUME_SIZE_GB, "VolumeType": "gp3", "Encrypted": True}
        }],
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [
                {"Key": "Name", "Value": "app-rrhh"},
                {"Key": "Application", "Value": "RRHH"},
                {"Key": "DataClassification", "Value": "Confidential"}
            ]
        }]
    )
    iid = run["Instances"][0]["InstanceId"]
    print(f"✓ EC2 lanzada: {iid}. Esperando status OK...")
    waiter = ec2.get_waiter("instance_status_ok")
    waiter.wait(InstanceIds=[iid])

    desc = ec2.describe_instances(InstanceIds=[iid])
    ip = desc["Reservations"][0]["Instances"][0]["PublicIpAddress"]
    print(f"✓ IP pública: {ip}")
    return iid, ip

# ------------------- Paso 6: Alarms CloudWatch -------------------
def create_alarms(instance_id):
    print("[CW] Creando alarmas básicas (CPU > 70% y StatusCheckFailed)...")
    cw_alarms = [
        {
            "AlarmName": f"{PROJECT}-cpu-high-{instance_id}",
            "MetricName": "CPUUtilization",
            "Namespace": "AWS/EC2",
            "Statistic": "Average",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 70.0,
            "ComparisonOperator": "GreaterThanThreshold",
            "Dimensions": [{"Name": "InstanceId", "Value": instance_id}]
        },
        {
            "AlarmName": f"{PROJECT}-status-check-{instance_id}",
            "MetricName": "StatusCheckFailed",
            "Namespace": "AWS/EC2",
            "Statistic": "Maximum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1.0,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Dimensions": [{"Name": "InstanceId", "Value": instance_id}]
        }
    ]
    for a in cw_alarms:
        cloudwatch.put_metric_alarm(
            AlarmName=a["AlarmName"],
            MetricName=a["MetricName"],
            Namespace=a["Namespace"],
            Statistic=a["Statistic"],
            Period=a["Period"],
            EvaluationPeriods=a["EvaluationPeriods"],
            Threshold=a["Threshold"],
            ComparisonOperator=a["ComparisonOperator"],
            ActionsEnabled=False,  # sin SNS por simplicidad
            Dimensions=a["Dimensions"]
        )
    print("✓ Alarmas creadas")

# ------------------- Main -------------------
def main():
    print("=== Despliegue RRHH seguro (inicio desde cero) ===")
    vpc_id = VPC_ID or get_default_vpc_id()
    if not vpc_id:
        raise RuntimeError("No se encontró VPC default. Configura VPC_ID.")

    # 1) SGs primero
    sg_web_id, sg_db_id = create_security_groups(vpc_id)

    # 2) S3 seguro
    bucket = create_secure_bucket(S3_BUCKET_NAME)

    # 3) Subir archivos del profe al bucket
    upload_folder_to_s3(WEB_LOCAL_DIR, bucket, S3_PREFIX)

    # 4) Secrets
    db_secret_arn, app_secret_arn = create_secrets()

    # 5) RDS
    db_endpoint = create_rds_instance(sg_db_id)

    # 6) CloudWatch Log Group
    ensure_log_group()

    # 7) EC2 y User Data
    iid, ip = launch_ec2(sg_web_id, db_endpoint, bucket)

    # 8) Alarmas CloudWatch
    create_alarms(iid)

    print("\n=== Resultado ===")
    print(f"- SG Web: {sg_web_id}")
    print(f"- SG DB: {sg_db_id}")
    print(f"- S3: s3://{bucket}/{S3_PREFIX}")
    print(f"- Secrets: {DB_SECRET_NAME} | {APP_SECRET_NAME}")
    print(f"- RDS Endpoint: {db_endpoint} (MySQL, no público)")
    print(f"- EC2: {iid} | Acceso: http://{ip}/login.php")
    print("Recuerda que config.php busca .env en /var/www/.env (fuera del webroot).")  # [1](https://fi365-my.sharepoint.com/personal/mv288481_fi365_ort_edu_uy/Documents/Archivos%20de%20chat%20de%20Microsoft%C2%A0Copilot/config.php)
    print("Si el init_db.sql del profe usa demo_db/demo_user/demo_pass, lo ajustamos automáticamente.")  # [2](https://fi365-my.sharepoint.com/personal/mv288481_fi365_ort_edu_uy/Documents/Archivos%20de%20chat%20de%20Microsoft%C2%A0Copilot/init_db.sql)

if __name__ == "__main__":
    main()
