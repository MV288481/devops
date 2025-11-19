import boto3

ec2 = boto3.client('ec2')

image_id = 'ami-0ecb62995f68bb549'  # Amazon Linux 2 AMI en us-east-1
response = ec2.run_instances(
    ImageId=image_id,
    MinCount=1,
    MaxCount=1,
    InstanceType='c7i-flex.large'
)
instance_id = response['Instances'][0]['InstanceId']
print(f"Instancia creada con ID: {instance_id}")