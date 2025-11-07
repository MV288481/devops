import boto3

s3=boto3.client('s3')

#s3.create_bucket(Bucket='pepepapatata-288481')

#s3.upload_file('/home/alumno/gol.txt', 'pepepapatata-288481', 'gol.txt')

s3.download_file('pepepapatata-288481', 'Git.pptx', '/home/alumno/Git.pptx')