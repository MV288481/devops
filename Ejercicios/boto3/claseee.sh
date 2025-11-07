@ -0,0 +1,117 @@
Windows PowerShell
Copyright (C) Microsoft Corporation. Todos los derechos reservados.

Instale la versión más reciente de PowerShell para obtener nuevas características y mejoras. https://aka.ms/PSWindows

PS C:\WINDOWS\system32> wsl
Subsistema de Windows para Linux no tiene distribuciones instaladas.
Para resolverlo, instale una distribución con las instrucciones siguientes:

Use 'wsl.exe --list --online' para enumerar las distribuciones disponibles
y "wsl.exe --install <Distro>" para instalar.
PS C:\WINDOWS\system32> wsl.exe --install
Descargando: Ubuntu
Instalando: Ubuntu
Distribución instalada correctamente. Se puede iniciar a través de "wsl.exe -d Ubuntu"
Iniciando Ubuntu...
Provisioning the new WSL instance Ubuntu
This might take a while...
Create a default Unix user account: alumno
New password:
Retype new password:
passwd: password updated successfully
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

alumno@valevarietti:/mnt/c/WINDOWS/system32$ git --version
git version 2.43.0
alumno@valevarietti:/mnt/c/WINDOWS/system32$ git --version
git version 2.43.0
alumno@valevarietti:/mnt/c/WINDOWS/system32$ curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0Warning: Failed to open the file awscliv2.zip: Permission denied
  0 59.4M    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
curl: (23) Failure writing output to destination
alumno@valevarietti:/mnt/c/WINDOWS/system32$ aws --version
Command 'aws' not found, but can be installed with:
sudo snap install aws-cli
alumno@valevarietti:/mnt/c/WINDOWS/system32$ curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0Warning: Failed to open the file awscliv2.zip: Permission denied
  0 59.4M    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
curl: (23) Failure writing output to destination
alumno@valevarietti:/mnt/c/WINDOWS/system32$ unzip awscliv2.zip
Command 'unzip' not found, but can be installed with:
sudo apt install unzip
alumno@valevarietti:/mnt/c/WINDOWS/system32$ cd ~
alumno@valevarietti:~$ pwd
/home/alumno
alumno@valevarietti:~$ curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 59.4M  100 59.4M    0     0   714k      0  0:01:25  0:01:25 --:--:--  867k
alumno@valevarietti:~$ unzip awscliv2.zip
Command 'unzip' not found, but can be installed with:
sudo apt install unzip
alumno@valevarietti:~$ sudo apt install unzip
[sudo] password for alumno:
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Suggested packages:
  zip
The following NEW packages will be installed:
  unzip
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 174 kB of archives.
After this operation, 384 kB of additional disk space will be used.
Get:1 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 unzip amd64 6.0-28ubuntu4.1 [174 kB]
Fetched 174 kB in 2s (72.7 kB/s)
Selecting previously unselected package unzip.
(Reading database ... 40754 files and directories currently installed.)
Preparing to unpack .../unzip_6.0-28ubuntu4.1_amd64.deb ...
Unpacking unzip (6.0-28ubuntu4.1) ...
Setting up unzip (6.0-28ubuntu4.1) ...
Processing triggers for man-db (2.12.0-4build2) ...
alumno@valevarietti:~$ sudo ./aws/install
sudo: ./aws/install: command not found
alumno@valevarietti:~$ unzip awscliv2.zip
Archive:  awscliv2.zip
   creating: aws/
   creating: aws/dist/
  inflating: aws/dist/wheel-0.45.1.dist-info/INSTALLER
  inflating: aws/dist/wheel-0.45.1.dist-info/WHEEL
alumno@valevarietti:~$ sudo ./aws/install
You can now run: /usr/local/bin/aws --version
alumno@valevarietti:~$ ^C
alumno@valevarietti:~$ aws --version
aws-cli/2.31.31 Python/3.13.9 Linux/6.6.87.2-microsoft-standard-WSL2 exe/x86_64.ubuntu.24
alumno@valevarietti:~$ nano  ~/.aws/credentials
alumno@valevarietti:~$ sudo nano  ~/.aws/credentials
alumno@valevarietti:~$ dir
aws  awscliv2.zip
alumno@valevarietti:~$ cd aws
alumno@valevarietti:~/aws$ dir
README.md  THIRD_PARTY_LICENSES  dist  install
alumno@valevarietti:~/aws$ cd ..
alumno@valevarietti:~$ aws configure              #aqui se configuran las credenciales de acceso a AWS 
Default region name [None]: us-east-1
Default output format [None]: json
alumno@valevarietti:~$


############################    aws sts get-caller-identity ################################### esto chequea que la conexion esta bien

alumno@valevarietti:~$ 
alumno@valevarietti:~$ aws sts get-caller-identity
{
    "UserId": "AROASPF3BWEZQM5AH4KJA:user3135694=Mariana_Sol_Varietti_Cuturia",
    "Account": "170043486515",
    "Arn": "arn:aws:sts::170043486515:assumed-role/voclabs/user3135694=Mariana_Sol_Varietti_Cuturia"
}
alumno@valevarietti:~$
