## Cómo instalar WSL

1. Abre PowerShell como administrador y ejecuta el siguiente comando para habilitar WSL:
    ```sh
    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
    ```
2. Habilita la característica de máquina virtual:
    ```sh
    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
    ```

## Instalación de WSL y una distribución de Linux
1. Alternativamente, puedes instalar WSL y una distribución de Linux con un solo comando:
    ```sh
    wsl --install
    ```

2. Por defecto, al utilizar el comando:
    ```sh
    wsl --install
    ```
    Se instala Ubuntu como distribución predeterminada.

3. Una vez instalada, abre la distribución desde el menú de inicio y sigue las instrucciones de configuración.

4. Es probable que tengas que reiniciar el equipo para poder utilizar WSL 

## Cómo instalar Git

### En Windows

1. Descarga el instalador de Git desde el [sitio oficial](https://git-scm.com/download/win).

2. Ejecuta el instalador y sigue las instrucciones del asistente de instalación.

3. Una vez completada la instalación, abre una terminal y verifica la instalación con el siguiente comando:
    ```sh
    git --version
    ```

### En Linux

1. Abre una terminal.

2. Ejecuta el siguiente comando para instalar Git usando el gestor de paquetes de tu distribución (por ejemplo, `apt` para Debian/Ubuntu o `yum` para CentOS):
    ```sh
    sudo apt-get install git
    ```
    o
    ```sh
    sudo yum install git
    ```

3. Verifica la instalación con el siguiente comando:
    ```sh
    git --version
    ```

## Cómo instalar Visual Studio Code

1. Descarga el instalador de Visual Studio Code desde el [sitio oficial](https://code.visualstudio.com/Download).

2. Ejecuta el instalador y sigue las instrucciones del asistente de instalación.

3. Una vez completada la instalación, abre Visual Studio Code desde el menú de inicio.


## Ubicación y contenido de los ejercicios

En este repositorio encontrarás ejercicios prácticos para DevOps organizados en la carpeta `Ejercicios/`.

---

## Cómo instalar la CLI de AWS

### En Windows

1. Descarga el instalador de la CLI de AWS desde el [sitio oficial](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).

2. Ejecuta el instalador y sigue las instrucciones del asistente de instalación.

3. Una vez completada la instalación, abre una terminal y verifica la instalación con el siguiente comando:
    ```sh
    aws --version
    ```

### En Linux

1. Abre una terminal.

2. Descarga el paquete de instalación usando `curl`:
    ```sh
    curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip
    ```

3. Descomprime el paquete:
    ```sh
    unzip awscliv2.zip
    ```

4. Ejecuta el instalador:
    ```sh
    sudo ./aws/install
    ```

5. Verifica la instalación con el siguiente comando:
    ```sh
    aws --version
    ```
---
# Ejercicios

## Prerequisitos

- **Python**
- **Git**
- **Cuenta de github**
- **AWS CLI**
- **Acceso a AWS academy**

## Git
- **Enunciados:** En [Ejercicios](https://github.com/ORT-AII-ProgramacionDevOps/Labs/blob/main/Ejercicios/Git/Ejercicios.md) se encuentran ejercicios para practicar:
    - Configuración inicial de Git
    - Creación y manejo de repositorios y ramas
    - Subida de scripts y manejo de conflictos (locales y remotos)
- **Respuestas:** Las soluciones y comandos sugeridos están en [Respuestas](https://github.com/ORT-AII-ProgramacionDevOps/Labs/blob/main/Ejercicios/Git/Respuestas.md)

## Boto3
- **Enunciados:** En [Ejercicios](https://github.com/ORT-AII-ProgramacionDevOps/Labs/blob/main/Ejercicios/boto3/Ejercicios.md) se encuentran los enunciados de los ejercicios, que cubren:
    - Subida, descarga, listado y eliminación de archivos en S3
    - Creación y manejo de instancias EC2 (incluyendo UserData y SSM)
    - Creación y asociación de Security Groups
    - Creación de bases de datos MySQL en RDS usando variables de entorno para credenciales
- **Respuestas:** Los scripts de ejemplo para cada ejercicio están [Respuestas](https://github.com/ORT-AII-ProgramacionDevOps/Labs/tree/main/Ejercicios/boto3/Respuestas).


Estos ejercicios están pensados para practicar tanto el uso de AWS con Python (boto3) como el manejo de control de versiones con Git, y pueden ser ejecutados y adaptados según las necesidades del curso.

# Extras

Este directorio donde hay materiales extra que veremos a lo largo del curso Como CDK, CI/CD y mas

[Repo](https://github.com/ORT-AII-ProgramacionDevOps/extras)
