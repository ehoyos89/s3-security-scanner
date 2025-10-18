# S3 Security Scanner

## Descripción

**S3 Security Scanner** es una herramienta automatizada para escanear buckets de Amazon S3 en busca de vulnerabilidades de seguridad comunes. Está diseñada para ejecutarse como una función de AWS Lambda, permitiendo un monitoreo de seguridad continuo y sin servidor.

El scanner realiza las siguientes acciones:
1.  **Escanea todos los buckets de S3** en una cuenta de AWS.
2.  **Identifica vulnerabilidades** como acceso público, falta de cifrado, versionado deshabilitado, y más.
3.  **Genera reportes de seguridad** en formatos JSON, CSV y HTML.
4.  **Sube los reportes** a un bucket de S3 designado para su almacenamiento y análisis.
5.  **Envía notificaciones** a través de Amazon SNS si se encuentran vulnerabilidades de alta severidad.
6.  **Limpia automáticamente** los reportes antiguos para gestionar el almacenamiento.

## Arquitectura

El proyecto está diseñado para ser desplegado en AWS y utiliza los siguientes servicios:

*   **AWS Lambda**: Ejecuta el código del scanner de forma periódica o bajo demanda.
*   **Amazon S3**: Almacena los reportes de seguridad generados.
*   **Amazon SNS**: Envía notificaciones sobre vulnerabilidades críticas.
*   **AWS Systems Manager (Parameter Store)**: Almacena la configuración de la aplicación, como el nombre del bucket de reportes y el ARN del tema de SNS.
*   **Terraform**: Se utiliza para aprovisionar y gestionar la infraestructura en AWS.

## Vulnerabilidades Detectadas

El scanner busca las siguientes vulnerabilidades, clasificadas por nivel de severidad:

### Nivel ALTO
*   **public_read_acp**: El bucket tiene permisos de lectura públicos en su ACL.
*   **public_write_acp**: El bucket tiene permisos de escritura públicos en su ACL.
*   **public_read_policy**: La política del bucket permite lectura pública.
*   **public_write_policy**: La política del bucket permite escritura pública.
*   **no_encryption**: El bucket no tiene cifrado por defecto configurado.

### Nivel MEDIO
*   **versioning_disabled**: El versionado de objetos no está habilitado.
*   **no_access_logging**: El logging de acceso al bucket no está configurado.
*   **no_mfa_delete**: La opción "MFA Delete" no está habilitada.

### Nivel BAJO
*   **no_lifecycle_policy**: No hay una política de ciclo de vida configurada.
*   **no_cors_configuration**: La configuración de CORS no está definida.
*   **default_encryption_sse_s3**: Se utiliza cifrado SSE-S3 en lugar de SSE-KMS.

## Estructura del Proyecto

```
/
├── .gitignore
├── Dockerfile
├── LICENSE
├── requirements.txt
├── src/
│   ├── config.py             # Gestiona la configuración desde Parameter Store.
│   ├── lambda_handler.py     # Punto de entrada de la función Lambda.
│   ├── notifications.py      # Envía notificaciones a través de SNS.
│   ├── reporting.py          # Genera los reportes de seguridad.
│   ├── s3_scanner.py         # Lógica principal del escaneo de S3.
│   └── s3_uploader.py        # Sube los reportes a S3.
└── terraform/
    ├── main.tf               # Fichero principal de Terraform.
    ├── variables.tf          # Variables de Terraform.
    ├── outputs.tf            # Salidas de Terraform.
    └── modules/              # Módulos de Terraform para los recursos de AWS.
```

## Despliegue

Para desplegar el S3 Security Scanner, puedes utilizar Terraform para aprovisionar la infraestructura necesaria. Los módulos de Terraform en el directorio `terraform/modules` se encargan de crear la función Lambda, el bucket de S3 para los reportes, el tema de SNS y los parámetros en Parameter Store.

### Prerrequisitos

*   [Terraform](https://www.terraform.io/downloads.html) instalado.
*   Credenciales de AWS configuradas en tu entorno.

### Pasos

1.  Navega al directorio `terraform`.
2.  Inicializa Terraform: `terraform init`
3.  Revisa los planes de ejecución: `terraform plan`
4.  Aplica los cambios para desplegar la infraestructura: `terraform apply`

## Uso

Una vez desplegada, la función Lambda se puede ejecutar de las siguientes maneras:

*   **Manualmente**: A través de la consola de AWS Lambda.
*   **Programada**: Configurando un trigger de Amazon EventBridge (CloudWatch Events) para que se ejecute periódicamente (e.g., una vez al día).

Los reportes generados se encontrarán en el bucket de S3 especificado en la configuración, organizados por fecha y hora.
