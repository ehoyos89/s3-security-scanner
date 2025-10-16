# Variable para la región de AWS.
# Descripción: La región de AWS en la que se desplegarán los recursos.
variable "aws_region" {
    description = "The AWS region to deploy resources in"
    type        = string
    default     = "us-east-1"
}

# Variable para el nombre del proyecto.
# Descripción: El nombre del proyecto.
variable "project_name" {
    description = "The name of the project"
    type        = string
    default     = "s3-security-scanner"
}

# Variable para el entorno.
# Descripción: El entorno para el despliegue (dev/prod).
variable "environment" {
  description = "The environment for the deployment (dev/prod)"
  type        = string

  validation {
    condition = contains(["dev", "prod"], var.environment)
    error_message = "Environment must be either 'dev' or 'prod'."
  }
  
}

# Variable para el email de notificación.
# Descripción: El email para recibir notificaciones de SNS.
variable "notification_email" {
  description = "The email for SNS notifications"
  type        = string
}

# Variable para la URI de la imagen de Lambda.
# Descripción: La URI de la imagen del contenedor de la función Lambda en ECR.
variable "lambda_image_uri" {
  description = "The URI of the Lambda function container image in ECR"
  type        = string
}