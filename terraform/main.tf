# Bloque de configuración de Terraform.
# Define la versión de Terraform requerida y los proveedores necesarios.

terraform {
    required_version = ">= 1.0.0"
    required_providers {
      aws = {
        source  = "hashicorp/aws"
        version = "~> 5.0"
      }
    }
}

# Configuración del proveedor de AWS.
# Define la región de AWS y las etiquetas por defecto para todos los recursos.

provider "aws" {
    region = var.aws_region

    default_tags {
      tags = {
        Environment = var.environment
        Project = var.project_name
        Owner   = "EHoyos"
      }
    }
  
}

# Módulo de S3 (Simple Storage Service).
# Crea un bucket de S3 para almacenar archivos.
module "s3" {
    source = "./modules/s3"
    environment = var.environment
    project_name = var.project_name
}

# Módulo de SNS (Simple Notification Service).
# Crea un tema de SNS para enviar notificaciones.
module "sns" {
    source = "./modules/sns"
    notification_email = var.notification_email
}

# Módulo de parametros de SSM (AWS Systems Manager).
# Crea parámetros en el SSM Parameter Store.
module "parameter_store" {
    source = "./modules/parameter_store"
    bucket_name = module.s3.s3_bucket_name
    aws_region = var.aws_region
    sns_topic_arn = module.sns.sns_topic_arn
} 

# Módulo de Lambda.
# Crea una función Lambda para escanear los buckets de S3 y enviar notificaciones.
module "lambda" {
    source = "./modules/lambda"
    bucket_name = module.s3.s3_bucket_name
    sns_topic_arn = module.sns.sns_topic_arn
    lambda_image_uri = var.lambda_image_uri
    environment = var.environment
}