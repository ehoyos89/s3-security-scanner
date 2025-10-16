# Recurso para el bucket de S3.
# Crea un bucket de S3 para almacenar los informes de seguridad.
resource "aws_s3_bucket" "reports_bucket" {
  bucket = "${var.project_name}-${var.environment}-reports"

  tags = {
    Name        = "${var.project_name}-${var.environment}-reports"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Bloquea el acceso público al bucket.
# Asegura que el contenido del bucket no sea accesible públicamente.
resource "aws_s3_bucket_public_access_block" "reports_bucket_public_access" {
  bucket = aws_s3_bucket.reports_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
}

