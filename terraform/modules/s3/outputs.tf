# Salida para el nombre del bucket de S3.
# Descripción: El nombre del bucket de S3 para las fotos.
output "s3_bucket_name" {
  description = "The name of the S3 bucket for reports"
  value       = aws_s3_bucket.reports_bucket.bucket
}