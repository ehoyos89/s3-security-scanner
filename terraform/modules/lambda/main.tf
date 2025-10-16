data "aws_iam_policy_document" "lambda_policy" {
  # Permisos de lectura generales de S3
  statement {
    effect = "Allow"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketVersioning",
      "s3:GetBucketLogging",
      "s3:GetLifecycleConfiguration",
      "s3:GetBucketCors"
    ]
    resources = ["*"]
  }

  # Permisos específicos del bucket
  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:ListBucket"
    ]
    resources = [
      "arn:aws:s3:::${var.bucket_name}",
      "arn:aws:s3:::${var.bucket_name}/*"
    ]
  }

  # Permisos de SNS
  statement {
    effect = "Allow"
    actions = [
      "sns:Publish"
    ]
    resources = [var.sns_topic_arn]
  }

  # Permisos de SSM Parameter Store
  statement {
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters"
    ]
    resources = [
      "arn:aws:ssm:*:*:parameter/s3-scanner/*"
    ]
  }
}

# Crear rol de ejecución para Lambda
resource "aws_iam_role" "lambda_role" {
  name = "${var.environment}-lambda-s3-scanner-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Crear política IAM para Lambda
resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.environment}-lambda-s3-scanner-policy"
  description = "IAM policy for Lambda function to scan S3 buckets and send notifications"
  policy      = data.aws_iam_policy_document.lambda_policy.json
}

# Adjuntar la política al rol de ejecución de Lambda
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# Adjuntar política administrada de AWS para logs básicos
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Crear función Lambda
resource "aws_lambda_function" "s3_scanner" {
  function_name = "${var.environment}-s3-security-scanner"
  role          = aws_iam_role.lambda_role.arn
  package_type = "Image"
  image_uri    = var.lambda_image_uri
  timeout      = 900  # 15 minutos
  memory_size  = 512  # Memoria en MB (ajustable según necesidades)
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.s3_scanner.function_name}"
  retention_in_days = 7
}
