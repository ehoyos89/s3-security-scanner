resource "aws_ssm_parameter" "region" {
    name = "/s3-scanner/aws-region"
    description = "AWS Region for S3 Scanner"
    type = "SecureString"
    value = var.aws_region
}

resource "aws_ssm_parameter" "bucket_name" {
    name = "/s3-scanner/reports-bucket"
    description = "S3 Bucket Name for S3 Scanner"
    type = "SecureString"
    value = var.bucket_name
  
}

resource "aws_ssm_parameter" "sns_topic_arn" {
    name = "/s3-scanner/sns-topic-arn"
    description = "SNS Topic ARN for S3 Scanner notifications"
    type = "SecureString"
    value = var.sns_topic_arn
}