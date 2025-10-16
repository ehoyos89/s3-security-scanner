variable "bucket_name" {
    description = "The name of the S3 bucket to save the reports."
    type        = string
  
}

variable "sns_topic_arn" {
    description = "The ARN of the SNS topic to publish notifications."
    type        = string
  
}

variable "lambda_image_uri" {
    description = "The URI of the Lambda function container image in ECR."
    type        = string
}

variable "environment" {
    description = "The deployment environment (e.g., dev, prod)."
    type        = string
}