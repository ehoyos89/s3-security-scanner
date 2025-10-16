variable "aws_region" {
  description = "AWS Region"
  type        = string
}
variable "bucket_name" {
  description = "S3 Bucket Name"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS Topic ARN"
  type        = string
}