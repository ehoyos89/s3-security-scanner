# ARN del tema de SNS.
output "sns_topic_arn" {
  value = aws_sns_topic.security_notifications.arn
}