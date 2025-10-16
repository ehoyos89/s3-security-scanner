resource "aws_sns_topic" "security_notifications" {
  name = "security-notifications"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.security_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}