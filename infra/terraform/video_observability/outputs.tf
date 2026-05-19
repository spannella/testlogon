output "dashboard_name" {
  value       = aws_cloudwatch_dashboard.video_health.dashboard_name
  description = "CloudWatch dashboard name"
}

output "warning_topic_arn" {
  value       = aws_sns_topic.video_alerts_warning.arn
  description = "SNS topic for warning alerts"
}

output "critical_topic_arn" {
  value       = aws_sns_topic.video_alerts_critical.arn
  description = "SNS topic for critical alerts"
}

output "alarm_names" {
  value = [
    aws_cloudwatch_metric_alarm.channel_state_alarm.alarm_name,
    aws_cloudwatch_metric_alarm.input_loss_alarm.alarm_name,
    aws_cloudwatch_metric_alarm.output_error_alarm.alarm_name,
    aws_cloudwatch_metric_alarm.drm_key_error_alarm.alarm_name,
  ]
  description = "Configured CloudWatch alarm names"
}
