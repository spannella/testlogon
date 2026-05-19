output "medialive_role_arn" {
  value       = aws_iam_role.medialive.arn
  description = "IAM role ARN for MediaLive channel execution."
}

output "medialive_input_id" {
  value       = aws_medialive_input.this.id
  description = "MediaLive input id for channel attachment."
}

output "medialive_input_security_group_id" {
  value       = aws_medialive_input_security_group.this.id
  description = "MediaLive input security group id."
}
