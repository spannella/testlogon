output "speke_role_arn" {
  value       = aws_iam_role.speke_access.arn
  description = "IAM role used by MediaPackage to call SPEKE provider."
}

output "stack_id" {
  value       = aws_cloudformation_stack.mediapackage.id
  description = "CloudFormation stack id for MediaPackage resources."
}

output "hls_endpoint_url" {
  value       = lookup(aws_cloudformation_stack.mediapackage.outputs, "HlsEndpointUrl", "")
  description = "HLS encrypted endpoint URL."
}

output "dash_endpoint_url" {
  value       = lookup(aws_cloudformation_stack.mediapackage.outputs, "DashEndpointUrl", "")
  description = "DASH encrypted endpoint URL."
}
