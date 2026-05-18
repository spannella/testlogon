output "distribution_id" {
  value       = aws_cloudfront_distribution.packaging.id
  description = "CloudFront distribution id."
}

output "distribution_domain_name" {
  value       = aws_cloudfront_distribution.packaging.domain_name
  description = "CloudFront distribution domain name."
}

output "manifest_cache_policy_id" {
  value       = aws_cloudfront_cache_policy.manifest.id
  description = "Cache policy for manifests."
}

output "segment_cache_policy_id" {
  value       = aws_cloudfront_cache_policy.segment.id
  description = "Cache policy for segments."
}
