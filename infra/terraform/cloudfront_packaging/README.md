# CloudFront Packaging Front Door (VWD-013)

This module places CloudFront in front of packaging origins (MediaPackage/local equivalent) with:

- HTTPS-only origin fetch
- viewer TLS (`TLSv1.2_2021`) with ACM cert
- cache policy split for manifests vs segments
- signed URL/cookie strategy hooks via trusted key groups
- origin access header (`X-Origin-Verify`) for origin-side access checks

## Usage

```hcl
module "cdn_packaging" {
  source              = "./infra/terraform/cloudfront_packaging"
  name_prefix         = "nonprod-video"
  origin_domain_name  = "abc123.mediapackage.us-east-1.amazonaws.com"
  origin_shared_secret = "replace-with-random-secret"
  acm_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/xxxx"
  key_group_ids       = ["abcd1234-key-group-id"]
}
```

## Origin access control guidance

- Validate `X-Origin-Verify` in origin auth layer (or Lambda@Edge/origin service) and reject direct origin requests without the expected header.
- Keep origin endpoints private to trusted paths when possible.

## Cache tuning guidance

- Manifest cache policy is low TTL to accommodate rapid updates and key rotations.
- Segment cache policy is higher TTL for better CDN hit ratio.
