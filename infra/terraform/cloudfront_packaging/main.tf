terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

resource "aws_cloudfront_origin_access_control" "packaging" {
  name                              = "${var.name_prefix}-oac"
  description                       = "Origin access control for packaging origin."
  origin_access_control_origin_type = "mediastore"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_cache_policy" "manifest" {
  name        = "${var.name_prefix}-manifest-cache"
  comment     = "Low TTL for manifests so key rotations are reflected quickly."
  default_ttl = 2
  max_ttl     = 10
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["Origin"]
      }
    }
    query_strings_config {
      query_string_behavior = "all"
    }
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true
  }
}

resource "aws_cloudfront_cache_policy" "segment" {
  name        = "${var.name_prefix}-segment-cache"
  comment     = "Longer TTL for media segments."
  default_ttl = 60
  max_ttl     = 300
  min_ttl     = 1

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "all"
    }
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true
  }
}

resource "aws_cloudfront_response_headers_policy" "cors" {
  name = "${var.name_prefix}-cors"

  cors_config {
    access_control_allow_credentials = false
    access_control_allow_headers {
      items = ["*"]
    }
    access_control_allow_methods {
      items = ["GET", "HEAD", "OPTIONS"]
    }
    access_control_allow_origins {
      items = ["*"]
    }
    origin_override = true
  }

  custom_headers_config {
    items {
      header   = "Cache-Control"
      value    = "public, max-age=60"
      override = false
    }
  }
}

resource "aws_cloudfront_distribution" "packaging" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.name_prefix} packaging distribution"
  default_root_object = ""
  aliases             = var.aliases

  origin {
    domain_name              = var.origin_domain_name
    origin_id                = "packaging-origin"
    origin_path              = var.origin_path
    origin_access_control_id = aws_cloudfront_origin_access_control.packaging.id

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_keepalive_timeout = 5
      origin_read_timeout      = 30
    }

    custom_header {
      name  = "X-Origin-Verify"
      value = var.origin_shared_secret
    }
  }

  default_cache_behavior {
    target_origin_id       = "packaging-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    cache_policy_id            = aws_cloudfront_cache_policy.segment.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.cors.id
    trusted_key_groups         = var.key_group_ids
  }

  ordered_cache_behavior {
    path_pattern           = "*.m3u8"
    target_origin_id       = "packaging-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    cache_policy_id            = aws_cloudfront_cache_policy.manifest.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.cors.id
    trusted_key_groups         = var.key_group_ids
  }

  ordered_cache_behavior {
    path_pattern           = "*.mpd"
    target_origin_id       = "packaging-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    cache_policy_id            = aws_cloudfront_cache_policy.manifest.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.cors.id
    trusted_key_groups         = var.key_group_ids
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  price_class = "PriceClass_100"
  tags        = var.tags
}
