variable "name_prefix" {
  type        = string
  description = "Prefix for CloudFront resource names."
}

variable "origin_domain_name" {
  type        = string
  description = "MediaPackage (or packaging origin) domain name without protocol."
}

variable "origin_path" {
  type        = string
  description = "Optional origin path (e.g. /out/v1)."
  default     = ""
}

variable "origin_shared_secret" {
  type        = string
  description = "Shared header secret passed by CloudFront to origin for access control checks."
}

variable "acm_certificate_arn" {
  type        = string
  description = "ACM certificate ARN (us-east-1) for CloudFront TLS."
}

variable "aliases" {
  type        = list(string)
  default     = []
}

variable "key_group_ids" {
  type        = list(string)
  description = "Optional trusted key groups for signed URL/cookie enforcement."
  default     = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
