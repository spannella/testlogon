variable "name_prefix" {
  type        = string
  description = "Resource name prefix"
}

variable "environment" {
  type        = string
  description = "Environment dimension for custom metrics"
}

variable "aws_region" {
  type        = string
  description = "AWS region for CloudWatch dashboard widgets"
}

variable "medialive_channel_id" {
  type        = string
  description = "MediaLive channel ID"
}

variable "drm_metric_namespace" {
  type        = string
  description = "CloudWatch custom metric namespace for DRM health"
  default     = "Video/DRM"
}

variable "playback_metric_namespace" {
  type        = string
  description = "CloudWatch custom metric namespace for playback health"
  default     = "Video/Playback"
}

variable "runbook_base_url" {
  type        = string
  description = "Base URL for on-call runbooks"
  default     = "https://runbooks.example.com"
}

variable "escalation_policy_url" {
  type        = string
  description = "Escalation policy URL included in alarm descriptions"
  default     = "https://oncall.example.com/escalation/video"
}

variable "warning_email_endpoint" {
  type        = string
  description = "Email endpoint for warning notifications"
}

variable "critical_email_endpoint" {
  type        = string
  description = "Email endpoint for critical notifications"
}

variable "escalation_webhook_endpoint" {
  type        = string
  description = "Escalation webhook endpoint (PagerDuty/Opsgenie/etc.)"
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default     = {}
}
