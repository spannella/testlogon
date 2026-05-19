# video_observability Terraform module

CloudWatch dashboards and alarms for live channel, DRM key/license, and playback health.

## What this module provisions

- `aws_cloudwatch_dashboard.video_health`
- `aws_cloudwatch_metric_alarm` resources for:
  - channel state anomalies
  - input loss
  - output errors
  - DRM key/license errors
- SNS topics + subscriptions for warning and critical routing
- Alarm descriptions include **runbook links** and **escalation policy URL** for actionable on-call alerts.

## Inputs

- `name_prefix`, `environment`, `aws_region`, `medialive_channel_id`
- `warning_email_endpoint`, `critical_email_endpoint`, `escalation_webhook_endpoint`
- Optional: metric namespaces, runbook base URL, escalation policy URL, tags

## Alert routing model

- Warning route: email notifications via `video_alerts_warning`
- Critical route: email + escalation webhook via `video_alerts_critical`

This supports an escalation path where critical issues immediately page on-call while warnings remain informational.
