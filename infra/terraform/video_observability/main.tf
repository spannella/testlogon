terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

locals {
  runbook_channel = "${var.runbook_base_url}/video/channel-health"
  runbook_drm     = "${var.runbook_base_url}/video/drm-key-health"
  runbook_playback = "${var.runbook_base_url}/video/playback-health"

  alarm_common_tags = merge(var.tags, {
    service = "video-platform"
    module  = "video_observability"
  })
}

resource "aws_sns_topic" "video_alerts_warning" {
  name = "${var.name_prefix}-video-alerts-warning"
  tags = local.alarm_common_tags
}

resource "aws_sns_topic" "video_alerts_critical" {
  name = "${var.name_prefix}-video-alerts-critical"
  tags = local.alarm_common_tags
}

resource "aws_sns_topic_subscription" "warning_email" {
  topic_arn = aws_sns_topic.video_alerts_warning.arn
  protocol  = "email"
  endpoint  = var.warning_email_endpoint
}

resource "aws_sns_topic_subscription" "critical_ops_email" {
  topic_arn = aws_sns_topic.video_alerts_critical.arn
  protocol  = "email"
  endpoint  = var.critical_email_endpoint
}

resource "aws_sns_topic_subscription" "critical_escalation_webhook" {
  topic_arn = aws_sns_topic.video_alerts_critical.arn
  protocol  = "https"
  endpoint  = var.escalation_webhook_endpoint
}

resource "aws_cloudwatch_dashboard" "video_health" {
  dashboard_name = "${var.name_prefix}-video-health"
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          title = "MediaLive Channel State Changes"
          view  = "timeSeries"
          stat  = "Sum"
          period = 60
          region = var.aws_region
          metrics = [
            ["AWS/MediaLive", "StateChange", "ChannelId", var.medialive_channel_id],
            ["AWS/MediaLive", "InputVideoFrameRate", "ChannelId", var.medialive_channel_id]
          ]
        }
      },
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          title = "Input Loss + Output Errors"
          view  = "timeSeries"
          stat  = "Sum"
          period = 60
          region = var.aws_region
          metrics = [
            ["AWS/MediaLive", "InputLoss", "ChannelId", var.medialive_channel_id],
            ["AWS/MediaLive", "OutputError", "ChannelId", var.medialive_channel_id]
          ]
        }
      },
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          title = "DRM Key and License Errors"
          view  = "timeSeries"
          stat  = "Sum"
          period = 60
          region = var.aws_region
          metrics = [
            [var.drm_metric_namespace, "KeyErrorCount", "Environment", var.environment],
            [var.drm_metric_namespace, "LicenseProvider5xxCount", "Environment", var.environment]
          ]
        }
      },
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          title = "Playback Health"
          view  = "timeSeries"
          stat  = "Average"
          period = 60
          region = var.aws_region
          metrics = [
            [var.playback_metric_namespace, "PlaybackStartSuccessRate", "Environment", var.environment],
            [var.playback_metric_namespace, "PlaybackEntitlementRejectRate", "Environment", var.environment]
          ]
        }
      }
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "channel_state_alarm" {
  alarm_name          = "${var.name_prefix}-channel-state-alarm"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "StateChange"
  namespace           = "AWS/MediaLive"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  dimensions = {
    ChannelId = var.medialive_channel_id
  }
  alarm_actions       = [aws_sns_topic.video_alerts_critical.arn]
  ok_actions          = [aws_sns_topic.video_alerts_warning.arn]
  alarm_description   = "MediaLive channel state anomaly. Runbook: ${local.runbook_channel} Escalation: ${var.escalation_policy_url}"
  treat_missing_data  = "breaching"
  tags                = local.alarm_common_tags
}

resource "aws_cloudwatch_metric_alarm" "input_loss_alarm" {
  alarm_name          = "${var.name_prefix}-input-loss-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "InputLoss"
  namespace           = "AWS/MediaLive"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  dimensions = {
    ChannelId = var.medialive_channel_id
  }
  alarm_actions      = [aws_sns_topic.video_alerts_critical.arn]
  alarm_description  = "Input loss detected. Runbook: ${local.runbook_channel} Escalation: ${var.escalation_policy_url}"
  treat_missing_data = "notBreaching"
  tags               = local.alarm_common_tags
}

resource "aws_cloudwatch_metric_alarm" "output_error_alarm" {
  alarm_name          = "${var.name_prefix}-output-error-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "OutputError"
  namespace           = "AWS/MediaLive"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  dimensions = {
    ChannelId = var.medialive_channel_id
  }
  alarm_actions      = [aws_sns_topic.video_alerts_critical.arn]
  alarm_description  = "Output error burst. Runbook: ${local.runbook_playback} Escalation: ${var.escalation_policy_url}"
  treat_missing_data = "notBreaching"
  tags               = local.alarm_common_tags
}

resource "aws_cloudwatch_metric_alarm" "drm_key_error_alarm" {
  alarm_name          = "${var.name_prefix}-drm-key-error-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "KeyErrorCount"
  namespace           = var.drm_metric_namespace
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  dimensions = {
    Environment = var.environment
  }
  alarm_actions      = [aws_sns_topic.video_alerts_critical.arn]
  alarm_description  = "DRM key/license errors detected. Runbook: ${local.runbook_drm} Escalation: ${var.escalation_policy_url}"
  treat_missing_data = "notBreaching"
  tags               = local.alarm_common_tags
}
