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
  channel_name = "${var.name_prefix}-medialive-channel"
  input_name   = "${var.name_prefix}-medialive-input"
}

resource "aws_iam_role" "medialive" {
  name = "${var.name_prefix}-medialive-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "medialive.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "medialive" {
  name = "${var.name_prefix}-medialive-policy"
  role = aws_iam_role.medialive.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "mediastore:PutObject",
          "mediastore:GetObject",
          "mediastore:DescribeObject",
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_medialive_input_security_group" "this" {
  whitelist_rules = [for cidr in var.input_cidr_allow_list : { cidr = cidr }]
  tags            = var.tags
}

resource "aws_medialive_input" "this" {
  name                  = local.input_name
  type                  = var.input_type
  input_security_groups = [aws_medialive_input_security_group.this.id]
  tags                  = var.tags
}

# Channel template is intentionally externalized to make ABR ladder/profile updates deterministic.
# See channel_template.json.tpl for canonical 1080p/720p/540p/360p outputs.
output "channel_template_rendered" {
  description = "Rendered MediaLive channel template JSON (for review/apply via pipeline tooling)."
  value = templatefile("${path.module}/channel_template.json.tpl", {
    channel_name    = local.channel_name
    destination_url = var.destination_url
    role_arn        = aws_iam_role.medialive.arn
    input_id        = aws_medialive_input.this.id
    channel_class   = var.channel_class
  })
}
