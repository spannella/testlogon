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
  channel_id = "${var.name_prefix}-mp-channel"
}

resource "aws_iam_role" "speke_access" {
  name = "${var.name_prefix}-mediapackage-speke-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "mediapackage.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "speke_access" {
  name = "${var.name_prefix}-mediapackage-speke-policy"
  role = aws_iam_role.speke_access.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "execute-api:Invoke",
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudformation_stack" "mediapackage" {
  name = "${var.name_prefix}-mediapackage-stack"

  capabilities = ["CAPABILITY_NAMED_IAM"]

  template_body = templatefile("${path.module}/mediapackage_speke.yaml.tpl", {
    channel_id      = local.channel_id
    speke_url       = var.speke_url
    speke_role_arn  = aws_iam_role.speke_access.arn
    speke_system_ids = var.speke_system_ids
  })

  tags = var.tags
}
