# Breach-response stack for a real AWS account.
#
# This deploys the *defensive* side of the lab: the detection and response
# wiring that catches the attack telemetry and contains it automatically. It
# does not create anything deliberately vulnerable.
#
# Flow in a live account:
#   GuardDuty finding  ->  EventBridge rule  ->  Lambda responder  ->  revoke /
#   quarantine / isolate / snapshot, using the same logic as breachlab/respond.py
#
# Apply this in a sandbox account you own. Review every resource first.
#
#   terraform init
#   terraform plan
#   terraform apply
#
# Nothing here is applied from the project's CI; it is yours to run deliberately.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region to deploy the responder into."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
  default     = "breachlab"
}

data "aws_caller_identity" "current" {}

# --- GuardDuty: the signal source -------------------------------------------

resource "aws_guardduty_detector" "this" {
  enable = true
}

# --- Execution role for the responder Lambda --------------------------------
#
# Scoped to exactly the containment actions in respond.py: deactivate access
# keys, attach a deny-all policy, move an instance to an isolation group, and
# snapshot volumes. No wildcard admin.

resource "aws_iam_role" "responder" {
  name = "${var.name_prefix}-responder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "responder" {
  name = "${var.name_prefix}-responder-policy"
  role = aws_iam_role.responder.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Containment"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:ListAccessKeys",
          "iam:PutUserPolicy",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:CreateSecurityGroup",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
        ]
        Resource = "*"
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      },
    ]
  })
}

# --- The responder Lambda ----------------------------------------------------
#
# The deployment package is built from the lambda/ directory, which imports
# breachlab.respond so the live responder and the local lab share one code path.

data "archive_file" "responder" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/build/responder.zip"
}

resource "aws_lambda_function" "responder" {
  function_name    = "${var.name_prefix}-responder"
  role             = aws_iam_role.responder.arn
  handler          = "handler.on_finding"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.responder.output_path
  source_code_hash = data.archive_file.responder.output_base64sha256
}

# --- EventBridge: GuardDuty finding -> Lambda --------------------------------

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.name_prefix}-guardduty-findings"
  description = "Route GuardDuty findings to the breach responder."
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.guardduty.name
  arn  = aws_lambda_function.responder.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}

output "responder_lambda" {
  value = aws_lambda_function.responder.function_name
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.this.id
}
