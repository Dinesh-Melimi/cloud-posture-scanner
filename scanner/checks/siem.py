"""Security telemetry pipeline: are AWS security signals actually reaching the SIEM?

Turning on CloudTrail, GuardDuty and Security Hub is not enough; the SOC only sees what is
forwarded. These checks confirm each signal has a delivery path a SIEM can consume
(EventBridge rule with a target, CloudWatch Logs, or S3 event notifications to SQS/SNS,
which is how Splunk, Sentinel and most SIEM S3 connectors pull CloudTrail).
"""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from scanner.checks.base import BaseCheck, register
from scanner.models import Finding, Severity


def _forwarding_rules(events, source: str) -> list[str]:
    """Enabled EventBridge rules whose pattern matches `source` and that have at least one target."""
    names = []
    for rule in events.list_rules().get("Rules", []):
        if rule.get("State") != "ENABLED" or not rule.get("EventPattern"):
            continue
        sources = json.loads(rule["EventPattern"]).get("source", [])
        if source in sources and events.list_targets_by_rule(Rule=rule["Name"]).get("Targets"):
            names.append(rule["Name"])
    return names


@register
class SecurityHubEnabled(BaseCheck):
    check_id = "SIEM-001"
    title = "Security Hub is enabled to aggregate findings in the region"
    cis_ref = "AWS FSBP SecurityHub.1 (supplemental)"
    severity = Severity.MEDIUM
    regional = True
    remediation = "aws securityhub enable-security-hub --enable-default-standards --region <region>"

    def run(self) -> list[Finding]:
        try:
            hub = self.client("securityhub").describe_hub()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("InvalidAccessException", "ResourceNotFoundException"):
                return [self.failed("securityhub", "Security Hub is not enabled in this region.")]
            raise
        return [self.passed(hub["HubArn"], "Security Hub enabled.")]


@register
class FindingsForwardedToSiem(BaseCheck):
    check_id = "SIEM-002"
    title = "GuardDuty and Security Hub findings are forwarded by EventBridge to a SIEM target"
    cis_ref = "CIS v8 8.9, NIST CSF DE.CM-1 (supplemental)"
    severity = Severity.HIGH
    regional = True
    remediation = (
        "aws events put-rule --name findings-to-siem "
        "--event-pattern '{\"source\":[\"aws.guardduty\",\"aws.securityhub\"]}' && "
        "aws events put-targets --rule findings-to-siem --targets Id=siem,Arn=<firehose-or-sqs-or-lambda-arn>"
    )

    def run(self) -> list[Finding]:
        events = self.client("events")
        out = []
        for source, label in (("aws.guardduty", "GuardDuty"), ("aws.securityhub", "Security Hub")):
            rules = _forwarding_rules(events, source)
            if rules:
                out.append(self.passed(", ".join(rules), f"{label} findings forwarded by EventBridge."))
            else:
                msg = (f"No enabled EventBridge rule with a target forwards {label} findings; "
                       "the SOC will not see them in the SIEM.")
                out.append(self.failed(label, msg))
        return out


@register
class CloudTrailSiemDelivery(BaseCheck):
    check_id = "SIEM-003"
    title = "CloudTrail logs have a SIEM delivery path (CloudWatch Logs or S3 notifications)"
    cis_ref = "CIS 3.4 (CloudWatch Logs integration), NIST CSF DE.AE-3"
    severity = Severity.HIGH
    remediation = (
        "Send the trail to CloudWatch Logs (aws cloudtrail update-trail "
        "--cloud-watch-logs-log-group-arn ...), "
        "or add an S3 event notification on the trail bucket to an SQS queue the SIEM connector reads."
    )

    def run(self) -> list[Finding]:
        ct, s3 = self.client("cloudtrail"), self.client("s3")
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            return [self.failed("account", "No CloudTrail trail to deliver.")]
        out = []
        for t in trails:
            if t.get("CloudWatchLogsLogGroupArn"):
                out.append(self.passed(t["Name"], "Trail delivers to CloudWatch Logs."))
                continue
            bucket = t.get("S3BucketName")
            cfg = s3.get_bucket_notification_configuration(Bucket=bucket) if bucket else {}
            if cfg.get("QueueConfigurations") or cfg.get("TopicConfigurations"):
                out.append(self.passed(t["Name"], f"Trail bucket {bucket} notifies SQS/SNS for SIEM pull."))
            else:
                msg = (f"Trail writes to s3://{bucket} with no CloudWatch Logs or SQS/SNS notification; "
                       "no SIEM can pick it up automatically.")
                out.append(self.failed(t["Name"], msg))
        return out
