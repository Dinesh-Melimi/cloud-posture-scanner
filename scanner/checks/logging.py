"""Logging and monitoring controls (CloudTrail, GuardDuty)."""

from __future__ import annotations

from scanner.checks.base import BaseCheck, register
from scanner.models import Finding, Severity


@register
class CloudTrailMultiRegion(BaseCheck):
    check_id = "LOG-001"
    title = "A multi-region CloudTrail trail is logging with log file validation"
    cis_ref = "CIS 3.1, 3.2"
    severity = Severity.HIGH
    remediation = (
        "aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> "
        "--is-multi-region-trail --enable-log-file-validation && "
        "aws cloudtrail start-logging --name org-trail"
    )

    def run(self) -> list[Finding]:
        ct = self.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        partial = []
        for t in trails:
            if not t.get("IsMultiRegionTrail"):
                continue
            logging = ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging", False)
            validation = t.get("LogFileValidationEnabled", False)
            if logging and validation:
                return [self.passed(t["Name"], "Multi-region trail logging with log file validation.")]
            partial.append(t["Name"])
        if partial:
            return [self.failed(", ".join(partial),
                                "Multi-region trail exists but is not logging or lacks validation.")]
        return [self.failed("account", "No multi-region CloudTrail trail found.")]


@register
class GuardDutyEnabled(BaseCheck):
    check_id = "LOG-002"
    title = "GuardDuty is enabled in the region"
    cis_ref = "AWS FSBP GuardDuty.1 (supplemental)"
    severity = Severity.MEDIUM
    regional = True
    remediation = "aws guardduty create-detector --enable --region <region>"

    def run(self) -> list[Finding]:
        gd = self.client("guardduty")
        for det_id in gd.list_detectors().get("DetectorIds", []):
            if gd.get_detector(DetectorId=det_id).get("Status") == "ENABLED":
                return [self.passed(det_id, "GuardDuty detector enabled.")]
        return [self.failed("guardduty", "No enabled GuardDuty detector in region.")]
