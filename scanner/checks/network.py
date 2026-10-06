"""EC2 / VPC / KMS controls."""

from __future__ import annotations

from scanner.checks.base import BaseCheck, register
from scanner.models import Finding, Severity

ADMIN_PORTS = (22, 3389)
OPEN_V4 = "0.0.0.0/0"
OPEN_V6 = "::/0"


def _rule_exposes(rule: dict, port: int) -> bool:
    proto = rule.get("IpProtocol")
    if proto not in ("tcp", "-1"):
        return False
    if proto != "-1":
        lo, hi = rule.get("FromPort", 0), rule.get("ToPort", 65535)
        if not lo <= port <= hi:
            return False
    v4 = any(r.get("CidrIp") == OPEN_V4 for r in rule.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") == OPEN_V6 for r in rule.get("Ipv6Ranges", []))
    return v4 or v6


@register
class OpenAdminPorts(BaseCheck):
    check_id = "NET-001"
    title = "No security groups allow 0.0.0.0/0 or ::/0 to SSH/RDP"
    cis_ref = "CIS 5.2, 5.3"
    severity = Severity.HIGH
    regional = True
    remediation = (
        "Remove the world-open ingress rule and restrict SSH/RDP to known CIDRs, "
        "or use SSM Session Manager instead of open admin ports."
    )

    def run(self) -> list[Finding]:
        ec2 = self.client("ec2")
        findings = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                exposed = sorted({p for r in sg.get("IpPermissions", [])
                                  for p in ADMIN_PORTS if _rule_exposes(r, p)})
                rid = f"{sg['GroupId']} ({sg.get('GroupName', '')})"
                if exposed:
                    findings.append(self.failed(rid, f"Ports open to the internet: {exposed}"))
                else:
                    findings.append(self.passed(rid, "No world-open SSH/RDP."))
        return findings


@register
class EbsDefaultEncryption(BaseCheck):
    check_id = "EC2-001"
    title = "EBS encryption by default is enabled"
    cis_ref = "CIS 2.2.1"
    severity = Severity.MEDIUM
    regional = True
    remediation = "aws ec2 enable-ebs-encryption-by-default --region <region>"

    def run(self) -> list[Finding]:
        enabled = self.client("ec2").get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
        if enabled:
            return [self.passed("ebs-default", "EBS encryption by default enabled.")]
        return [self.failed("ebs-default", "EBS encryption by default disabled.")]


@register
class KmsKeyRotation(BaseCheck):
    check_id = "KMS-001"
    title = "Customer-managed symmetric KMS keys have rotation enabled"
    cis_ref = "CIS 3.6"
    severity = Severity.MEDIUM
    regional = True
    remediation = "aws kms enable-key-rotation --key-id <key-id>"

    def run(self) -> list[Finding]:
        kms = self.client("kms")
        findings = []
        for page in kms.get_paginator("list_keys").paginate():
            for key in page["Keys"]:
                meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if (meta.get("KeyManager") != "CUSTOMER"
                        or meta.get("KeyState") != "Enabled"
                        or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT"):
                    continue
                on = kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]
                if on:
                    findings.append(self.passed(key["KeyId"], "Rotation enabled."))
                else:
                    findings.append(self.failed(key["KeyId"], "Rotation disabled."))
        if not findings:
            findings.append(self.passed("kms", "No customer-managed symmetric keys in region."))
        return findings
