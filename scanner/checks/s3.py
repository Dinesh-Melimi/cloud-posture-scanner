"""S3-related CIS controls."""

from __future__ import annotations

from botocore.exceptions import ClientError

from scanner.checks.base import BaseCheck, register
from scanner.models import Finding, Severity

BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


@register
class S3PublicAccessBlock(BaseCheck):
    check_id = "S3-001"
    title = "S3 Block Public Access enabled on buckets"
    cis_ref = "CIS 2.1.4"
    severity = Severity.HIGH
    remediation = (
        "aws s3api put-public-access-block --bucket <name> --public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    )

    def run(self) -> list[Finding]:
        s3 = self.client("s3")
        findings = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                ok = all(cfg.get(k) for k in BPA_KEYS)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                    raise
                ok = False
            if ok:
                findings.append(self.passed(name, "All four public access block settings enabled."))
            else:
                findings.append(self.failed(name, "Public access block missing or incomplete."))
        if not findings:
            findings.append(self.passed("account", "No S3 buckets found."))
        return findings


@register
class S3DefaultEncryption(BaseCheck):
    check_id = "S3-002"
    title = "S3 buckets have default encryption configured"
    cis_ref = "CIS 2.1.1 (v1.4)"
    severity = Severity.MEDIUM
    remediation = (
        "aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration "
        "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'"
    )

    def run(self) -> list[Finding]:
        s3 = self.client("s3")
        findings = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                rules = s3.get_bucket_encryption(Bucket=name)[
                    "ServerSideEncryptionConfiguration"]["Rules"]
                algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                findings.append(self.passed(name, f"Default encryption: {algo}."))
            except ClientError as e:
                if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                    raise
                findings.append(self.failed(name, "No default encryption configured."))
        if not findings:
            findings.append(self.passed("account", "No S3 buckets found."))
        return findings
