"""IAM-related CIS controls."""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime, timezone

from scanner.checks.base import BaseCheck, register
from scanner.models import Finding, Severity

UNUSED_DAYS = 90
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def get_credential_report(iam) -> list[dict]:
    """Generate (if needed) and parse the IAM credential report."""
    for _ in range(10):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(1)
    content = iam.get_credential_report()["Content"]
    if isinstance(content, bytes):
        content = content.decode()
    return list(csv.DictReader(io.StringIO(content)))


def _parse_ts(value: str):
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@register
class RootMfa(BaseCheck):
    check_id = "IAM-001"
    title = "Root account has MFA enabled"
    cis_ref = "CIS 1.5"
    severity = Severity.CRITICAL
    remediation = (
        "Sign in as root, open Security credentials, and assign a hardware or "
        "virtual MFA device to the root user."
    )

    def run(self) -> list[Finding]:
        summary = self.client("iam").get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled") == 1:
            return [self.passed("root", "Root MFA is enabled.")]
        return [self.failed("root", "Root MFA is NOT enabled.")]


@register
class RootAccessKeys(BaseCheck):
    check_id = "IAM-002"
    title = "No access keys exist for the root account"
    cis_ref = "CIS 1.4"
    severity = Severity.CRITICAL
    remediation = "Sign in as root and delete all root access keys; use IAM roles instead."

    def run(self) -> list[Finding]:
        summary = self.client("iam").get_account_summary()["SummaryMap"]
        if summary.get("AccountAccessKeysPresent", 0) == 0:
            return [self.passed("root", "Root has no access keys.")]
        return [self.failed("root", "Root account has active access keys.")]


@register
class PasswordPolicy(BaseCheck):
    check_id = "IAM-003"
    title = "IAM password policy meets minimum strength"
    cis_ref = "CIS 1.8, 1.9"
    severity = Severity.MEDIUM
    remediation = (
        "aws iam update-account-password-policy --minimum-password-length 14 "
        "--password-reuse-prevention 24"
    )
    MIN_LENGTH = 14
    MIN_REUSE = 24

    def run(self) -> list[Finding]:
        iam = self.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            return [self.failed("account", "No account password policy is set.")]
        problems = []
        if policy.get("MinimumPasswordLength", 0) < self.MIN_LENGTH:
            problems.append(f"minimum length < {self.MIN_LENGTH}")
        if policy.get("PasswordReusePrevention", 0) < self.MIN_REUSE:
            problems.append(f"reuse prevention < {self.MIN_REUSE}")
        if problems:
            return [self.failed("account", "Password policy weak: " + ", ".join(problems))]
        return [self.passed("account", "Password policy meets length and reuse requirements.")]


@register
class UnusedCredentials(BaseCheck):
    check_id = "IAM-004"
    title = f"Credentials unused for {UNUSED_DAYS}+ days are disabled"
    cis_ref = "CIS 1.12"
    severity = Severity.MEDIUM
    remediation = (
        "Deactivate or delete passwords and access keys not used in 90 days: "
        "aws iam update-access-key --status Inactive"
    )

    def __init__(self, session, region="global", now: datetime | None = None):
        super().__init__(session, region)
        self.now = now or datetime.now(timezone.utc)

    def _stale(self, active: str, last_used: str, created: str) -> bool:
        if active != "true":
            return False
        ts = _parse_ts(last_used) or _parse_ts(created)
        return ts is not None and (self.now - ts).days > UNUSED_DAYS

    def run(self) -> list[Finding]:
        findings = []
        for row in get_credential_report(self.client("iam")):
            user = row["user"]
            if user == "<root_account>":
                continue
            stale = []
            if self._stale(row.get("password_enabled", "false"),
                           row.get("password_last_used", ""),
                           row.get("user_creation_time", "")):
                stale.append("password")
            for n in ("1", "2"):
                if self._stale(row.get(f"access_key_{n}_active", "false"),
                               row.get(f"access_key_{n}_last_used_date", ""),
                               row.get(f"access_key_{n}_last_rotated", "")):
                    stale.append(f"access_key_{n}")
            if stale:
                findings.append(self.failed(user, "Unused >90 days: " + ", ".join(stale)))
            else:
                findings.append(self.passed(user, "No stale credentials."))
        return findings


@register
class DirectAdminPolicy(BaseCheck):
    check_id = "IAM-005"
    title = "No IAM users have AdministratorAccess attached directly"
    cis_ref = "CIS 1.15, 1.16"
    severity = Severity.HIGH
    remediation = (
        "Detach admin policies from users; grant privileges through groups or "
        "assumable roles with least-privilege policies."
    )

    def run(self) -> list[Finding]:
        iam = self.client("iam")
        findings = []
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                name = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
                if any(p["PolicyArn"] == ADMIN_POLICY_ARN for p in attached):
                    findings.append(self.failed(name, "AdministratorAccess attached directly to user."))
                else:
                    findings.append(self.passed(name, "No admin policy attached directly."))
        if not findings:
            findings.append(self.passed("account", "No IAM users found."))
        return findings
