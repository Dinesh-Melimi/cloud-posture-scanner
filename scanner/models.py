"""Core data types shared by checks, the engine, and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Status(str, Enum):
    PASS = "PASS"  # noqa: S105  # nosec B105
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass
class Finding:
    """Result of evaluating one check against one resource."""

    check_id: str
    title: str
    cis_ref: str
    severity: Severity
    status: Status
    resource: str
    region: str
    message: str
    remediation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass
class ScanResult:
    account_id: str
    regions: list[str]
    started_at: str
    findings: list[Finding] = field(default_factory=list)
    provider: str = "aws"  # "aws" or "gcp"; account_id holds the GCP project ID for gcp
    note: str = ""  # free-text banner, e.g. marking a synthetic sample report

    def summary(self) -> dict:
        counts = {s.value: {st.value: 0 for st in Status} for s in Severity}
        for f in self.findings:
            counts[f.severity.value][f.status.value] += 1
        total = len(self.findings)
        passed = sum(1 for f in self.findings if f.status == Status.PASS)
        return {
            "total": total,
            "passed": passed,
            "failed": sum(1 for f in self.findings if f.status == Status.FAIL),
            "errors": sum(1 for f in self.findings if f.status == Status.ERROR),
            "score": round(100 * passed / total, 1) if total else 100.0,
            "by_severity": counts,
        }

    def to_dict(self) -> dict:
        d = {
            "provider": self.provider,
            "account_id": self.account_id,
            "regions": self.regions,
            "started_at": self.started_at,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.note:
            d["note"] = self.note
        return d
