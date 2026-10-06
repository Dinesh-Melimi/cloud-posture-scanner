"""Base class and registry for check plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from scanner.models import Finding, Severity, Status

REGISTRY: dict[str, type[BaseCheck]] = {}


def register(cls: type[BaseCheck]) -> type[BaseCheck]:
    """Class decorator that adds a check to the global registry."""
    if cls.check_id in REGISTRY:
        raise ValueError(f"Duplicate check id {cls.check_id}")
    REGISTRY[cls.check_id] = cls
    return cls


class BaseCheck(ABC):
    """A single posture control.

    Subclasses set metadata as class attributes and implement ``run``.
    ``regional`` checks are executed once per scanned region; global
    checks (IAM, S3 account settings) run once.
    """

    check_id: ClassVar[str]
    title: ClassVar[str]
    cis_ref: ClassVar[str]
    severity: ClassVar[Severity]
    remediation: ClassVar[str]
    regional: ClassVar[bool] = False

    def __init__(self, session, region: str = "global"):
        self.session = session
        self.region = region

    def client(self, service: str):
        region = None if self.region == "global" else self.region
        return self.session.client(service, region_name=region or "us-east-1")

    def finding(self, status: Status, resource: str, message: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            title=self.title,
            cis_ref=self.cis_ref,
            severity=self.severity,
            status=status,
            resource=resource,
            region=self.region,
            message=message,
            remediation=self.remediation,
        )

    def passed(self, resource: str, message: str) -> Finding:
        return self.finding(Status.PASS, resource, message)

    def failed(self, resource: str, message: str) -> Finding:
        return self.finding(Status.FAIL, resource, message)

    @abstractmethod
    def run(self) -> list[Finding]:
        """Evaluate the control and return one or more findings."""
