"""Base class and registry for GCP checks (separate from the AWS registry)."""

from __future__ import annotations

from typing import ClassVar

from scanner.checks.base import BaseCheck
from scanner.models import Finding, Status

GCP_REGISTRY: dict[str, type[GcpCheck]] = {}


def register_gcp(cls: type[GcpCheck]) -> type[GcpCheck]:
    """Class decorator that adds a GCP check to ``GCP_REGISTRY``."""
    if cls.check_id in GCP_REGISTRY:
        raise ValueError(f"Duplicate check id {cls.check_id}")
    GCP_REGISTRY[cls.check_id] = cls
    return cls


class GcpCheck(BaseCheck):
    """A GCP control. ``self.gcp`` is a ``GcpAdapter``; ``self.project`` the project ID.

    GCP checks are project-scoped, so they run once per scan. Findings can still
    carry a location (bucket region, SQL region, cluster zone) via ``location=``.
    """

    provider: ClassVar[str] = "gcp"

    def __init__(self, adapter, project: str):
        super().__init__(adapter, "global")
        self.gcp = adapter
        self.project = project

    def client(self, service: str):  # pragma: no cover - AWS-only helper
        raise NotImplementedError("GCP checks use self.gcp (the adapter), not boto3 clients")

    def finding(self, status: Status, resource: str, message: str, location: str = "global") -> Finding:
        f = super().finding(status, resource, message)
        f.region = location
        return f

    def passed(self, resource: str, message: str, location: str = "global") -> Finding:
        return self.finding(Status.PASS, resource, message, location)

    def failed(self, resource: str, message: str, location: str = "global") -> Finding:
        return self.finding(Status.FAIL, resource, message, location)
