"""Runs registered checks and collects findings."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from botocore.exceptions import BotoCoreError, ClientError

from scanner.checks import REGISTRY
from scanner.models import ScanResult, Status

log = logging.getLogger(__name__)


def select_checks(include: list[str] | None = None, exclude: list[str] | None = None):
    ids = sorted(REGISTRY)
    if include:
        ids = [i for i in ids if i in include]
    if exclude:
        ids = [i for i in ids if i not in exclude]
    return [REGISTRY[i] for i in ids]


def run_scan(session, regions: list[str], include=None, exclude=None) -> ScanResult:
    account_id = session.client("sts", region_name=regions[0]).get_caller_identity()["Account"]
    result = ScanResult(
        account_id=account_id,
        regions=regions,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    for check_cls in select_checks(include, exclude):
        targets = regions if check_cls.regional else ["global"]
        for region in targets:
            check = check_cls(session, region)
            try:
                result.findings.extend(check.run())
            except (ClientError, BotoCoreError) as exc:
                # One failing API call (e.g. AccessDenied) must not abort the scan.
                log.warning("%s failed in %s: %s", check_cls.check_id, region, exc)
                result.findings.append(
                    check.finding(Status.ERROR, "n/a", f"Check could not run: {exc}")
                )
    return result



def select_gcp_checks(include: list[str] | None = None, exclude: list[str] | None = None):
    from scanner.gcp import GCP_REGISTRY

    ids = sorted(GCP_REGISTRY)
    if include:
        ids = [i for i in ids if i in include]
    if exclude:
        ids = [i for i in ids if i not in exclude]
    return [GCP_REGISTRY[i] for i in ids]


def run_gcp_scan(adapter, project: str, include=None, exclude=None) -> ScanResult:
    """Run GCP checks against one project through a ``GcpAdapter``."""
    from scanner.gcp import GcpApiError

    result = ScanResult(
        account_id=project,
        regions=["global"],
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        provider="gcp",
    )
    locations: set[str] = set()
    for check_cls in select_gcp_checks(include, exclude):
        check = check_cls(adapter, project)
        try:
            findings = check.run()
        except GcpApiError as exc:
            # Same contract as AWS: a 403 or disabled API becomes a visible ERROR finding.
            log.warning("%s failed: %s", check_cls.check_id, exc)
            findings = [check.finding(Status.ERROR, "n/a", f"Check could not run: {exc}")]
        result.findings.extend(findings)
        locations.update(f.region for f in findings)
    result.regions = sorted(locations) or ["global"]
    return result
