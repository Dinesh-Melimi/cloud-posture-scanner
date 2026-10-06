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

