"""Command-line entry point: python -m scanner --help"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from scanner.checks import REGISTRY
from scanner.engine import run_gcp_scan, run_scan
from scanner.models import Severity, Status
from scanner.report import write_reports


def _split(value: str | None) -> list[str] | None:
    return [x.strip() for x in value.split(",") if x.strip()] if value else None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cloud-posture-scanner",
                                description="Read-only AWS or GCP posture scan against CIS controls.")
    p.add_argument("--provider", choices=["aws", "gcp"], default="aws", help="Cloud provider (default: aws)")
    p.add_argument("--profile", help="AWS named profile")
    p.add_argument("--regions", default="us-east-1", help="Comma-separated AWS regions")
    p.add_argument("--project", help="GCP project ID (required with --provider gcp)")
    p.add_argument("--checks", help="Comma-separated check IDs to run (default: all)")
    p.add_argument("--exclude", help="Comma-separated check IDs to skip")
    p.add_argument("--format", default="json,md,html", help="Any of json,md,html")
    p.add_argument("--output", default="reports", help="Output directory")
    p.add_argument("--fail-on", choices=[s.value for s in Severity],
                   help="Exit 2 if any FAIL at or above this severity (for CI gating)")
    p.add_argument("--list-checks", action="store_true", help="List checks and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _gcp_registry():
    from scanner.gcp import GCP_REGISTRY

    return GCP_REGISTRY


def _scan(args, gcp_adapter=None):
    if args.provider == "gcp":
        if gcp_adapter is None:
            from scanner.gcp.client import GoogleApiAdapter

            gcp_adapter = GoogleApiAdapter()
        return run_gcp_scan(gcp_adapter, args.project, _split(args.checks), _split(args.exclude))
    import boto3

    session = boto3.Session(profile_name=args.profile)
    return run_scan(session, _split(args.regions), _split(args.checks), _split(args.exclude))


def main(argv: list[str] | None = None, gcp_adapter=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(message)s")
    if args.list_checks:
        registry = _gcp_registry() if args.provider == "gcp" else REGISTRY
        for cid in sorted(registry):
            c = registry[cid]
            scope = "regional" if c.regional else "global"
            print(f"{cid:11} {c.severity.value:8} {c.cis_ref:31} {scope:8} {c.title}")
        return 0

    if args.provider == "gcp" and not args.project:
        parser.error("--project is required with --provider gcp")
    from scanner.gcp.client import GcpApiError

    try:
        result = _scan(args, gcp_adapter)  # tests inject a fake GCP adapter
    except GcpApiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    paths = write_reports(result, Path(args.output), _split(args.format))
    s = result.summary()
    print(f"Score {s['score']}%  passed={s['passed']} failed={s['failed']} errors={s['errors']}")
    for p in paths:
        print(f"  wrote {p}")

    if args.fail_on:
        ranks = [sv.value for sv in Severity]
        threshold = ranks.index(args.fail_on)
        if any(f.status == Status.FAIL and ranks.index(f.severity.value) <= threshold
               for f in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
