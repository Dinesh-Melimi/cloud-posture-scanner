"""Command-line entry point: python -m scanner --help"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import boto3

from scanner.checks import REGISTRY
from scanner.engine import run_scan
from scanner.models import Severity, Status
from scanner.report import write_reports


def _split(value: str | None) -> list[str] | None:
    return [x.strip() for x in value.split(",") if x.strip()] if value else None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cloud-posture-scanner",
                                description="Read-only AWS posture scan against CIS controls.")
    p.add_argument("--profile", help="AWS named profile")
    p.add_argument("--regions", default="us-east-1", help="Comma-separated regions")
    p.add_argument("--checks", help="Comma-separated check IDs to run (default: all)")
    p.add_argument("--exclude", help="Comma-separated check IDs to skip")
    p.add_argument("--format", default="json,md,html", help="Any of json,md,html")
    p.add_argument("--output", default="reports", help="Output directory")
    p.add_argument("--fail-on", choices=[s.value for s in Severity],
                   help="Exit 2 if any FAIL at or above this severity (for CI gating)")
    p.add_argument("--list-checks", action="store_true", help="List checks and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(message)s")
    if args.list_checks:
        for cid in sorted(REGISTRY):
            c = REGISTRY[cid]
            scope = "regional" if c.regional else "global"
            print(f"{cid:8} {c.severity.value:8} {c.cis_ref:24} {scope:8} {c.title}")
        return 0

    session = boto3.Session(profile_name=args.profile)
    result = run_scan(session, _split(args.regions), _split(args.checks), _split(args.exclude))
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
