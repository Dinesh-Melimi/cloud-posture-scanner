"""Benign day-in-the-life telemetry.

Running the detections over this timeline must produce zero hits. It is the
false-positive test: ordinary operations that look superficially similar to the
attack (an instance role working from inside the VPC, a human admin making a
scoped policy change, a normal-sized download) and must not trip any rule.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .events import Event, cloudtrail, vpcflow

START = datetime(2026, 11, 5, 9, 0, 0, tzinfo=timezone.utc)
ACCOUNT = "111122223333"
INSTANCE_ROLE = f"arn:aws:sts::{ACCOUNT}:assumed-role/app-server-role/i-0labdeadbeef00001"
ADMIN = f"arn:aws:iam::{ACCOUNT}:user/alice-admin"
INTERNAL_IP = "10.0.1.20"


def _t(seconds: int) -> str:
    return (START + timedelta(seconds=seconds)).isoformat()


def baseline_events() -> list[Event]:
    out: list[Event] = [
        # Instance role doing its job, from the instance's own private IP.
        cloudtrail("GetObject", INSTANCE_ROLE, INTERNAL_IP, "acme-app-assets",
                   ts=_t(0)),
        cloudtrail("PutObject", INSTANCE_ROLE, INTERNAL_IP, "acme-app-assets",
                   ts=_t(30)),
        # A single, scoped IAM change by a human admin -- not wildcard, so the
        # privesc rule should rate it HIGH at most only if wildcard; here it is
        # a tight policy, so it must not read as allow-all.
        cloudtrail("PutUserPolicy", ADMIN, INTERNAL_IP,
                   f"arn:aws:iam::{ACCOUNT}:user/ci-deploy", ts=_t(120),
                   policyName="s3-read-one-bucket",
                   policyDocument='{"Version":"2012-10-17","Statement":[{"Effect"'
                   ':"Allow","Action":["s3:GetObject"],"Resource":'
                   '"arn:aws:s3:::acme-app-assets/*"}]}'),
        # Two IAM reads -- below the enumeration-burst threshold of three.
        cloudtrail("ListUsers", ADMIN, INTERNAL_IP, ts=_t(140)),
        cloudtrail("ListRoles", ADMIN, INTERNAL_IP, ts=_t(145)),
        # A normal-sized outbound transfer, well under the exfil threshold.
        vpcflow("ACCEPT", INTERNAL_IP, "203.0.113.200", 443, bytes_out=2_500_000,
                ts=_t(200)),
    ]
    return out
