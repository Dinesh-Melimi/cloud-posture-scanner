"""Tie detection to response.

Given the detection hits, decide which containment actions to run and execute
them against the (simulated) account. The mapping is intentionally explicit so a
reviewer can see which alert drives which action -- no hidden automation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .detections import Hit, run_rules
from .events import Event
from .lab_account import simulated_account
from .respond import Responder
from .scenario import scenario_events


@dataclass
class Outcome:
    hits: list[Hit] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    resources: dict[str, Any] = field(default_factory=dict)


# Which rule ids call for which response.
CREDENTIAL_ALERTS = {"DET-001", "DET-002"}
PRIVESC_ALERTS = {"DET-004"}
EXFIL_ALERTS = {"DET-005", "DET-006"}


def respond_to(hits: list[Hit], acct: dict, responder: Responder) -> None:
    fired = {h.rule_id for h in hits}

    if fired & CREDENTIAL_ALERTS:
        # Stolen instance-role session: kill the long-lived keys on the blast-
        # radius user and snapshot the instance before touching it.
        responder.snapshot_instance_volumes(acct["instance_id"])
        responder.revoke_access_keys(acct["user_name"])

    if fired & PRIVESC_ALERTS:
        responder.quarantine_principal(acct["user_name"])

    if fired & EXFIL_ALERTS:
        responder.isolate_instance(acct["instance_id"])


def run_pipeline(events: list[Event] | None = None) -> Outcome:
    """Full detect-then-contain run against a fresh simulated account."""
    events = events if events is not None else scenario_events()
    hits = run_rules(events)

    with simulated_account() as acct:
        responder = Responder(region=acct["region"])
        respond_to(hits, acct, responder)
        return Outcome(
            hits=hits,
            actions=[a.to_dict() for a in responder.actions],
            resources=acct,
        )
