"""Telemetry event model.

An Event is one normalized log record. Real cloud logs come in several shapes
(CloudTrail JSON, GuardDuty findings, VPC flow log lines); we flatten them into
a single structure so detections can read any source the same way.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    """One log record on the timeline.

    Attributes:
        ts:         ISO-8601 timestamp.
        source:     where the record came from -- cloudtrail, guardduty, vpcflow.
        name:       event name (e.g. an API call like GetObject, or a finding type).
        actor:      the principal or identity seen in the record.
        source_ip:  the IP the activity came from, when the source has one.
        resource:   the resource acted on, when there is one.
        attributes: any extra source-specific fields a detection may read.
        step:       scenario step id that produced this record (for the lab only;
                    real logs do not carry this, so detections never read it).
    """

    ts: str
    source: str
    name: str
    actor: str | None = None
    source_ip: str | None = None
    resource: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    step: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def cloudtrail(name: str, actor: str, source_ip: str, resource: str | None = None,
               ts: str | None = None, step: str | None = None, **attrs: Any) -> Event:
    return Event(ts or _now(), "cloudtrail", name, actor, source_ip, resource,
                 dict(attrs), step)


def guardduty(finding_type: str, actor: str | None, source_ip: str | None,
              resource: str | None = None, severity: float = 5.0,
              ts: str | None = None, step: str | None = None, **attrs: Any) -> Event:
    data = {"severity": severity}
    data.update(attrs)
    return Event(ts or _now(), "guardduty", finding_type, actor, source_ip, resource,
                 data, step)


def vpcflow(action: str, source_ip: str, dest_ip: str, dest_port: int,
            bytes_out: int = 0, ts: str | None = None, step: str | None = None,
            **attrs: Any) -> Event:
    data = {"dest_ip": dest_ip, "dest_port": dest_port, "bytes_out": bytes_out,
            "action": action}
    data.update(attrs)
    return Event(ts or _now(), "vpcflow", f"flow:{action}", None, source_ip, dest_ip,
                 data, step)


def load_events(path: str) -> list[Event]:
    """Read a timeline back from a JSON-lines file."""
    out: list[Event] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(Event(**json.loads(line)))
    return out


def dump_events(events: list[Event], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev.to_dict()) + "\n")
