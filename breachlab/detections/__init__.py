"""Detection-as-code rules.

Each rule is a function that takes the full timeline and returns the events it
considers malicious, with a reason. Rules are deliberately small and readable:
one behaviour each, so the ATT&CK coverage is easy to audit and a reviewer can
see exactly why something fired.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ..events import Event

# AWS IP-space check is a stand-in: in the lab, any routable attacker IP counts
# as "outside AWS". Real deployments resolve this against the published AWS
# ip-ranges.json instead.
_AWS_SERVICE_PRINCIPAL_SUFFIX = ".amazonaws.com"


@dataclass
class Hit:
    rule_id: str
    title: str
    technique: str
    severity: str          # LOW / MEDIUM / HIGH / CRITICAL
    event: Event
    reason: str


Rule = "Callable[[list[Event]], list[Hit]]"


def _is_role(actor: str | None) -> bool:
    return bool(actor and "assumed-role" in actor)


def r_imds_exfil(events: list[Event]) -> list[Hit]:
    """GuardDuty: instance role credentials used outside AWS (T1552.005)."""
    out = []
    for e in events:
        if e.source == "guardduty" and "InstanceCredentialExfiltration" in e.name:
            out.append(Hit("DET-001", "Instance credentials used outside AWS",
                           "T1552.005", "CRITICAL", e,
                           "GuardDuty flagged an instance role's temporary keys "
                           "being used from an external IP -- the signature of "
                           "an SSRF or metadata-service credential theft."))
    return out


def r_role_from_new_ip(events: list[Event]) -> list[Hit]:
    """An instance role makes API calls from an IP that is not the instance.

    Instance roles should only ever be used from the instance. A role call from
    a different, external IP means the credentials have left the box (T1078.004).
    """
    out = []
    seen: set[tuple[str, str]] = set()
    for e in events:
        if (e.source == "cloudtrail" and _is_role(e.actor)
                and e.source_ip and not e.source_ip.startswith("10.")):
            key = (e.actor or "", e.source_ip)
            if key in seen:  # one alert per principal+IP; the rest are the same session
                continue
            seen.add(key)
            out.append(Hit("DET-002", "Instance role used from a foreign IP",
                           "T1078.004", "HIGH", e,
                           f"Role {e.actor} first seen calling {e.name} from "
                           f"{e.source_ip}, which is not the instance address; "
                           "all later calls from this session are the same alert."))
    return out


def r_iam_enum_burst(events: list[Event]) -> list[Hit]:
    """A burst of read-only IAM discovery calls from one principal (T1087)."""
    discovery = {"ListAttachedRolePolicies", "ListRolePolicies", "GetPolicyVersion",
                 "ListUsers", "ListRoles", "GetAccountAuthorizationDetails"}
    by_actor: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source == "cloudtrail" and e.name in discovery:
            by_actor[e.actor or "?"].append(e)
    out = []
    for actor, evs in by_actor.items():
        if len(evs) >= 3:
            out.append(Hit("DET-003", "IAM enumeration burst", "T1087", "MEDIUM",
                           evs[0],
                           f"{actor} made {len(evs)} IAM discovery calls in quick "
                           "succession, consistent with permission mapping."))
    return out


def r_iam_privesc(events: list[Event]) -> list[Hit]:
    """A policy change that grants wildcard admin (T1098).

    PutUserPolicy / PutRolePolicy / AttachUserPolicy with an allow-* document is
    the classic AWS privilege-escalation move.
    """
    sensitive = {"PutUserPolicy", "PutRolePolicy", "AttachUserPolicy",
                 "AttachRolePolicy", "CreatePolicyVersion"}
    out = []
    for e in events:
        if e.source != "cloudtrail" or e.name not in sensitive:
            continue
        doc = e.attributes.get("policyDocument", "").replace(" ", "")
        managed = e.attributes.get("policyArn", "")
        # Fire only on an over-broad grant: an inline allow-* document, or one of
        # the well-known admin managed policies. A scoped policy change is normal
        # operations and must not alert, or the rule is just noise.
        wildcard = (('"Effect":"Allow"' in doc and '"Action":"*"' in doc)
                    or '"Action":["*"]' in doc
                    or managed.endswith("AdministratorAccess"))
        if wildcard:
            out.append(Hit("DET-004", "IAM privilege escalation", "T1098",
                           "CRITICAL", e,
                           f"{e.actor} called {e.name} on {e.resource}, granting a "
                           "wildcard allow-all policy."))
    return out


def r_s3_exfil(events: list[Event]) -> list[Hit]:
    """GuardDuty anomalous S3 reads, or a large outbound transfer (T1537)."""
    out = []
    for e in events:
        if e.source == "guardduty" and e.name.startswith("Exfiltration:S3"):
            out.append(Hit("DET-005", "Anomalous S3 data access", "T1537", "HIGH",
                           e, "GuardDuty saw an unusual volume of object reads "
                           f"from {e.resource} by a single principal."))
        if (e.source == "vpcflow"
                and e.attributes.get("bytes_out", 0) >= 100_000_000):
            mb = e.attributes["bytes_out"] // (1024 * 1024)
            out.append(Hit("DET-006", "Large outbound transfer", "T1537", "MEDIUM",
                           e, f"{mb} MB left {e.source_ip} toward "
                           f"{e.attributes.get('dest_ip')} -- possible bulk "
                           "exfiltration."))
    return out


ALL_RULES = [
    r_imds_exfil,
    r_role_from_new_ip,
    r_iam_enum_burst,
    r_iam_privesc,
    r_s3_exfil,
]


def run_rules(events: list[Event]) -> list[Hit]:
    hits: list[Hit] = []
    for rule in ALL_RULES:
        hits.extend(rule(events))
    hits.sort(key=lambda h: h.event.ts)
    return hits
