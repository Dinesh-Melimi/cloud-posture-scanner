"""The breach scenario as a timeline of telemetry.

Each step describes one stage of a cloud intrusion and emits the log records
that stage would leave in CloudTrail, GuardDuty and VPC flow logs. There is no
exploit code here -- a step is a short description plus the evidence it drops,
which is exactly what a detection engineer works from.

The scenario is a classic IMDS-to-exfiltration path, the most common way an
AWS account gets taken over from a single exposed web app:

  1. Recon of the exposed web app                       (ATT&CK T1595)
  2. Server-side request forgery reaches the metadata
     service and the instance role's keys are read      (T1552.005)
  3. Those keys are used from a new IP outside AWS       (T1078.004)
  4. The attacker enumerates their own permissions       (T1087 / T1069)
  5. Privilege escalation via an over-broad iam:PutUserPolicy (T1098)
  6. Lateral movement: the new rights open an S3 bucket  (T1530)
  7. Bulk download of the bucket -- data exfiltration    (T1537)

A fixed start time and fixed IPs/identifiers make every replay identical, so
the detections and the demo are reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .events import Event, cloudtrail, guardduty, vpcflow

# Fixed, obviously-synthetic values. RFC 5737 / RFC 3849 documentation ranges
# and example ARNs, so nothing here points at a real host or account.
START = datetime(2026, 11, 5, 14, 0, 0, tzinfo=timezone.utc)
ACCOUNT = "111122223333"
INSTANCE_ID = "i-0labdeadbeef00001"
INSTANCE_IP = "203.0.113.10"          # the web server (TEST-NET-3)
ATTACKER_IP = "198.51.100.77"         # attacker's host (TEST-NET-2)
INSTANCE_ROLE = f"arn:aws:sts::{ACCOUNT}:assumed-role/app-server-role/{INSTANCE_ID}"
IAM_USER = f"arn:aws:iam::{ACCOUNT}:user/ci-deploy"
BUCKET = "acme-customer-exports"


def _t(seconds: int) -> str:
    return (START + timedelta(seconds=seconds)).isoformat()


@dataclass
class Step:
    id: str
    title: str
    technique: str          # ATT&CK technique id
    tactic: str
    narrative: str          # plain-language description of what happened
    events: list[Event] = field(default_factory=list)


def build_scenario() -> list[Step]:
    """Return the ordered breach timeline."""
    steps: list[Step] = []

    steps.append(Step(
        "recon", "Web app reconnaissance", "T1595", "Reconnaissance",
        "An outside host probes the public web app, walking URL parameters that "
        "look like they fetch remote content.",
        [
            vpcflow("ACCEPT", ATTACKER_IP, INSTANCE_IP, 443, ts=_t(0), step="recon"),
            vpcflow("ACCEPT", ATTACKER_IP, INSTANCE_IP, 443, ts=_t(3), step="recon",
                    note="repeated parameter probing"),
        ],
    ))

    steps.append(Step(
        "imds", "Instance metadata read via SSRF", "T1552.005",
        "Credential Access",
        "A server-side request forgery in the app makes the instance call its own "
        "metadata service and return the app-server role's temporary credentials. "
        "GuardDuty records the role credentials being used from outside AWS shortly "
        "after.",
        [
            guardduty(
                "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                INSTANCE_ROLE, ATTACKER_IP, INSTANCE_ID, severity=8.0, ts=_t(45),
                step="imds",
                description="Instance role credentials used from an external IP"),
        ],
    ))

    steps.append(Step(
        "reuse", "Stolen role used from a new IP", "T1078.004",
        "Defense Evasion",
        "The temporary credentials are now driving API calls from the attacker's "
        "IP, not from the instance.",
        [
            cloudtrail("GetCallerIdentity", INSTANCE_ROLE, ATTACKER_IP, ts=_t(60),
                       step="reuse", userAgent="aws-cli/2.15.0"),
        ],
    ))

    steps.append(Step(
        "enum", "Permission enumeration", "T1087",
        "Discovery",
        "The attacker maps what the stolen role can do, listing policies and "
        "attached permissions -- a burst of read-only IAM calls in a few seconds.",
        [
            cloudtrail("ListAttachedRolePolicies", INSTANCE_ROLE, ATTACKER_IP,
                       ts=_t(70), step="enum"),
            cloudtrail("ListRolePolicies", INSTANCE_ROLE, ATTACKER_IP, ts=_t(72),
                       step="enum"),
            cloudtrail("GetPolicyVersion", INSTANCE_ROLE, ATTACKER_IP, ts=_t(74),
                       step="enum"),
            cloudtrail("ListUsers", INSTANCE_ROLE, ATTACKER_IP, ts=_t(76),
                       step="enum"),
        ],
    ))

    steps.append(Step(
        "privesc", "Privilege escalation", "T1098",
        "Privilege Escalation",
        "The role can attach IAM policies, so the attacker grants a deploy user "
        "full admin by putting an inline allow-all policy on it. This single call "
        "is the turning point of the breach.",
        [
            cloudtrail("PutUserPolicy", INSTANCE_ROLE, ATTACKER_IP, IAM_USER,
                       ts=_t(95), step="privesc",
                       policyName="deploy-inline",
                       policyDocument='{"Version":"2012-10-17","Statement":'
                       '[{"Effect":"Allow","Action":"*","Resource":"*"}]}'),
        ],
    ))

    steps.append(Step(
        "lateral", "Lateral movement to data store", "T1530",
        "Collection",
        "With admin rights the attacker turns to the customer-export bucket, "
        "reading its policy and listing its contents.",
        [
            cloudtrail("GetBucketPolicy", IAM_USER, ATTACKER_IP, BUCKET, ts=_t(120),
                       step="lateral"),
            cloudtrail("ListObjects", IAM_USER, ATTACKER_IP, BUCKET, ts=_t(123),
                       step="lateral"),
        ],
    ))

    steps.append(Step(
        "exfil", "Data exfiltration", "T1537",
        "Exfiltration",
        "The attacker bulk-downloads the bucket. GuardDuty flags anomalous S3 "
        "reads and the flow logs show a large outbound transfer to the attacker IP.",
        [
            guardduty("Exfiltration:S3/AnomalousBehavior", IAM_USER, ATTACKER_IP,
                      BUCKET, severity=8.0, ts=_t(150), step="exfil",
                      description="Unusual volume of S3 GetObject from one principal"),
            vpcflow("ACCEPT", INSTANCE_IP, ATTACKER_IP, 443, bytes_out=734003200,
                    ts=_t(155), step="exfil", note="~700 MB outbound"),
        ],
    ))

    return steps


def scenario_events() -> list[Event]:
    """Flatten the scenario into a single ordered timeline."""
    out: list[Event] = []
    for step in build_scenario():
        out.extend(step.events)
    out.sort(key=lambda e: e.ts)
    return out
