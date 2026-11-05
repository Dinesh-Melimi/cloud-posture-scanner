"""Lambda entry point for the breach responder.

EventBridge delivers a GuardDuty finding; this handler reads the finding type
and runs the matching containment from breachlab.respond against the live
account the Lambda is deployed in. The decision logic mirrors
breachlab.orchestrate so the local lab and the deployed responder behave the
same way.

Package this directory together with the breachlab package (see the README in
this folder) so the import below resolves at runtime.
"""

from __future__ import annotations

from typing import Any

from breachlab.respond import Responder

CREDENTIAL_FINDINGS = ("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",)
EXFIL_FINDINGS = ("Exfiltration:S3",)


def on_finding(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    detail = event.get("detail", {})
    finding_type = detail.get("type", "")
    resource = detail.get("resource", {})

    responder = Responder()
    taken: list[str] = []

    instance_id = (
        resource.get("instanceDetails", {}).get("instanceId"))
    user_name = (
        resource.get("accessKeyDetails", {}).get("userName"))

    if finding_type.startswith(CREDENTIAL_FINDINGS):
        if instance_id:
            responder.snapshot_instance_volumes(instance_id)
            responder.isolate_instance(instance_id)
            taken += ["snapshot", "isolate"]
        if user_name:
            responder.revoke_access_keys(user_name)
            responder.quarantine_principal(user_name)
            taken += ["revoke_keys", "quarantine"]

    elif finding_type.startswith(EXFIL_FINDINGS):
        if instance_id:
            responder.isolate_instance(instance_id)
            taken.append("isolate")
        if user_name:
            responder.quarantine_principal(user_name)
            taken.append("quarantine")

    return {"finding": finding_type, "actions": taken,
            "detail": [a.to_dict() for a in responder.actions]}
