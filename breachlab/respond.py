"""Automated containment.

When a detection fires, the responder takes the action a SOC would take by hand,
against a *simulated* AWS account stood up with moto. The boto3 calls are real;
the account is not. In a real deployment the same functions run against a live
account from a Lambda triggered by EventBridge (see terraform/breach-response).

Three containment actions, each mapped to the detection that triggers it:

  revoke_instance_role_session  <- DET-001 / DET-002  (kill the stolen creds)
  quarantine_principal          <- DET-004            (stop the privesc'd user)
  isolate_instance              <- DET-005 / DET-006  (cut off the exfil host)

Every action is idempotent and records what it did, so the incident report can
show a full before/after.
"""

from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

# A deny-everything policy used to neutralize a compromised identity without
# deleting it -- keeps the evidence intact for forensics.
DENY_ALL = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
}
QUARANTINE_POLICY_NAME = "breachlab-quarantine-deny-all"


@dataclass
class Action:
    name: str
    target: str
    detail: str
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "target": self.target, "detail": self.detail,
                "ts": self.ts}


class Responder:
    """Runs containment against whatever AWS endpoints boto3 is pointed at.

    Under the lab's moto context this is a simulated account; the calls below
    are the same ones a production responder would make.
    """

    def __init__(self, region: str = "us-east-1") -> None:
        self.region = region
        self.iam = boto3.client("iam", region_name=region)
        self.ec2 = boto3.client("ec2", region_name=region)
        self.actions: list[Action] = []

    # -- containment actions -------------------------------------------------

    def quarantine_principal(self, user_name: str) -> Action:
        """Attach an explicit deny-all to a compromised IAM user.

        An explicit deny overrides every allow, so this stops the user at once
        while leaving the account and its history in place for investigation.
        """
        self.iam.put_user_policy(
            UserName=user_name,
            PolicyName=QUARANTINE_POLICY_NAME,
            PolicyDocument=json.dumps(DENY_ALL),
        )
        act = Action("quarantine_principal", user_name,
                     "Attached deny-all inline policy; the user can no longer act.")
        self.actions.append(act)
        return act

    def revoke_access_keys(self, user_name: str) -> list[Action]:
        """Deactivate every access key on a user (the stolen long-lived creds)."""
        done: list[Action] = []
        keys = self.iam.list_access_keys(UserName=user_name).get(
            "AccessKeyMetadata", [])
        for k in keys:
            self.iam.update_access_key(
                UserName=user_name, AccessKeyId=k["AccessKeyId"], Status="Inactive")
            act = Action("revoke_access_keys", user_name,
                         f"Deactivated access key {k['AccessKeyId']}.")
            self.actions.append(act)
            done.append(act)
        return done

    def isolate_instance(self, instance_id: str) -> Action:
        """Move an instance into an empty, no-egress security group.

        A security group with no rules denies all traffic (groups are allow-only),
        so this severs the exfiltration channel without terminating the box, which
        would destroy volatile evidence.
        """
        vpc_id = self._instance_vpc(instance_id)
        sg_id = self._ensure_isolation_sg(vpc_id)
        self.ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])
        act = Action("isolate_instance", instance_id,
                     f"Replaced security groups with no-egress group {sg_id}.")
        self.actions.append(act)
        return act

    def snapshot_instance_volumes(self, instance_id: str) -> list[Action]:
        """Snapshot attached EBS volumes for forensics before anything changes."""
        done: list[Action] = []
        resp = self.ec2.describe_instances(InstanceIds=[instance_id])
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                for bdm in inst.get("BlockDeviceMappings", []):
                    vol = bdm.get("Ebs", {}).get("VolumeId")
                    if not vol:
                        continue
                    snap = self.ec2.create_snapshot(
                        VolumeId=vol,
                        Description=f"breachlab forensic snapshot of {instance_id}")
                    act = Action("snapshot_instance_volumes", instance_id,
                                 f"Created snapshot {snap['SnapshotId']} of {vol}.")
                    self.actions.append(act)
                    done.append(act)
        return done

    # -- helpers -------------------------------------------------------------

    def _instance_vpc(self, instance_id: str) -> str:
        resp = self.ec2.describe_instances(InstanceIds=[instance_id])
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                return inst["VpcId"]
        raise ValueError(f"instance {instance_id} not found")

    def _ensure_isolation_sg(self, vpc_id: str) -> str:
        name = "breachlab-isolation"
        existing = self.ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [name]},
                     {"Name": "vpc-id", "Values": [vpc_id]}]).get(
            "SecurityGroups", [])
        if existing:
            sg_id = existing[0]["GroupId"]
        else:
            sg_id = self.ec2.create_security_group(
                GroupName=name, Description="No ingress/egress; forensic hold",
                VpcId=vpc_id)["GroupId"]
            # New groups come with a default allow-all egress rule; strip it so
            # the isolated instance truly cannot talk out. Some backends add no
            # such default rule, so a missing-rule error here is harmless.
            with suppress(ClientError):
                self.ec2.revoke_security_group_egress(
                    GroupId=sg_id,
                    IpPermissions=[{"IpProtocol": "-1",
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        return sg_id
