"""Tests for the breach detection-and-response lab."""

from __future__ import annotations

import boto3
from moto import mock_aws

from breachlab.baseline import baseline_events
from breachlab.detections import run_rules
from breachlab.lab_account import simulated_account
from breachlab.orchestrate import run_pipeline
from breachlab.report import render_markdown
from breachlab.respond import QUARANTINE_POLICY_NAME, Responder
from breachlab.scenario import build_scenario, scenario_events


def test_scenario_is_time_ordered():
    evs = scenario_events()
    assert evs == sorted(evs, key=lambda e: e.ts)
    assert len(evs) >= 7


def test_every_step_has_attack_mapping():
    for s in build_scenario():
        assert s.technique.startswith("T")
        assert s.events, f"{s.id} has no telemetry"


def test_detections_cover_the_whole_chain():
    hits = run_rules(scenario_events())
    fired = {h.rule_id for h in hits}
    # Every stage from credential theft through exfiltration is caught.
    assert {"DET-001", "DET-002", "DET-003", "DET-004", "DET-005", "DET-006"} <= fired


def test_privesc_rule_is_critical():
    hits = run_rules(scenario_events())
    privesc = [h for h in hits if h.rule_id == "DET-004"]
    assert privesc and all(h.severity == "CRITICAL" for h in privesc)


def test_role_from_new_ip_deduped_to_one():
    hits = [h for h in run_rules(scenario_events()) if h.rule_id == "DET-002"]
    assert len(hits) == 1, "DET-002 should collapse one session to a single alert"


def test_benign_baseline_has_no_false_positives():
    assert run_rules(baseline_events()) == []


def test_pipeline_runs_containment():
    outcome = run_pipeline()
    names = {a["name"] for a in outcome.actions}
    assert {"snapshot_instance_volumes", "revoke_access_keys",
            "quarantine_principal", "isolate_instance"} <= names


def test_quarantine_actually_denies_the_user():
    with simulated_account() as acct:
        r = Responder(region=acct["region"])
        r.quarantine_principal(acct["user_name"])
        iam = boto3.client("iam", region_name=acct["region"])
        pol = iam.get_user_policy(UserName=acct["user_name"],
                                  PolicyName=QUARANTINE_POLICY_NAME)
        stmt = pol["PolicyDocument"]["Statement"][0]
        assert stmt["Effect"] == "Deny" and stmt["Action"] == "*"


def test_revoke_deactivates_keys():
    with simulated_account() as acct:
        r = Responder(region=acct["region"])
        r.revoke_access_keys(acct["user_name"])
        iam = boto3.client("iam", region_name=acct["region"])
        keys = iam.list_access_keys(UserName=acct["user_name"])["AccessKeyMetadata"]
        assert keys and all(k["Status"] == "Inactive" for k in keys)


def test_isolate_moves_instance_to_empty_sg():
    with simulated_account() as acct:
        r = Responder(region=acct["region"])
        r.isolate_instance(acct["instance_id"])
        ec2 = boto3.client("ec2", region_name=acct["region"])
        inst = ec2.describe_instances(InstanceIds=[acct["instance_id"]])[
            "Reservations"][0]["Instances"][0]
        groups = inst["SecurityGroups"]
        assert len(groups) == 1
        sg = ec2.describe_security_groups(GroupIds=[groups[0]["GroupId"]])[
            "SecurityGroups"][0]
        assert sg["IpPermissionsEgress"] == []  # no way out


def test_snapshot_created():
    with simulated_account() as acct:
        r = Responder(region=acct["region"])
        actions = r.snapshot_instance_volumes(acct["instance_id"])
        assert actions
        ec2 = boto3.client("ec2", region_name=acct["region"])
        snaps = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
        assert snaps


def test_report_has_all_sections():
    md = render_markdown(run_pipeline())
    for heading in ("# Incident report", "## Attack timeline", "## Detections",
                    "## Containment", "## Recommended follow-up"):
        assert heading in md


@mock_aws
def test_responder_is_idempotent_on_isolation_sg():
    # Calling isolate twice must not fail or create a second group.
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                             SubnetId=subnet["SubnetId"])["Instances"][0]
    r = Responder()
    r.isolate_instance(inst["InstanceId"])
    r.isolate_instance(inst["InstanceId"])
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["breachlab-isolation"]}])[
        "SecurityGroups"]
    assert len(groups) == 1
