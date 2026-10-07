"""GCP checks against the in-memory FakeGcpAdapter: no network, no credentials."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from scanner.cli import main
from scanner.engine import run_gcp_scan
from scanner.gcp import GCP_REGISTRY
from scanner.gcp.checks import (
    GcpDataAccessAuditLogs,
    GcpDefaultNetwork,
    GcpFirewallAdminPorts,
    GcpGkeLegacyAbac,
    GcpGkePrivateNodes,
    GcpKmsRotation,
    GcpPrimitiveRoles,
    GcpPublicBuckets,
    GcpServiceAccountAdmin,
    GcpServiceAccountKeyAge,
    GcpSqlPublicIp,
    GcpSqlRequireSsl,
    GcpUniformBucketAccess,
)
from scanner.gcp.fake import FakeGcpAdapter
from scanner.models import Severity, Status
from scanner.report import to_html, to_markdown

P = "demo-project"
SA = "app@demo-project.iam.gserviceaccount.com"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def statuses(findings):
    return {f.resource: f.status for f in findings}


def only(findings):
    assert len(findings) == 1
    return findings[0].status


def test_gcp_registry_metadata():
    assert len(GCP_REGISTRY) == 13
    for cid, cls in GCP_REGISTRY.items():
        assert cid.startswith("GCP-") and cls.check_id == cid
        assert cls.cis_ref.startswith("CIS ") and cls.title and cls.remediation
        assert isinstance(cls.severity, Severity)


# ---- IAM

def test_primitive_roles():
    ok = FakeGcpAdapter(iam_policy={"bindings": [
        {"role": "roles/viewer", "members": ["user:a@x.com"]},
        {"role": "roles/owner", "members": ["group:admins@x.com"]}]})
    assert only(GcpPrimitiveRoles(ok, P).run()) == Status.PASS
    bad = FakeGcpAdapter(iam_policy={"bindings": [
        {"role": "roles/editor", "members": ["user:dev@x.com", f"serviceAccount:{SA}"]}]})
    assert statuses(GcpPrimitiveRoles(bad, P).run()) == {
        "user:dev@x.com": Status.FAIL, f"serviceAccount:{SA}": Status.FAIL}


def test_service_account_admin():
    other = "ci@other.iam.gserviceaccount.com"
    fake = FakeGcpAdapter(
        service_accounts=[{"email": SA}, {"email": "ro@demo-project.iam.gserviceaccount.com"}],
        iam_policy={"bindings": [
            {"role": "roles/storage.admin", "members": [f"serviceAccount:{SA}"]},
            {"role": "roles/owner", "members": [f"serviceAccount:{other}"]},
            {"role": "roles/viewer", "members": ["serviceAccount:ro@demo-project.iam.gserviceaccount.com"]},
        ]})
    assert statuses(GcpServiceAccountAdmin(fake, P).run()) == {
        SA: Status.FAIL, "ro@demo-project.iam.gserviceaccount.com": Status.PASS, other: Status.FAIL}
    assert only(GcpServiceAccountAdmin(FakeGcpAdapter(), P).run()) == Status.PASS


def _key(kid, days_old, **extra):
    ts = (NOW - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"name": f"projects/{P}/serviceAccounts/{SA}/keys/{kid}", "validAfterTime": ts,
            "keyType": "USER_MANAGED", **extra}


def test_service_account_key_age():
    fake = FakeGcpAdapter(service_accounts=[{"email": SA}], sa_keys={SA: [
        _key("new", 10), _key("old", 200), _key("off", 400, disabled=True),
        _key("sys", 500, keyType="SYSTEM_MANAGED")]})
    assert statuses(GcpServiceAccountKeyAge(fake, P, now=NOW).run()) == {
        f"{SA}/new": Status.PASS, f"{SA}/old": Status.FAIL}
    no_keys = FakeGcpAdapter(service_accounts=[{"email": SA}])
    assert only(GcpServiceAccountKeyAge(no_keys, P, now=NOW).run()) == Status.PASS


# ---- Logging

ALL_LOGS = [{"logType": t} for t in ("ADMIN_READ", "DATA_READ", "DATA_WRITE")]


@pytest.mark.parametrize("audit,expected", [
    ([{"service": "allServices", "auditLogConfigs": ALL_LOGS}], Status.PASS),
    ([], Status.FAIL),
    ([{"service": "storage.googleapis.com", "auditLogConfigs": ALL_LOGS}], Status.FAIL),
    ([{"service": "allServices", "auditLogConfigs": ALL_LOGS[:1]}], Status.FAIL),
    ([{"service": "allServices", "auditLogConfigs": ALL_LOGS[:2] + [
        {"logType": "DATA_WRITE", "exemptedMembers": ["user:boss@x.com"]}]}], Status.FAIL),
])
def test_data_access_audit_logs(audit, expected):
    fake = FakeGcpAdapter(iam_policy={"bindings": [], "auditConfigs": audit})
    assert only(GcpDataAccessAuditLogs(fake, P).run()) == expected


# ---- Networking

def test_default_network():
    assert only(GcpDefaultNetwork(FakeGcpAdapter(networks=[{"name": "prod-vpc"}]), P).run()) == Status.PASS
    assert only(GcpDefaultNetwork(FakeGcpAdapter(networks=[{"name": "default"}]), P).run()) == Status.FAIL


def _fw(name, ports=None, src=("0.0.0.0/0",), proto="tcp", **extra):
    allowed = {"IPProtocol": proto}
    if ports is not None:
        allowed["ports"] = ports
    return {"name": name, "direction": "INGRESS", "sourceRanges": list(src), "allowed": [allowed], **extra}


def test_firewall_admin_ports():
    fake = FakeGcpAdapter(firewalls=[
        _fw("ssh-open", ["22"]),
        _fw("rdp-range", ["3000-4000"]),
        _fw("all-proto", proto="all"),
        _fw("ipv6-ssh", ["22"], src=("::/0",)),
        _fw("https", ["443"]),
        _fw("ssh-corp", ["22"], src=("203.0.113.0/24",)),
        _fw("iap", ["22", "3389"], src=("35.235.240.0/20",)),
        _fw("disabled", ["22"], disabled=True),
        _fw("egress", ["22"], direction="EGRESS"),
        _fw("udp-only", ["22"], proto="udp"),
    ])
    assert statuses(GcpFirewallAdminPorts(fake, P).run()) == {
        "ssh-open": Status.FAIL, "rdp-range": Status.FAIL, "all-proto": Status.FAIL,
        "ipv6-ssh": Status.FAIL, "https": Status.PASS, "ssh-corp": Status.PASS,
        "iap": Status.PASS, "udp-only": Status.PASS}
    assert only(GcpFirewallAdminPorts(FakeGcpAdapter(), P).run()) == Status.PASS


# ---- Cloud Storage

def _bucket(name, ubla=True, pap="inherited"):
    return {"name": name, "location": "US", "iamConfiguration": {
        "uniformBucketLevelAccess": {"enabled": ubla}, "publicAccessPrevention": pap}}


def test_public_buckets():
    fake = FakeGcpAdapter(
        buckets=[_bucket("private"), _bucket("web"), _bucket("authn"), _bucket("pap", pap="enforced")],
        bucket_policies={
            "private": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["group:t@x.com"]}]},
            "web": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
            "authn": {"bindings": [{"role": "roles/storage.legacyBucketReader",
                                    "members": ["allAuthenticatedUsers"]}]},
            "pap": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
        })
    res = GcpPublicBuckets(fake, P).run()
    assert statuses(res) == {"private": Status.PASS, "web": Status.FAIL,
                             "authn": Status.FAIL, "pap": Status.PASS}
    assert {f.region for f in res} == {"us"}
    assert only(GcpPublicBuckets(FakeGcpAdapter(), P).run()) == Status.PASS


def test_uniform_bucket_access():
    fake = FakeGcpAdapter(buckets=[_bucket("ubla"), _bucket("acl", ubla=False), {"name": "bare"}])
    assert statuses(GcpUniformBucketAccess(fake, P).run()) == {
        "ubla": Status.PASS, "acl": Status.FAIL, "bare": Status.FAIL}
    assert only(GcpUniformBucketAccess(FakeGcpAdapter(), P).run()) == Status.PASS


# ---- Cloud SQL

def _sql(name, ipv4=False, ssl_mode=None, require_ssl=None, nets=()):
    cfg = {"ipv4Enabled": ipv4, "authorizedNetworks": [{"value": n} for n in nets]}
    if ssl_mode:
        cfg["sslMode"] = ssl_mode
    if require_ssl is not None:
        cfg["requireSsl"] = require_ssl
    ips = [{"type": "PRIVATE", "ipAddress": "10.0.0.5"}] + (
        [{"type": "PRIMARY", "ipAddress": "34.1.2.3"}] if ipv4 else [])
    return {"name": name, "region": "us-central1", "ipAddresses": ips, "settings": {"ipConfiguration": cfg}}


def test_sql_public_ip():
    fake = FakeGcpAdapter(sql_instances=[_sql("private"), _sql("public", ipv4=True, nets=["0.0.0.0/0"])])
    res = GcpSqlPublicIp(fake, P).run()
    assert statuses(res) == {"private": Status.PASS, "public": Status.FAIL}
    assert "0.0.0.0/0" in next(f.message for f in res if f.resource == "public")
    assert only(GcpSqlPublicIp(FakeGcpAdapter(), P).run()) == Status.PASS


def test_sql_require_ssl():
    fake = FakeGcpAdapter(sql_instances=[
        _sql("enc", ssl_mode="ENCRYPTED_ONLY"),
        _sql("mtls", ssl_mode="TRUSTED_CLIENT_CERTIFICATE_REQUIRED"),
        _sql("legacy-ok", require_ssl=True),
        _sql("plain", ssl_mode="ALLOW_UNENCRYPTED_AND_ENCRYPTED"),
        _sql("legacy-off", require_ssl=False),
        _sql("unset"),
    ])
    assert statuses(GcpSqlRequireSsl(fake, P).run()) == {
        "enc": Status.PASS, "mtls": Status.PASS, "legacy-ok": Status.PASS,
        "plain": Status.FAIL, "legacy-off": Status.FAIL, "unset": Status.FAIL}
    assert only(GcpSqlRequireSsl(FakeGcpAdapter(), P).run()) == Status.PASS


# ---- KMS

def _kms(name, period=None, purpose="ENCRYPT_DECRYPT", state="ENABLED"):
    k = {"name": f"projects/{P}/locations/us-east1/keyRings/ring/cryptoKeys/{name}",
         "purpose": purpose, "primary": {"state": state}}
    if period:
        k["rotationPeriod"] = period
    return k


def test_kms_rotation():
    fake = FakeGcpAdapter(kms_keys=[
        _kms("ninety", "7776000s"), _kms("thirty", "2592000s"), _kms("yearly", "31536000s"),
        _kms("never"), _kms("asym", purpose="ASYMMETRIC_SIGN"), _kms("gone", state="DESTROYED")])
    res = GcpKmsRotation(fake, P).run()
    by_short = {f.resource.rsplit("/", 1)[-1]: f.status for f in res}
    assert by_short == {"ninety": Status.PASS, "thirty": Status.PASS,
                        "yearly": Status.FAIL, "never": Status.FAIL}
    assert {f.region for f in res} == {"us-east1"}
    assert only(GcpKmsRotation(FakeGcpAdapter(), P).run()) == Status.PASS


# ---- GKE

GKE = [
    {"name": "hardened", "location": "us-central1",
     "privateClusterConfig": {"enablePrivateNodes": True}, "legacyAbac": {}},
    {"name": "netcfg", "location": "us-central1-a",
     "networkConfig": {"defaultEnablePrivateNodes": True}},
    {"name": "legacy", "location": "us-central1-a", "legacyAbac": {"enabled": True}},
]


def test_gke_private_nodes():
    assert statuses(GcpGkePrivateNodes(FakeGcpAdapter(gke_clusters=GKE), P).run()) == {
        "hardened": Status.PASS, "netcfg": Status.PASS, "legacy": Status.FAIL}
    assert only(GcpGkePrivateNodes(FakeGcpAdapter(), P).run()) == Status.PASS


def test_gke_legacy_abac():
    assert statuses(GcpGkeLegacyAbac(FakeGcpAdapter(gke_clusters=GKE), P).run()) == {
        "hardened": Status.PASS, "netcfg": Status.PASS, "legacy": Status.FAIL}
    assert only(GcpGkeLegacyAbac(FakeGcpAdapter(), P).run()) == Status.PASS


# ---- Engine, CLI, reports

def test_gcp_scan_empty_project_all_pass_except_audit_logs():
    result = run_gcp_scan(FakeGcpAdapter(), P)
    assert result.provider == "gcp" and result.account_id == P
    failed = {f.check_id for f in result.findings if f.status == Status.FAIL}
    assert failed == {"GCP-LOG-001"}
    assert {f.check_id for f in result.findings} == set(GCP_REGISTRY)


def test_gcp_api_error_becomes_error_finding():
    fake = FakeGcpAdapter(fail={"list_buckets": "403 storage.buckets.list denied"})
    result = run_gcp_scan(fake, P, include=["GCP-GCS-001", "GCP-NET-001"])
    assert {f.check_id: f.status for f in result.findings} == {
        "GCP-GCS-001": Status.ERROR, "GCP-NET-001": Status.PASS}


def test_gcp_reports_labelled():
    result = run_gcp_scan(FakeGcpAdapter(networks=[{"name": "default"}]), P)
    result.note = "SYNTHETIC"
    md, html = to_markdown(result), to_html(result)
    assert md.startswith("# GCP Cloud Posture Report") and "**Project:** demo-project" in md
    assert "SYNTHETIC" in md and "SYNTHETIC" in html and "GCP Cloud Posture Report" in html
    assert result.to_dict()["provider"] == "gcp"


def test_cli_gcp(tmp_path, capsys):
    fake = FakeGcpAdapter(firewalls=[_fw("ssh-open", ["22"])])
    args = ["--provider", "gcp", "--project", P, "--output", str(tmp_path), "--format", "json"]
    assert main(args + ["--fail-on", "HIGH"], gcp_adapter=fake) == 2
    assert main(args + ["--checks", "GCP-NET-001"], gcp_adapter=fake) == 0
    data = json.loads((tmp_path / "posture-report.json").read_text())
    assert data["provider"] == "gcp" and data["account_id"] == P
    assert main(["--provider", "gcp", "--list-checks"]) == 0
    assert "GCP-SQL-002" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["--provider", "gcp"], gcp_adapter=fake)


def test_cli_gcp_missing_credentials_is_clean_error(monkeypatch, tmp_path, capsys):
    from scanner.gcp import client

    class NoCreds:
        def __init__(self):
            raise client.GcpApiError("No GCP credentials found")

    monkeypatch.setattr(client, "GoogleApiAdapter", NoCreds)
    assert main(["--provider", "gcp", "--project", P, "--output", str(tmp_path)]) == 1
    assert "No GCP credentials" in capsys.readouterr().err
