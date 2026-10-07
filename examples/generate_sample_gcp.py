"""Generate the SYNTHETIC GCP sample report in examples/sample-report-gcp/.

Uses the in-memory FakeGcpAdapter. No GCP project, API, or credential is involved;
every resource below is invented to populate each report section.

    PYTHONPATH=. python examples/generate_sample_gcp.py
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from scanner.engine import run_gcp_scan
from scanner.gcp.fake import FakeGcpAdapter
from scanner.report import write_reports

P = "acme-synthetic-demo"
SA = f"etl@{P}.iam.gserviceaccount.com"
WEB_SA = f"web@{P}.iam.gserviceaccount.com"
now = datetime.now(timezone.utc)


def ts(days):
    return (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def bucket(name, ubla):
    return {"name": name, "location": "US-CENTRAL1", "iamConfiguration": {
        "uniformBucketLevelAccess": {"enabled": ubla}, "publicAccessPrevention": "inherited"}}


fake = FakeGcpAdapter(
    iam_policy={"bindings": [
        {"role": "roles/editor", "members": ["user:contractor@example.com", f"serviceAccount:{SA}"]},
        {"role": "roles/owner", "members": ["group:platform-admins@example.com"]},
        {"role": "roles/storage.objectViewer", "members": [f"serviceAccount:{WEB_SA}"]},
    ], "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}]}]},
    service_accounts=[{"email": SA}, {"email": WEB_SA}],
    sa_keys={SA: [{"name": f"projects/{P}/serviceAccounts/{SA}/keys/3f9a1c", "validAfterTime": ts(214),
                   "keyType": "USER_MANAGED"}],
             WEB_SA: [{"name": f"projects/{P}/serviceAccounts/{WEB_SA}/keys/b71e02",
                       "validAfterTime": ts(12), "keyType": "USER_MANAGED"}]},
    buckets=[bucket("acme-public-assets", False), bucket("acme-audit-logs", True)],
    bucket_policies={"acme-public-assets": {"bindings": [
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}},
    networks=[{"name": "default"}, {"name": "prod-vpc"}],
    firewalls=[
        {"name": "default-allow-ssh", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
         "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
        {"name": "allow-iap-admin", "direction": "INGRESS", "sourceRanges": ["35.235.240.0/20"],
         "allowed": [{"IPProtocol": "tcp", "ports": ["22", "3389"]}]},
        {"name": "allow-https", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
         "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
    ],
    sql_instances=[
        {"name": "orders-db", "region": "us-central1",
         "ipAddresses": [{"type": "PRIMARY", "ipAddress": "203.0.113.10"}],
         "settings": {"ipConfiguration": {"ipv4Enabled": True, "sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
                                          "authorizedNetworks": [{"value": "0.0.0.0/0"}]}}},
        {"name": "analytics-db", "region": "us-central1",
         "ipAddresses": [{"type": "PRIVATE", "ipAddress": "10.10.0.3"}],
         "settings": {"ipConfiguration": {"ipv4Enabled": False, "sslMode": "ENCRYPTED_ONLY"}}},
    ],
    kms_keys=[
        {"name": f"projects/{P}/locations/us-central1/keyRings/app/cryptoKeys/app-data",
         "purpose": "ENCRYPT_DECRYPT", "primary": {"state": "ENABLED"}, "rotationPeriod": "7776000s"},
        {"name": f"projects/{P}/locations/us-central1/keyRings/app/cryptoKeys/legacy-key",
         "purpose": "ENCRYPT_DECRYPT", "primary": {"state": "ENABLED"}},
    ],
    gke_clusters=[
        {"name": "prod-gke", "location": "us-central1",
         "privateClusterConfig": {"enablePrivateNodes": True}, "legacyAbac": {}},
        {"name": "sandbox-gke", "location": "us-central1-a", "legacyAbac": {"enabled": True}},
    ],
)

result = run_gcp_scan(fake, P)
result.note = ("SYNTHETIC SAMPLE: generated from an in-memory fake adapter "
               "(examples/generate_sample_gcp.py). No real GCP project was scanned.")
out = Path(__file__).parent / "sample-report-gcp"
for p in write_reports(result, out, ["json", "md", "html"]):
    print("wrote", p)
