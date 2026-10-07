"""GCP controls mapped to the CIS Google Cloud Platform Foundation Benchmark (v2.0
numbering) and, for GKE, the CIS Google Kubernetes Engine Benchmark.

Each check reads state through ``self.gcp`` (a ``GcpAdapter``) and never writes.
"""

from __future__ import annotations

from datetime import datetime, timezone

from scanner.gcp.base import GcpCheck, register_gcp
from scanner.models import Finding, Severity

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
OPEN_RANGES = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
MAX_KEY_AGE_DAYS = 90
MAX_ROTATION_SECONDS = 90 * 24 * 3600


def _bindings(policy: dict):
    for b in policy.get("bindings", []) or []:
        yield b.get("role", ""), b.get("members", []) or []


def _is_admin_role(role: str) -> bool:
    return role in PRIMITIVE_ROLES or role.endswith("Admin") or role.endswith(".admin")


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _location_of(resource_name: str) -> str:
    parts = resource_name.split("/")
    return parts[parts.index("locations") + 1] if "locations" in parts else "global"


# ---------------------------------------------------------------- IAM

@register_gcp
class GcpPrimitiveRoles(GcpCheck):
    check_id = "GCP-IAM-001"
    title = "No primitive Owner/Editor roles granted to users or service accounts at project level"
    cis_ref = "CIS GCP 1.5 (extended to users)"
    severity = Severity.HIGH
    remediation = (
        "gcloud projects remove-iam-policy-binding <project> --member=<member> --role=roles/editor "
        "and grant a narrower predefined role instead"
    )

    def run(self) -> list[Finding]:
        policy = self.gcp.get_project_iam_policy(self.project)
        out = []
        for role, members in _bindings(policy):
            if role not in PRIMITIVE_ROLES:
                continue
            for m in members:
                if m.startswith(("user:", "serviceAccount:")):
                    out.append(self.failed(m, f"Granted primitive role {role} on the project."))
        if not out:
            out.append(self.passed(self.project, "No users or service accounts hold Owner/Editor."))
        return out


@register_gcp
class GcpServiceAccountAdmin(GcpCheck):
    check_id = "GCP-IAM-002"
    title = "Service accounts do not hold admin privileges"
    cis_ref = "CIS GCP 1.5"
    severity = Severity.HIGH
    remediation = (
        "gcloud projects remove-iam-policy-binding <project> "
        "--member=serviceAccount:<email> --role=<admin role>"
    )

    def run(self) -> list[Finding]:
        policy = self.gcp.get_project_iam_policy(self.project)
        admin: dict[str, list[str]] = {}
        for role, members in _bindings(policy):
            if not _is_admin_role(role):
                continue
            for m in members:
                if m.startswith("serviceAccount:"):
                    admin.setdefault(m.split(":", 1)[1], []).append(role)
        out = []
        for sa in self.gcp.list_service_accounts(self.project):
            email = sa["email"]
            roles = admin.pop(email, None)
            if roles:
                out.append(self.failed(email, f"Holds admin role(s): {', '.join(sorted(roles))}."))
            else:
                out.append(self.passed(email, "No admin roles at project level."))
        # Service accounts from other projects that were granted admin here.
        for email, roles in sorted(admin.items()):
            out.append(self.failed(email, f"External SA holds admin role(s): {', '.join(sorted(roles))}."))
        if not out:
            out.append(self.passed(self.project, "No service accounts found."))
        return out


@register_gcp
class GcpServiceAccountKeyAge(GcpCheck):
    check_id = "GCP-IAM-003"
    title = "User-managed service account keys are rotated within 90 days"
    cis_ref = "CIS GCP 1.7"
    severity = Severity.MEDIUM
    remediation = (
        "gcloud iam service-accounts keys create new.json --iam-account=<email>; switch callers; "
        "gcloud iam service-accounts keys delete <key-id> --iam-account=<email>. "
        "Prefer Workload Identity / impersonation over keys."
    )

    def __init__(self, adapter, project: str, now: datetime | None = None):
        super().__init__(adapter, project)
        self.now = now or datetime.now(timezone.utc)

    def run(self) -> list[Finding]:
        out = []
        for sa in self.gcp.list_service_accounts(self.project):
            email = sa["email"]
            for key in self.gcp.list_service_account_keys(self.project, email):
                if key.get("keyType", "USER_MANAGED") != "USER_MANAGED" or key.get("disabled"):
                    continue
                key_id = key["name"].rsplit("/", 1)[-1]
                age = (self.now - _parse_ts(key["validAfterTime"])).days
                res = f"{email}/{key_id}"
                if age > MAX_KEY_AGE_DAYS:
                    out.append(self.failed(res, f"User-managed key is {age} days old."))
                else:
                    out.append(self.passed(res, f"User-managed key is {age} days old."))
        if not out:
            out.append(self.passed(self.project, "No active user-managed service account keys."))
        return out


# ---------------------------------------------------------------- Logging

@register_gcp
class GcpDataAccessAuditLogs(GcpCheck):
    check_id = "GCP-LOG-001"
    title = "Cloud Audit Logs Data Access logging enabled for all services"
    cis_ref = "CIS GCP 2.1"
    severity = Severity.MEDIUM
    remediation = (
        "gcloud projects get-iam-policy <project> > p.yaml; add auditConfigs for service "
        "allServices with ADMIN_READ, DATA_READ, DATA_WRITE and no exemptedMembers; "
        "gcloud projects set-iam-policy <project> p.yaml"
    )
    required = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}

    def run(self) -> list[Finding]:
        policy = self.gcp.get_project_iam_policy(self.project)
        for cfg in policy.get("auditConfigs", []) or []:
            if cfg.get("service") != "allServices":
                continue
            logs = cfg.get("auditLogConfigs", []) or []
            types = {c.get("logType") for c in logs}
            exempt = sorted({m for c in logs for m in c.get("exemptedMembers", []) or []})
            missing = self.required - types
            if missing:
                return [self.failed(self.project, f"allServices audit config missing {sorted(missing)}.")]
            if exempt:
                return [self.failed(self.project, f"Audit logging exempts members: {', '.join(exempt)}.")]
            return [self.passed(self.project, "Data Access logs enabled for allServices, no exemptions.")]
        return [self.failed(self.project, "No allServices audit config; Data Access logs are off.")]


# ---------------------------------------------------------------- Networking

@register_gcp
class GcpDefaultNetwork(GcpCheck):
    check_id = "GCP-NET-001"
    title = "The default VPC network does not exist"
    cis_ref = "CIS GCP 3.1"
    severity = Severity.MEDIUM
    remediation = "Move workloads to a custom VPC, then: gcloud compute networks delete default"

    def run(self) -> list[Finding]:
        names = {n.get("name") for n in self.gcp.list_networks(self.project)}
        if "default" in names:
            return [self.failed("default", "Default network (with permissive pre-built rules) exists.")]
        return [self.passed(self.project, "No default network.")]


def _port_exposed(allowed: list[dict], port: int) -> bool:
    for rule in allowed or []:
        proto = str(rule.get("IPProtocol", "")).lower()
        if proto not in ("tcp", "all", "6"):
            continue
        ports = rule.get("ports")
        if not ports:  # no ports listed means every port
            return True
        for p in ports:
            lo, _, hi = str(p).partition("-")
            if int(lo) <= port <= int(hi or lo):
                return True
    return False


@register_gcp
class GcpFirewallAdminPorts(GcpCheck):
    check_id = "GCP-NET-002"
    title = "No firewall rule allows 0.0.0.0/0 to SSH (22) or RDP (3389)"
    cis_ref = "CIS GCP 3.6, 3.7"
    severity = Severity.HIGH
    remediation = (
        "gcloud compute firewall-rules update <rule> --source-ranges=<trusted CIDR> "
        "(or delete it and use IAP TCP forwarding: 35.235.240.0/20)"
    )

    def run(self) -> list[Finding]:
        out = []
        for fw in self.gcp.list_firewalls(self.project):
            if fw.get("direction", "INGRESS") != "INGRESS" or fw.get("disabled"):
                continue
            name = fw["name"]
            if not OPEN_RANGES & set(fw.get("sourceRanges", []) or []):
                out.append(self.passed(name, "Source ranges are restricted."))
                continue
            exposed = [f"{svc}/{p}" for p, svc in ADMIN_PORTS.items()
                       if _port_exposed(fw.get("allowed", []), p)]
            if exposed:
                out.append(self.failed(name, f"Open to the internet on {', '.join(exposed)}."))
            else:
                out.append(self.passed(name, "Internet-facing, but not on 22/3389."))
        if not out:
            out.append(self.passed(self.project, "No enabled ingress firewall rules."))
        return out


# ---------------------------------------------------------------- Cloud Storage

@register_gcp
class GcpPublicBuckets(GcpCheck):
    check_id = "GCP-GCS-001"
    title = "Cloud Storage buckets are not anonymously or publicly accessible"
    cis_ref = "CIS GCP 5.1"
    severity = Severity.CRITICAL
    remediation = (
        "gcloud storage buckets remove-iam-policy-binding gs://<bucket> --member=allUsers --role=<role>; "
        "enforce the constraints/storage.publicAccessPrevention org policy"
    )

    def run(self) -> list[Finding]:
        out = []
        for b in self.gcp.list_buckets(self.project):
            name, loc = b["name"], b.get("location", "global").lower()
            pap = (b.get("iamConfiguration") or {}).get("publicAccessPrevention")
            public = sorted({f"{m} -> {role}" for role, members in
                             _bindings(self.gcp.get_bucket_iam_policy(name))
                             for m in members if m in PUBLIC_MEMBERS})
            if public and pap != "enforced":
                out.append(self.failed(name, f"Public IAM bindings: {'; '.join(public)}.", loc))
            else:
                out.append(self.passed(name, "No allUsers/allAuthenticatedUsers bindings in effect.", loc))
        if not out:
            out.append(self.passed(self.project, "No buckets found."))
        return out


@register_gcp
class GcpUniformBucketAccess(GcpCheck):
    check_id = "GCP-GCS-002"
    title = "Cloud Storage buckets have uniform bucket-level access enabled"
    cis_ref = "CIS GCP 5.2"
    severity = Severity.MEDIUM
    remediation = "gcloud storage buckets update gs://<bucket> --uniform-bucket-level-access"

    def run(self) -> list[Finding]:
        out = []
        for b in self.gcp.list_buckets(self.project):
            name, loc = b["name"], b.get("location", "global").lower()
            ubla = ((b.get("iamConfiguration") or {}).get("uniformBucketLevelAccess") or {})
            if ubla.get("enabled"):
                out.append(self.passed(name, "Uniform bucket-level access enabled; ACLs disabled.", loc))
            else:
                out.append(self.failed(name, "Fine-grained object ACLs are still active.", loc))
        if not out:
            out.append(self.passed(self.project, "No buckets found."))
        return out


# ---------------------------------------------------------------- Cloud SQL

def _sql_ip_cfg(inst: dict) -> dict:
    return (inst.get("settings") or {}).get("ipConfiguration") or {}


@register_gcp
class GcpSqlPublicIp(GcpCheck):
    check_id = "GCP-SQL-001"
    title = "Cloud SQL instances do not have public IP addresses"
    cis_ref = "CIS GCP 6.6"
    severity = Severity.HIGH
    remediation = (
        "Configure private IP (Private Services Access), then: "
        "gcloud sql instances patch <instance> --no-assign-ip"
    )

    def run(self) -> list[Finding]:
        out = []
        for inst in self.gcp.list_sql_instances(self.project):
            name, loc = inst["name"], inst.get("region", "global")
            has_public = _sql_ip_cfg(inst).get("ipv4Enabled") or any(
                a.get("type") == "PRIMARY" for a in inst.get("ipAddresses", []) or [])
            if has_public:
                nets = [n.get("value") for n in _sql_ip_cfg(inst).get("authorizedNetworks", []) or []]
                extra = " Authorized networks include 0.0.0.0/0." if "0.0.0.0/0" in nets else ""
                out.append(self.failed(name, f"Instance has a public IPv4 address.{extra}", loc))
            else:
                out.append(self.passed(name, "Private IP only.", loc))
        if not out:
            out.append(self.passed(self.project, "No Cloud SQL instances found."))
        return out


@register_gcp
class GcpSqlRequireSsl(GcpCheck):
    check_id = "GCP-SQL-002"
    title = "Cloud SQL instances require SSL/TLS for incoming connections"
    cis_ref = "CIS GCP 6.4"
    severity = Severity.HIGH
    remediation = "gcloud sql instances patch <instance> --ssl-mode=ENCRYPTED_ONLY"
    secure_modes = {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}

    def run(self) -> list[Finding]:
        out = []
        for inst in self.gcp.list_sql_instances(self.project):
            name, loc = inst["name"], inst.get("region", "global")
            cfg = _sql_ip_cfg(inst)
            mode = cfg.get("sslMode")
            ok = mode in self.secure_modes if mode else bool(cfg.get("requireSsl"))
            if ok:
                out.append(self.passed(name, f"TLS required ({mode or 'requireSsl=true'}).", loc))
            else:
                detail = mode or "requireSsl=false"
                out.append(self.failed(name, f"Unencrypted connections allowed ({detail}).", loc))
        if not out:
            out.append(self.passed(self.project, "No Cloud SQL instances found."))
        return out


# ---------------------------------------------------------------- KMS

@register_gcp
class GcpKmsRotation(GcpCheck):
    check_id = "GCP-KMS-001"
    title = "Cloud KMS symmetric keys rotate at least every 90 days"
    cis_ref = "CIS GCP 1.10"
    severity = Severity.MEDIUM
    remediation = (
        "gcloud kms keys update <key> --keyring=<ring> --location=<loc> "
        "--rotation-period=90d --next-rotation-time=<RFC3339>"
    )

    def run(self) -> list[Finding]:
        out = []
        for key in self.gcp.list_kms_keys(self.project):
            if key.get("purpose", "ENCRYPT_DECRYPT") != "ENCRYPT_DECRYPT":
                continue  # asymmetric keys cannot auto-rotate
            if (key.get("primary") or {}).get("state", "ENABLED") != "ENABLED":
                continue
            name = key["name"]
            loc = _location_of(name)
            period = key.get("rotationPeriod")
            if not period:
                out.append(self.failed(name, "No automatic rotation schedule.", loc))
                continue
            seconds = float(period.rstrip("s"))
            days = round(seconds / 86400, 1)
            if seconds <= MAX_ROTATION_SECONDS:
                out.append(self.passed(name, f"Rotates every {days:g} days.", loc))
            else:
                out.append(self.failed(name, f"Rotates every {days:g} days (> 90).", loc))
        if not out:
            out.append(self.passed(self.project, "No enabled symmetric KMS keys found."))
        return out


# ---------------------------------------------------------------- GKE

@register_gcp
class GcpGkePrivateNodes(GcpCheck):
    check_id = "GCP-GKE-001"
    title = "GKE clusters use private nodes"
    cis_ref = "CIS GKE 5.6.5"
    severity = Severity.MEDIUM
    remediation = (
        "gcloud container clusters update <cluster> --location=<loc> --enable-private-nodes "
        "(older clusters may need re-creation with --enable-private-nodes)"
    )

    def run(self) -> list[Finding]:
        out = []
        for c in self.gcp.list_gke_clusters(self.project):
            name, loc = c["name"], c.get("location", "global")
            private = ((c.get("privateClusterConfig") or {}).get("enablePrivateNodes")
                       or ((c.get("networkConfig") or {}).get("defaultEnablePrivateNodes")))
            if private:
                out.append(self.passed(name, "Nodes have internal IPs only.", loc))
            else:
                out.append(self.failed(name, "Nodes have public IP addresses.", loc))
        if not out:
            out.append(self.passed(self.project, "No GKE clusters found."))
        return out


@register_gcp
class GcpGkeLegacyAbac(GcpCheck):
    check_id = "GCP-GKE-002"
    title = "GKE legacy authorization (ABAC) is disabled"
    cis_ref = "CIS GKE 5.8.3"
    severity = Severity.HIGH
    remediation = (
        "gcloud container clusters update <cluster> --location=<loc> --no-enable-legacy-authorization"
    )

    def run(self) -> list[Finding]:
        out = []
        for c in self.gcp.list_gke_clusters(self.project):
            name, loc = c["name"], c.get("location", "global")
            if (c.get("legacyAbac") or {}).get("enabled"):
                out.append(self.failed(name, "Legacy ABAC enabled; RBAC can be bypassed.", loc))
            else:
                out.append(self.passed(name, "Legacy ABAC disabled; RBAC only.", loc))
        if not out:
            out.append(self.passed(self.project, "No GKE clusters found."))
        return out
