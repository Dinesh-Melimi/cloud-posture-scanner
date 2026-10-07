"""In-memory ``GcpAdapter`` for tests and the synthetic sample report.

Holds plain dicts shaped like the GCP REST responses. No network, no credentials.
Set ``fail={"list_buckets": "403 ..."}`` to make a method raise ``GcpApiError``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scanner.gcp.client import GcpApiError


@dataclass
class FakeGcpAdapter:
    iam_policy: dict = field(default_factory=lambda: {"bindings": []})
    service_accounts: list[dict] = field(default_factory=list)
    sa_keys: dict[str, list[dict]] = field(default_factory=dict)  # email -> keys
    buckets: list[dict] = field(default_factory=list)
    bucket_policies: dict[str, dict] = field(default_factory=dict)  # name -> policy
    firewalls: list[dict] = field(default_factory=list)
    networks: list[dict] = field(default_factory=list)
    sql_instances: list[dict] = field(default_factory=list)
    kms_keys: list[dict] = field(default_factory=list)
    gke_clusters: list[dict] = field(default_factory=list)
    fail: dict[str, str] = field(default_factory=dict)

    def _guard(self, method: str):
        if method in self.fail:
            raise GcpApiError(self.fail[method])

    def get_project_iam_policy(self, project):
        self._guard("get_project_iam_policy")
        return self.iam_policy

    def list_service_accounts(self, project):
        self._guard("list_service_accounts")
        return self.service_accounts

    def list_service_account_keys(self, project, email):
        self._guard("list_service_account_keys")
        return self.sa_keys.get(email, [])

    def list_buckets(self, project):
        self._guard("list_buckets")
        return self.buckets

    def get_bucket_iam_policy(self, bucket):
        self._guard("get_bucket_iam_policy")
        return self.bucket_policies.get(bucket, {"bindings": []})

    def list_firewalls(self, project):
        self._guard("list_firewalls")
        return self.firewalls

    def list_networks(self, project):
        self._guard("list_networks")
        return self.networks

    def list_sql_instances(self, project):
        self._guard("list_sql_instances")
        return self.sql_instances

    def list_kms_keys(self, project):
        self._guard("list_kms_keys")
        return self.kms_keys

    def list_gke_clusters(self, project):
        self._guard("list_gke_clusters")
        return self.gke_clusters
