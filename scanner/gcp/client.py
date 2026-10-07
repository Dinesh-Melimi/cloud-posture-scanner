"""Thin adapter between GCP checks and Google's REST APIs.

Checks depend only on the ``GcpAdapter`` protocol below. Every method returns
plain dicts shaped like the public REST API responses, so the production adapter
(``GoogleApiAdapter``, built on ``googleapiclient`` discovery) and the in-memory
test adapter (``scanner.gcp.fake.FakeGcpAdapter``) are interchangeable.

Every method is a read-only list/get call. The IAM permission each one needs is
noted in its docstring and collected in ``policies/gcp-scanner-role.yaml``.
"""

from __future__ import annotations

from typing import Protocol


class GcpApiError(Exception):
    """Raised by adapters for any API failure (403, 404, disabled API, auth error)."""


class GcpAdapter(Protocol):
    def get_project_iam_policy(self, project: str) -> dict:
        """resourcemanager.projects.getIamPolicy"""

    def list_service_accounts(self, project: str) -> list[dict]:
        """iam.serviceAccounts.list"""

    def list_service_account_keys(self, project: str, email: str) -> list[dict]:
        """iam.serviceAccountKeys.list (USER_MANAGED keys only)"""

    def list_buckets(self, project: str) -> list[dict]:
        """storage.buckets.list"""

    def get_bucket_iam_policy(self, bucket: str) -> dict:
        """storage.buckets.getIamPolicy"""

    def list_firewalls(self, project: str) -> list[dict]:
        """compute.firewalls.list"""

    def list_networks(self, project: str) -> list[dict]:
        """compute.networks.list"""

    def list_sql_instances(self, project: str) -> list[dict]:
        """cloudsql.instances.list"""

    def list_kms_keys(self, project: str) -> list[dict]:
        """cloudkms.locations.list, cloudkms.keyRings.list, cloudkms.cryptoKeys.list"""

    def list_gke_clusters(self, project: str) -> list[dict]:
        """container.clusters.list"""


class GoogleApiAdapter:
    """Production adapter using Application Default Credentials.

    Not exercised by the test suite (no live project is available); the request
    shapes follow the public discovery documents for each API version below.
    """

    def __init__(self, credentials=None):
        try:
            import google.auth
            from googleapiclient import discovery
            from googleapiclient.errors import HttpError
        except ImportError as exc:  # pragma: no cover
            raise GcpApiError(
                "GCP support needs google-api-python-client and google-auth "
                "(pip install -r requirements.txt)"
            ) from exc
        if credentials is None:
            try:
                credentials, _ = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
                )
            except google.auth.exceptions.DefaultCredentialsError as exc:
                raise GcpApiError(f"No GCP credentials found: {exc}") from exc
        self._discovery = discovery
        self._http_error = HttpError
        self._creds = credentials
        self._services: dict[tuple[str, str], object] = {}

    def _svc(self, name: str, version: str):
        key = (name, version)
        if key not in self._services:
            self._services[key] = self._discovery.build(
                name, version, credentials=self._creds, cache_discovery=False
            )
        return self._services[key]

    def _call(self, request):
        try:
            return request.execute()
        except self._http_error as exc:
            raise GcpApiError(str(exc)) from exc

    def _paged(self, collection, field: str, **kwargs) -> list[dict]:
        items: list[dict] = []
        request = collection.list(**kwargs)
        while request is not None:
            resp = self._call(request)
            items.extend(resp.get(field, []))
            request = collection.list_next(request, resp)
        return items

    def get_project_iam_policy(self, project: str) -> dict:
        crm = self._svc("cloudresourcemanager", "v1")
        return self._call(crm.projects().getIamPolicy(
            resource=project, body={"options": {"requestedPolicyVersion": 3}}))

    def list_service_accounts(self, project: str) -> list[dict]:
        sa = self._svc("iam", "v1").projects().serviceAccounts()
        return self._paged(sa, "accounts", name=f"projects/{project}")

    def list_service_account_keys(self, project: str, email: str) -> list[dict]:
        keys = self._svc("iam", "v1").projects().serviceAccounts().keys()
        resp = self._call(keys.list(name=f"projects/{project}/serviceAccounts/{email}",
                                    keyTypes="USER_MANAGED"))
        return resp.get("keys", [])

    def list_buckets(self, project: str) -> list[dict]:
        return self._paged(self._svc("storage", "v1").buckets(), "items", project=project)

    def get_bucket_iam_policy(self, bucket: str) -> dict:
        return self._call(self._svc("storage", "v1").buckets().getIamPolicy(bucket=bucket))

    def list_firewalls(self, project: str) -> list[dict]:
        return self._paged(self._svc("compute", "v1").firewalls(), "items", project=project)

    def list_networks(self, project: str) -> list[dict]:
        return self._paged(self._svc("compute", "v1").networks(), "items", project=project)

    def list_sql_instances(self, project: str) -> list[dict]:
        return self._paged(self._svc("sqladmin", "v1").instances(), "items", project=project)

    def list_kms_keys(self, project: str) -> list[dict]:
        locs = self._svc("cloudkms", "v1").projects().locations()
        keys: list[dict] = []
        for loc in self._paged(locs, "locations", name=f"projects/{project}"):
            for ring in self._paged(locs.keyRings(), "keyRings", parent=loc["name"]):
                keys.extend(self._paged(locs.keyRings().cryptoKeys(), "cryptoKeys",
                                        parent=ring["name"]))
        return keys

    def list_gke_clusters(self, project: str) -> list[dict]:
        clusters = self._svc("container", "v1").projects().locations().clusters()
        resp = self._call(clusters.list(parent=f"projects/{project}/locations/-"))
        return resp.get("clusters", [])
