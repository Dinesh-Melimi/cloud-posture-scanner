"""GCP provider: checks mapped to the CIS Google Cloud Platform Foundation Benchmark.

Importing this package registers every GCP check in ``GCP_REGISTRY``. Checks talk to
GCP only through a ``GcpAdapter`` (see ``client.py``), so tests can swap in the
in-memory ``FakeGcpAdapter`` and never touch the network.
"""

from scanner.gcp import checks  # noqa: F401
from scanner.gcp.base import GCP_REGISTRY, GcpCheck, register_gcp
from scanner.gcp.client import GcpApiError

__all__ = ["GCP_REGISTRY", "GcpApiError", "GcpCheck", "register_gcp"]
