import json

from botocore.exceptions import ClientError

from scanner.checks import REGISTRY
from scanner.checks.base import BaseCheck
from scanner.cli import main
from scanner.engine import run_scan
from scanner.models import Severity, Status
from scanner.report import to_html, to_markdown, write_reports


def test_registry_has_twelve_checks_with_metadata():
    assert len(REGISTRY) == 12
    for cid, cls in REGISTRY.items():
        assert cls.check_id == cid
        assert cls.cis_ref and cls.title and cls.remediation
        assert isinstance(cls.severity, Severity)


def test_full_scan_noncompliant_account(session, tmp_path):
    session.client("s3").create_bucket(Bucket="exposed")
    result = run_scan(session, ["us-east-1"])
    s = result.summary()
    assert s["total"] == len(result.findings) and s["failed"] > 0 and s["errors"] == 0
    paths = write_reports(result, tmp_path, ["json", "md", "html"])
    data = json.loads(paths[0].read_text())
    assert data["account_id"] == "123456789012"
    assert "## Remediation" in paths[1].read_text()
    assert "<table>" in paths[2].read_text()


def test_html_escapes_resource_names(session):
    result = run_scan(session, ["us-east-1"], include=["IAM-001"])
    result.findings[0].resource = "<script>alert(1)</script>"
    html = to_html(result)
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    assert "IAM-001" in to_markdown(result)


def test_api_error_becomes_error_finding(session, monkeypatch):
    def boom(self):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "Op")

    monkeypatch.setattr(REGISTRY["IAM-003"], "run", boom)
    result = run_scan(session, ["us-east-1"], include=["IAM-003", "IAM-002"])
    by_id = {f.check_id: f.status for f in result.findings}
    assert by_id == {"IAM-003": Status.ERROR, "IAM-002": Status.PASS}


def test_cli_fail_on_gate(session, tmp_path, capsys):
    rc = main(["--checks", "IAM-001", "--output", str(tmp_path), "--fail-on", "CRITICAL"])
    assert rc == 2
    rc = main(["--checks", "IAM-002", "--output", str(tmp_path), "--fail-on", "CRITICAL"])
    assert rc == 0
    assert main(["--list-checks"]) == 0
    assert "KMS-001" in capsys.readouterr().out


def test_base_check_is_abstract():
    assert getattr(BaseCheck.run, "__isabstractmethod__", False)
