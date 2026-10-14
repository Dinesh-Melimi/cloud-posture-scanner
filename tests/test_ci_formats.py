import json
import xml.etree.ElementTree as ET

from scanner.cli import main
from scanner.engine import run_scan
from scanner.report import to_junit, to_sarif


def test_sarif_has_rules_and_failed_results(session):
    session.client("s3").create_bucket(Bucket="exposed")
    result = run_scan(session, ["us-east-1"])
    doc = json.loads(to_sarif(result))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    fails = [f for f in result.findings if f.status.value == "FAIL"]
    assert len(run["results"]) == len(fails) > 0
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert all(r["level"] in ("error", "warning", "note") for r in run["results"])
    fps = [r["partialFingerprints"]["resource/v1"] for r in run["results"]]
    assert len(fps) == len(set(fps))  # stable, unique fingerprints for dedup across builds


def test_junit_counts_match_summary_and_escape(session):
    session.client("s3").create_bucket(Bucket="exposed")
    result = run_scan(session, ["us-east-1"])
    result.findings[0].resource = 'bad"<name>&'
    root = ET.fromstring(to_junit(result))  # noqa: S314 - our own output in a test
    suite = root.find("testsuite")
    s = result.summary()
    assert int(suite.get("tests")) == s["total"] == len(suite.findall("testcase"))
    assert int(suite.get("failures")) == s["failed"] == len(suite.findall("testcase/failure"))
    assert any('bad"<name>&' in tc.get("name") for tc in suite.findall("testcase"))


def test_cli_writes_ci_formats(session, tmp_path, monkeypatch):
    import scanner.cli as cli
    monkeypatch.setattr(cli, "_scan", lambda args, adapter: run_scan(session, ["us-east-1"]))
    rc = main(["--format", "sarif,junit", "--output", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "posture-report.sarif").exists()
    assert (tmp_path / "posture-report.xml").exists()
