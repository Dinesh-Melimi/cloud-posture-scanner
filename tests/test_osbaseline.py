import json
from datetime import date
from pathlib import Path

from osbaseline.collect import load_linux, load_windows
from osbaseline.evaluate import compliance, drift, evaluate, to_json

B = Path(__file__).resolve().parents[1] / "osbaseline"
LIN = json.loads((B / "baselines/linux_cis_l1.json").read_text())
WIN = json.loads((B / "baselines/windows_cis_l1.json").read_text())
EXC = json.loads((B / "samples/exceptions.json").read_text())


def test_hardened_linux_fully_compliant():
    r = evaluate("linux-web01", LIN, load_linux(B / "samples/linux-web01"))
    assert compliance(r) == 100.0


def test_weak_linux_flags_root_login_and_telnet():
    r = {x.id: x.status for x in evaluate("linux-db01", LIN, load_linux(B / "samples/linux-db01"))}
    assert r["LNX-SSH-01"] == "FAIL" and r["LNX-SVC-01"] == "FAIL" and r["LNX-KRN-01"] == "PASS"


def test_windows_exception_applied_and_excluded_from_score():
    r = evaluate(
        "win-app01", WIN, load_windows(B / "samples/win-app01.json"), EXC, today=date(2026, 11, 20)
    )
    smb = next(x for x in r if x.id == "WIN-SMB-01")
    assert smb.status == "EXCEPTION" and "compensating" in smb.note


def test_expired_exception_counts_as_failure():
    r = evaluate(
        "win-app01", WIN, load_windows(B / "samples/win-app01.json"), EXC, today=date(2027, 6, 1)
    )
    assert next(x for x in r if x.id == "WIN-SMB-01").status == "EXPIRED_EXCEPTION"


def test_hardened_dc_compliant():
    assert compliance(evaluate("win-dc01", WIN, load_windows(B / "samples/win-dc01.json"))) == 100.0


def test_drift_detected():
    good = to_json(evaluate("h", LIN, load_linux(B / "samples/linux-web01")))
    bad = evaluate("h", LIN, load_linux(B / "samples/linux-db01"))
    ids = {r.id for r in drift(good, bad)}
    assert "LNX-SSH-01" in ids and "LNX-KRN-01" not in ids
