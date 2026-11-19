"""Evaluate a host snapshot against a baseline; apply time-bound exceptions; compute compliance and drift."""
import json
from dataclasses import dataclass, asdict
from datetime import date


@dataclass
class Result:
    host: str
    id: str
    title: str
    severity: str
    expected: str
    actual: str
    status: str          # PASS | FAIL | EXCEPTION | EXPIRED_EXCEPTION
    cis: str
    nist: str
    note: str = ""


def _check(ctl, view):
    src = view.get(ctl["source"], {})
    actual = src.get(ctl["key"])
    if ctl.get("expect") == "absent":
        return actual is None, "absent" if actual is None else "present"
    if actual is None:
        return False, "not set"
    if "min" in ctl or "max" in ctl:
        try:
            n = float(actual)
        except ValueError:
            return False, actual
        ok = ("min" not in ctl or n >= ctl["min"]) and ("max" not in ctl or n <= ctl["max"])
        return ok, actual
    return str(actual).lower() == str(ctl["expect"]).lower(), actual


def _expected(ctl):
    if "min" in ctl and "max" in ctl:
        return f"{ctl['min']}-{ctl['max']}"
    if "min" in ctl:
        return f">= {ctl['min']}"
    if "max" in ctl:
        return f"<= {ctl['max']}"
    return ctl["expect"]


def evaluate(host, baseline, view, exceptions=(), today=None):
    today = today or date.today()
    exc = {(e["host"], e["control"]): e for e in exceptions}
    out = []
    for ctl in baseline["controls"]:
        ok, actual = _check(ctl, view)
        status, note = ("PASS", "") if ok else ("FAIL", "")
        e = exc.get((host, ctl["id"])) or exc.get(("*", ctl["id"]))
        if not ok and e:
            if date.fromisoformat(e["expires"]) >= today:
                status, note = "EXCEPTION", f"{e['reason']} | compensating: {e['compensating']} | owner {e['owner']} | expires {e['expires']}"
            else:
                status, note = "EXPIRED_EXCEPTION", f"exception expired {e['expires']}"
        out.append(Result(host, ctl["id"], ctl["title"], ctl["severity"], str(_expected(ctl)), str(actual), status, ctl["cis"], ctl["nist"], note))
    return out


def compliance(results):
    scored = [r for r in results if r.status != "EXCEPTION"]
    passed = sum(r.status == "PASS" for r in scored)
    return round(100 * passed / len(scored), 1) if scored else 100.0


def drift(previous, current):
    """Controls that were passing before and are failing now: configuration drift."""
    prev = {(r["host"], r["id"]): r["status"] for r in previous}
    return [r for r in current if prev.get((r.host, r.id)) == "PASS" and r.status in ("FAIL", "EXPIRED_EXCEPTION")]


def to_json(results):
    return [asdict(r) for r in results]
