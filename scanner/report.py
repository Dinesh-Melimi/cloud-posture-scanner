"""JSON, Markdown, HTML, SARIF, and JUnit report writers."""

from __future__ import annotations

import json
from pathlib import Path

# xml.sax.saxutils is used only to escape our own output, never to parse XML.
from xml.sax.saxutils import escape, quoteattr  # nosec B406

from jinja2 import Environment, PackageLoader

from scanner.models import ScanResult, Severity, Status

SEV_ORDER = {s.value: i for i, s in enumerate(Severity)}


def _sorted(result: ScanResult):
    return sorted(
        result.findings,
        key=lambda f: (f.status != Status.FAIL, SEV_ORDER[f.severity.value], f.check_id),
    )


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


PROVIDER_LABELS = {"aws": ("AWS", "Account", "Regions"), "gcp": ("GCP", "Project", "Locations")}


def labels(result: ScanResult) -> tuple[str, str, str]:
    return PROVIDER_LABELS.get(result.provider, PROVIDER_LABELS["aws"])


def to_markdown(result: ScanResult) -> str:
    s = result.summary()
    name, acct, regions = labels(result)
    lines = [f"# {name} Cloud Posture Report", ""]
    if result.note:
        lines += [f"> **{result.note}**", ""]
    lines += [
        f"- **{acct}:** {result.account_id}",
        f"- **{regions}:** {', '.join(result.regions)}",
        f"- **Scanned at:** {result.started_at}",
        (f"- **Score:** {s['score']}% ({s['passed']}/{s['total']} passed, "
         f"{s['failed']} failed, {s['errors']} errors)"),
        "",
        "## Severity summary",
        "",
        "| Severity | Fail | Pass | Error |",
        "|---|---|---|---|",
    ]
    for sev, c in s["by_severity"].items():
        lines.append(f"| {sev} | {c['FAIL']} | {c['PASS']} | {c['ERROR']} |")
    lines += ["", "## Findings", "",
              "| Status | Severity | ID | CIS | Resource | Region | Detail |",
              "|---|---|---|---|---|---|---|"]
    for f in _sorted(result):
        msg = f.message.replace("|", "\\|")
        lines.append(f"| {f.status.value} | {f.severity.value} | {f.check_id} | {f.cis_ref} | "
                     f"{f.resource} | {f.region} | {msg} |")
    fails = [f for f in _sorted(result) if f.status == Status.FAIL]
    if fails:
        lines += ["", "## Remediation", ""]
        seen = set()
        for f in fails:
            if f.check_id in seen:
                continue
            seen.add(f.check_id)
            lines += [f"### {f.check_id} - {f.title}", "", f"`{f.remediation}`", ""]
    return "\n".join(lines) + "\n"


def to_html(result: ScanResult) -> str:
    env = Environment(
        loader=PackageLoader("scanner", "templates"),
        autoescape=True,  # always escape: resource names are untrusted input
    )
    return env.get_template("report.html.j2").render(
        r=result, s=result.summary(), findings=_sorted(result), labels=labels(result)
    )


SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
SARIF_SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0"}


def to_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 for GitHub code scanning, GitLab, Azure DevOps, and Jenkins Warnings NG."""
    fails = [f for f in _sorted(result) if f.status == Status.FAIL]
    rules, seen = [], set()
    for f in result.findings:
        if f.check_id in seen:
            continue
        seen.add(f.check_id)
        rules.append({
            "id": f.check_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "help": {"text": f.remediation},
            "properties": {"tags": ["security", "cloud", f"CIS {f.cis_ref}"],
                           "security-severity": SARIF_SCORE[f.severity.value]},
        })
    results = [{
        "ruleId": f.check_id,
        "level": SARIF_LEVEL[f.severity.value],
        "message": {"text": f"{f.message} Remediation: {f.remediation}"},
        "locations": [{
            "logicalLocations": [{"fullyQualifiedName": f.resource, "kind": "resource"}],
            "physicalLocation": {"artifactLocation": {"uri": f"{result.provider}/{f.region}/{f.resource}"}},
        }],
        "partialFingerprints": {"resource/v1": f"{f.check_id}:{f.region}:{f.resource}"},
    } for f in fails]
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "cloud-posture-scanner", "rules": rules}},
                     "results": results}]}
    return json.dumps(doc, indent=2)


def to_junit(result: ScanResult) -> str:
    """JUnit XML: each check on each resource is a test case, so Jenkins and GitLab show
    failed controls in their native test report views and trend them across builds."""
    s = result.summary()
    name, acct, _ = labels(result)
    cases = []
    for f in _sorted(result):
        cls, case = quoteattr(f"{name}.{f.check_id}"), quoteattr(f"{f.resource} ({f.region})")
        attrs = f"classname={cls} name={case}"
        if f.status == Status.FAIL:
            body = (f"<failure type={quoteattr(f.severity.value)} message={quoteattr(f.message)}>"
                    f"{escape(f'CIS {f.cis_ref}: {f.remediation}')}</failure>")
        elif f.status == Status.ERROR:
            body = f"<error message={quoteattr(f.message)}/>"
        else:
            body = ""
        cases.append(f"    <testcase {attrs}>{body}</testcase>")
    suite_name = quoteattr(f"{name} posture {acct} {result.account_id}")
    suite = (f'  <testsuite name={suite_name} '
             f'tests="{s["total"]}" failures="{s["failed"]}" errors="{s["errors"]}">')
    return "\n".join(['<?xml version="1.0" encoding="UTF-8"?>', "<testsuites>", suite, *cases,
                      "  </testsuite>", "</testsuites>"]) + "\n"


WRITERS = {"json": to_json, "md": to_markdown, "html": to_html, "sarif": to_sarif, "junit": to_junit}


def write_reports(result: ScanResult, out_dir: Path, formats: list[str]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for fmt in formats:
        p = out_dir / f"posture-report.{'xml' if fmt == 'junit' else fmt}"
        p.write_text(WRITERS[fmt](result), encoding="utf-8")
        paths.append(p)
    return paths
