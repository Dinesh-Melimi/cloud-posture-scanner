"""JSON, Markdown, and HTML report writers."""

from __future__ import annotations

import json
from pathlib import Path

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


WRITERS = {"json": to_json, "md": to_markdown, "html": to_html}


def write_reports(result: ScanResult, out_dir: Path, formats: list[str]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for fmt in formats:
        p = out_dir / f"posture-report.{fmt}"
        p.write_text(WRITERS[fmt](result), encoding="utf-8")
        paths.append(p)
    return paths
