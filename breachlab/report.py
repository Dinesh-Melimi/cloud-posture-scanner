"""Incident report generator.

Turns a pipeline outcome into a Markdown report: an executive summary, the
attack timeline with ATT&CK mapping, what each detection caught, and the
containment actions taken. This is the artefact an on-call engineer would hand
to an incident channel.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .orchestrate import Outcome
from .scenario import build_scenario

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _coverage_table() -> list[str]:
    rows = ["| Step | Tactic | Technique | What happened |",
            "|---|---|---|---|"]
    for s in build_scenario():
        rows.append(f"| {s.title} | {s.tactic} | {s.technique} | {s.narrative} |")
    return rows


def render_markdown(outcome: Outcome) -> str:
    # Executive line wants the worst severity; the table below reads better in
    # time order, since it carries a timestamp column.
    by_sev = sorted(outcome.hits, key=lambda h: SEV_ORDER.get(h.severity, 9))
    top = by_sev[0].severity if by_sev else "NONE"
    hits = sorted(outcome.hits, key=lambda h: h.event.ts)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append("# Incident report: cloud account intrusion")
    lines.append("")
    lines.append(f"- **Generated:** {now}")
    lines.append(f"- **Highest severity:** {top}")
    lines.append(f"- **Detections fired:** {len(hits)}")
    lines.append(f"- **Containment actions taken:** {len(outcome.actions)}")
    lines.append("")
    lines.append("## What happened")
    lines.append("")
    lines.append(
        "A single exposed web application was used to reach the instance "
        "metadata service and steal the app server's role credentials. Those "
        "credentials were used from an outside IP to enumerate permissions, grant "
        "a deploy user full admin, open the customer-export bucket and begin "
        "downloading it. Detection-as-code caught the chain and automated "
        "containment cut it off.")
    lines.append("")

    lines.append("## Attack timeline (MITRE ATT&CK)")
    lines.append("")
    lines.extend(_coverage_table())
    lines.append("")

    lines.append("## Detections")
    lines.append("")
    if hits:
        lines.append("| Time | Rule | Severity | ATT&CK | Why it fired |")
        lines.append("|---|---|---|---|---|")
        for h in hits:
            t = h.event.ts.split("T")[-1][:8]
            lines.append(f"| {t} | {h.rule_id} {h.title} | {h.severity} | "
                         f"{h.technique} | {h.reason} |")
    else:
        lines.append("_No detections fired._")
    lines.append("")

    lines.append("## Containment")
    lines.append("")
    if outcome.actions:
        lines.append("| Time | Action | Target | Detail |")
        lines.append("|---|---|---|---|")
        for a in outcome.actions:
            t = a["ts"].split("T")[-1][:8]
            lines.append(f"| {t} | {a['name']} | {a['target']} | {a['detail']} |")
    else:
        lines.append("_No containment actions were taken._")
    lines.append("")

    lines.append("## Recommended follow-up")
    lines.append("")
    lines.extend([
        "- Patch the SSRF in the web app and require IMDSv2 (hop limit 1) on every "
        "instance so the metadata service cannot be reached through a proxied "
        "request.",
        "- Scope the app-server role down to only the APIs it needs.",
        "- Review the quarantined user's recent activity before re-enabling it.",
        "- Confirm the forensic snapshot is retained with the case.",
    ])
    lines.append("")
    return "\n".join(lines)
