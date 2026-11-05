"""Command line for the breach lab.

    python -m breachlab replay            # print the attack timeline
    python -m breachlab detect            # run detections, show what fired
    python -m breachlab baseline          # prove the benign day is quiet
    python -m breachlab run                # full detect + contain + report
    python -m breachlab run --report out.md

The `run` command is what the demo records: it narrates each stage as it goes.
"""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .baseline import baseline_events
from .detections import run_rules
from .events import dump_events
from .orchestrate import run_pipeline
from .report import render_markdown
from .scenario import build_scenario, scenario_events

BAR = "=" * 70


def _say(msg: str, pause: float) -> None:
    print(msg)
    if pause:
        time.sleep(pause)


def cmd_replay(args: argparse.Namespace) -> int:
    for s in build_scenario():
        print(f"[{s.technique}] {s.title}  ({s.tactic})")
        print(f"    {s.narrative}")
        for e in s.events:
            print(f"      - {e.ts}  {e.source:10} {e.name}")
    if args.out:
        dump_events(scenario_events(), args.out)
        print(f"\nTimeline written to {args.out}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    hits = run_rules(scenario_events())
    print(f"{len(hits)} detections fired:\n")
    for h in hits:
        print(f"  {h.severity:8} {h.rule_id}  {h.title}  [{h.technique}]")
        print(f"           {h.reason}")
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    hits = run_rules(baseline_events())
    if hits:
        print(f"FAIL: benign baseline raised {len(hits)} false positive(s):")
        for h in hits:
            print(f"  {h.rule_id} {h.title}: {h.reason}")
        return 1
    print("OK: benign baseline produced 0 detections (no false positives).")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    pause = 0.0 if args.fast else args.pace

    _say(BAR, 0)
    _say("CLOUD BREACH LAB  -  detect and respond", pause)
    _say(BAR + "\n", pause)

    _say(">> Stage 1  Replaying the attack telemetry\n", pause)
    for s in build_scenario():
        _say(f"   [{s.technique}] {s.title}", pause)
    print()

    _say(">> Stage 2  Running detection-as-code\n", pause)
    outcome = run_pipeline()
    for h in sorted(outcome.hits, key=lambda x: x.event.ts):
        _say(f"   ALERT {h.severity:8} {h.rule_id} {h.title} [{h.technique}]", pause)
    _say(f"\n   {len(outcome.hits)} detections fired.\n", pause)

    _say(">> Stage 3  Automated containment (real boto3 on a simulated account)\n",
         pause)
    for a in outcome.actions:
        _say(f"   DID  {a['name']}  ->  {a['target']}", pause)
    _say(f"\n   {len(outcome.actions)} containment actions taken.\n", pause)

    _say(">> Stage 4  Incident report", pause)
    md = render_markdown(outcome)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(md)
        _say(f"   Written to {args.report}", 0)
    else:
        print("\n" + md)

    _say("\n" + BAR, 0)
    _say("Done. Attack contained; report ready.", 0)
    _say(BAR, 0)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="breachlab",
                                description="Cloud breach detection-and-response lab")
    p.add_argument("--version", action="version", version=f"breachlab {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("replay", help="print the attack timeline")
    pr.add_argument("--out", help="also write the timeline to a JSONL file")
    pr.set_defaults(func=cmd_replay)

    pd = sub.add_parser("detect", help="run detections over the attack timeline")
    pd.set_defaults(func=cmd_detect)

    pb = sub.add_parser("baseline", help="run detections over benign telemetry")
    pb.set_defaults(func=cmd_baseline)

    prun = sub.add_parser("run", help="detect, contain and report end to end")
    prun.add_argument("--report", help="write the incident report to this path")
    prun.add_argument("--pace", type=float, default=0.4,
                      help="seconds to pause between lines (demo pacing)")
    prun.add_argument("--fast", action="store_true", help="no pauses")
    prun.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
