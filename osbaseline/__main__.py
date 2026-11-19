"""CLI: python -m osbaseline --linux samples/linux-web01 --windows samples/win-app01.json"""
import argparse, json, sys
from pathlib import Path
from .collect import load_linux, load_windows
from .evaluate import evaluate, compliance, drift, to_json

HERE = Path(__file__).parent


def main():
    ap = argparse.ArgumentParser(description="CIS-style OS baseline compliance, exceptions and drift")
    ap.add_argument("--linux", action="append", default=[], help="Linux snapshot dir (repeatable)")
    ap.add_argument("--windows", action="append", default=[], help="Windows settings JSON (repeatable)")
    ap.add_argument("--exceptions", default=str(HERE / "samples" / "exceptions.json"))
    ap.add_argument("--previous", help="previous results JSON to detect drift")
    ap.add_argument("--out", default="baseline_results.json")
    ap.add_argument("--fail-under", type=float, default=0, help="exit 1 if any host is below this compliance %%")
    a = ap.parse_args()
    exc = json.loads(Path(a.exceptions).read_text()) if Path(a.exceptions).exists() else []
    lin = json.loads((HERE / "baselines" / "linux_cis_l1.json").read_text())
    win = json.loads((HERE / "baselines" / "windows_cis_l1.json").read_text())
    allres, worst = [], 100.0
    for p in a.linux:
        allres += [(Path(p).name, evaluate(Path(p).name, lin, load_linux(p), exc))]
    for p in a.windows:
        allres += [(Path(p).stem, evaluate(Path(p).stem, win, load_windows(p), exc))]
    flat = []
    for host, res in allres:
        pct = compliance(res); worst = min(worst, pct)
        print(f"\n== {host}: {pct}% compliant")
        for r in res:
            if r.status != "PASS":
                print(f"  [{r.status:17}] {r.id:11} {r.title:40} expected {r.expected!r} got {r.actual!r}  (CIS {r.cis}, NIST {r.nist}) {r.note}")
        flat += res
    if a.previous and Path(a.previous).exists():
        d = drift(json.loads(Path(a.previous).read_text()), flat)
        print(f"\nDrift since last scan: {len(d)}")
        for r in d:
            print(f"  DRIFT {r.host} {r.id} {r.title}: now {r.actual!r}")
    Path(a.out).write_text(json.dumps(to_json(flat), indent=1))
    sys.exit(1 if worst < a.fail_under else 0)


if __name__ == "__main__":
    main()
