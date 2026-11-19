"""Parse host configuration snapshots into a flat {source: {key: value}} view."""
import json, re
from pathlib import Path


def parse_kv(text, sep=None):
    out = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if sep:
            if sep in line:
                k, v = line.split(sep, 1)
                out[k.strip()] = v.strip()
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                out[parts[0]] = parts[1].strip()
    return out


def load_linux(snapdir):
    d = Path(snapdir)
    return {
        "sshd_config": parse_kv((d / "sshd_config").read_text()),
        "sysctl": parse_kv((d / "sysctl.conf").read_text(), sep="="),
        "pwquality": parse_kv((d / "pwquality.conf").read_text(), sep="="),
        "services": {s: "present" for s in (d / "services.txt").read_text().split()},
        "selinux": {"mode": (d / "selinux.txt").read_text().strip().lower()},
    }


def load_windows(path):
    """Windows snapshot: JSON exported by tools/export_windows_settings.ps1 (or a GPO/secedit export)."""
    return {"settings": json.loads(Path(path).read_text())}
