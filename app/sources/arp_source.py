"""Neighbour-table collector (read-only). Shows IP-to-MAC pairs this machine has recently talked to."""

from __future__ import annotations

import subprocess
from pathlib import Path


def collect() -> list:
    obs = []
    for fam in ("-4", "-6"):
        try:
            out = subprocess.run(["ip", fam, "neigh", "show"], capture_output=True, text=True, timeout=5).stdout
        except Exception:
            out = ""
        for line in out.splitlines():
            p = line.split()
            if len(p) < 4 or "lladdr" not in p or p[-1] in ("FAILED", "INCOMPLETE"):
                continue
            mac = p[p.index("lladdr") + 1]
            iface = p[p.index("dev") + 1] if "dev" in p else ""
            obs.append({"source": "arp", "ip": p[0] if fam == "-4" else None, "ip6": p[0] if fam == "-6" else None,
                        "mac": mac, "detail": {"state": p[-1], "iface": iface}})
    if not obs:
        try:
            for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
                p = line.split()
                if len(p) >= 6 and p[3] != "00:00:00:00:00:00":
                    obs.append({"source": "arp", "ip": p[0], "mac": p[3], "detail": {"iface": p[5]}})
        except OSError:
            pass
    return obs
