"""Command line helpers:  python -m app.cli set-password | seed-demo | clear-demo | collect"""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
import tempfile

from netrik.utils.validation import parse_targets

from . import auth, config, db, demo
from .sources import arp_source, nmap_source


def main():
    ap = argparse.ArgumentParser(prog="python -m app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("set-password", help="create or reset a user")
    p.add_argument("username", nargs="?", default="admin")
    sub.add_parser("seed-demo", help="load the synthetic college network")
    sub.add_parser("clear-demo", help="remove demo data")
    c = sub.add_parser("collect", help="collect evidence on THIS machine and write a bundle to import into the main Netrik")
    c.add_argument("--target", required=True)
    c.add_argument("--out", default="bundle.json")
    a = ap.parse_args()
    db.init()
    if a.cmd == "set-password":
        auth.set_user(a.username, getpass.getpass("New password (8+ chars): "))
        print("Saved.")
    elif a.cmd == "seed-demo":
        demo.seed()
        print("Demo data loaded.")
    elif a.cmd == "clear-demo":
        demo.clear()
        print("Demo data removed.")
    elif a.cmd == "collect":
        targets = parse_targets(a.target, config.allowed_networks(), config.cfg()["max_targets"])
        obs = []
        if shutil.which("nmap"):
            xml = tempfile.mktemp(suffix=".xml")
            args = nmap_source.build_args("discovery", targets, None, config.cfg()["nmap_privileged"], config.cfg()["max_rate"], xml, xml + ".txt")
            nmap_source.run(args, lambda l: None, lambda: False, 900)
            obs += [{"source": "nmap", **h} for h in nmap_source.parse_xml(xml)]
        obs += arp_source.collect()
        json.dump({"collector": config.collector_name(), "observations": obs, "flows": []}, open(a.out, "w"), indent=2)
        print(f"Wrote {len(obs)} observations to {a.out}. Import it in the web UI under Sources.")


if __name__ == "__main__":
    main()
