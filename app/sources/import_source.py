"""Imports: Wi-Fi/AP client lists, Zeek conn.log, and collector bundles from another machine."""

from __future__ import annotations

import json

from . import dhcp_source


def parse_ap(text: str) -> list:
    return dhcp_source.parse_text(text, source="ap")


def parse_zeek_conn(text: str):
    fields, flows, hosts = None, {}, set()
    for line in text.splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not fields:
            continue
        d = dict(zip(fields, line.split("\t")))
        src, dst, port, proto = d.get("id.orig_h"), d.get("id.resp_h"), d.get("id.resp_p"), d.get("proto", "tcp")
        if not src or not dst or "." not in src or "." not in dst or not (port or "").isdigit():
            continue
        key = (src, dst, int(port), proto)
        flows[key] = flows.get(key, 0) + 1
        hosts.update((src, dst))
    obs = [{"source": "zeek", "ip": ip} for ip in sorted(hosts)]
    return obs, [{"src": k[0], "dst": k[1], "port": k[2], "proto": k[3], "count": v} for k, v in flows.items()]


def parse_bundle(text: str):
    data = json.loads(text)
    return data.get("observations", []), data.get("flows", []), data.get("collector", "unknown")
