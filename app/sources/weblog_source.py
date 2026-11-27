"""Web activity logs: who asked for which domain. DNS and proxy logs show requests, not proof a page loaded."""

from __future__ import annotations

import csv
import io
import re
from urllib.parse import urlparse

MAX_LINES = 60000
IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DNSMASQ = re.compile(r"query\[\w+\]\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)")
SQUID = re.compile(r"^\d+(?:\.\d+)?\s+\d+\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\d+\s+\S+\s+(\S+)")


def _host(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "//" + url
    return (urlparse(url).hostname or "").lower().strip(".")


def parse(text: str) -> list:
    """Returns [(client_ip, domain)] from Zeek dns.log, dnsmasq/Pi-hole, squid access.log, CSV, or plain 'ip domain' lines."""
    lines = text.lstrip("\ufeff").splitlines()[:MAX_LINES]
    out = []
    fields = None
    first = next((l for l in lines if l.strip()), "")
    if first.startswith("#separator") or any(l.startswith("#fields") for l in lines[:12]):
        for l in lines:
            if l.startswith("#fields"):
                fields = l.split("\t")[1:]
            elif not l.startswith("#") and fields:
                d = dict(zip(fields, l.split("\t")))
                if IP.match(d.get("id.orig_h", "")) and d.get("query") and d["query"] != "-":
                    out.append((d["id.orig_h"], d["query"].lower().strip(".")))
        return out
    if "," in first and re.search(r"(domain|host|url|query)", first, re.I) and re.search(r"(ip|client|src)", first, re.I):
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            r = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            ip = next((r[k] for k in r if k in ("ip", "client", "client_ip", "src", "source", "src_ip", "client ip") and IP.match(r[k])), "")
            dom = next((r[k] for k in r if k in ("domain", "host", "hostname", "url", "query", "site")), "")
            if ip and dom:
                out.append((ip, _host(dom)))
        return out
    for l in lines:
        m = DNSMASQ.search(l)
        if m:
            out.append((m.group(2), m.group(1).lower().strip(".")))
            continue
        m = SQUID.match(l)
        if m:
            out.append((m.group(1), _host(m.group(2))))
            continue
        parts = l.replace(",", " ").split()
        if len(parts) >= 2:
            a, b = parts[0], parts[1]
            if IP.match(a):
                out.append((a, _host(b)))
            elif IP.match(b):
                out.append((b, _host(a)))
    return [(ip, d) for ip, d in out if d]
