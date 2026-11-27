"""DHCP lease parsing (dnsmasq, ISC dhcpd, or a CSV export). A lease proves an assignment, not presence."""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

from .. import config


def _obs(mac, ip, host, source="dhcp", **detail):
    return {"source": source, "mac": mac, "ip": ip, "hostname": (host or "").strip() if host and host != "*" else None,
            "detail": {k: v for k, v in detail.items() if v}}


def parse_text(text: str, source: str = "dhcp") -> list:
    text = text.lstrip("\ufeff")
    if re.search(r"^\s*lease\s+\d+\.\d+\.\d+\.\d+\s*\{", text, re.M):
        out = []
        for m in re.finditer(r"lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\n\s*\}", text, re.S):
            body = m.group(2)
            mac = re.search(r"hardware ethernet ([0-9a-fA-F:]+)", body)
            host = re.search(r'client-hostname "([^"]+)"', body)
            ends = re.search(r"ends\s+\d+\s+([\d/ :]+);", body)
            if mac:
                out.append(_obs(mac.group(1), m.group(1), host.group(1) if host else None, source, lease_ends=ends.group(1) if ends else ""))
        return out
    first = text.splitlines()[0].lower() if text.strip() else ""
    if "," in first and ("mac" in first or "ip" in first):
        out = []
        for row in csv.DictReader(io.StringIO(text)):
            r = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            mac = next((r[k] for k in r if "mac" in k or k in ("hw", "hardware")), "")
            ip = next((r[k] for k in r if k.startswith("ip") or k == "address"), "")
            host = next((r[k] for k in r if "host" in k or k in ("name", "device", "device name", "client name")), "")
            if mac or ip:
                out.append(_obs(mac or None, ip or None, host, source, ssid=r.get("ssid", ""), signal=r.get("signal", "")))
        return out
    out = []
    for line in text.splitlines():  # dnsmasq: expiry mac ip hostname clientid
        p = line.split()
        if len(p) >= 4 and re.match(r"^\d+$", p[0]):
            out.append(_obs(p[1], p[2], p[3], source, lease_expiry=p[0]))
    return out


def collect_configured() -> list:
    out = []
    for path in config.cfg()["dhcp_lease_files"]:
        try:
            out += parse_text(Path(path).read_text(errors="ignore"))
        except OSError:
            continue
    return out
