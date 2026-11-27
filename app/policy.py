"""Intended-access policy, vantage zone and zone names (config plus optional demo data)."""

from __future__ import annotations

import json

from . import config, db, util


def demo_on() -> bool:
    return db.setting("demo") == "1"


def rules() -> list:
    out = []
    for r in (config.cfg()["policy"].get("deny") or []):
        out.append({"from": r["from"], "to": r["to"], "ports": [int(p) for p in r.get("ports", [])]})
    if demo_on():
        out += util.jl(db.setting("demo_policy"), [])
    for r in db.q("SELECT * FROM policy_rules WHERE kind='zone_deny' AND enabled=1"):
        out.append({"from": r["from_zone"], "to": r["to_zone"], "ports": [int(p) for p in (r["ports"] or "").split(",") if p.strip().isdigit()], "name": r["name"], "id": r["id"]})
    return out


def forbidden_port(zone, port):
    """A rule saying this port must not be open on devices in this zone (zone empty or 'All zones' = everywhere)."""
    for r in db.q("SELECT * FROM policy_rules WHERE kind='port_forbid' AND enabled=1"):
        ports = [int(p) for p in (r["ports"] or "").split(",") if p.strip().isdigit()]
        if port in ports and (not r["zone"] or r["zone"] == "All zones" or r["zone"] == zone):
            return r
    return None


def vantage_zone() -> str:
    if demo_on() and db.setting("demo_vantage"):
        return db.setting("demo_vantage")
    ips = config.local_ips()
    for ip in sorted(ips):
        z = config.zone_for_ip(ip)
        if z != "Unassigned":
            return z
    return "Unassigned"


def violation(dev_zone, from_zone, port):
    for r in rules():
        if r["from"] == from_zone and r["to"] == dev_zone and (not r["ports"] or port in r["ports"]):
            return r
    return None


def zone_names() -> list:
    names = [z["name"] for z in config.configured_zones()]
    for r in rules():
        names += [r["from"], r["to"]]
    names += [r["zone"] for r in db.q("SELECT DISTINCT zone FROM devices WHERE zone IS NOT NULL")]
    seen, out = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out
