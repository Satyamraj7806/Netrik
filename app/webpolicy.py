"""Restricted-website rules. Each request is checked against the rules an administrator wrote in Settings."""

from __future__ import annotations

import json
import re

from . import config, db, detect, policy, util

DOMAIN = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def parse_domains(text: str) -> list:
    out = []
    for d in re.split(r"[,\s]+", (text or "").lower()):
        d = re.sub(r"^[a-z]+://", "", d).split("/")[0].strip(".")
        if d:
            out.append(d)
    bad = [d for d in out if not DOMAIN.match(d)]
    if bad:
        raise ValueError(f"'{bad[0]}' is not a valid domain name (example: facebook.com or *.betting.com).")
    return sorted(set(out))


def matches(domain: str, patterns: list):
    domain = domain.lower().strip(".")
    for p in patterns:
        p = p.lower().lstrip("*.").strip(".")
        if domain == p or domain.endswith("." + p):
            return p
    return None


def site_rules() -> list:
    return [dict(r, patterns=[d for d in (r["domains"] or "").split(",") if d]) for r in db.q("SELECT * FROM policy_rules WHERE kind='site' AND enabled=1")]


def blocked_domain(domain: str):
    """The rule (if any) that says Netrik's DNS monitor should refuse this name."""
    for r in site_rules():
        if r["block"] and matches(domain, r["patterns"]):
            return r
    return None


def record_many(events: list, source: str, blocked: bool = False) -> dict:
    """events: [(ts or None, client_ip, domain)]. Stores matching requests and raises one finding per client and rule."""
    rules = site_rules()
    stats = {"processed": len(events), "matched": 0, "alerts_new": 0, "alerts_updated": 0}
    if not rules:
        return stats
    with db.tx() as c:
        for ts, ip, domain in events:
            ts = ts or util.now()
            row = c.execute("SELECT device_id FROM identifiers WHERE type='ip' AND value=? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
            did = row["device_id"] if row else None
            dev = c.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone() if did else None
            zone = (dev["zone"] if dev else None) or config.zone_for_ip(ip)
            for r in rules:
                if r["zone"] and r["zone"] != "All zones" and r["zone"] != zone:
                    continue
                hit = matches(domain, r["patterns"])
                if not hit:
                    continue
                stats["matched"] += 1
                c.execute("INSERT INTO web_events(ts,client_ip,device_id,domain,source,matched_rule,blocked) VALUES(?,?,?,?,?,?,?)", (ts, ip, did, domain, source, r["id"], 1 if blocked else 0))
                dedupe = f"site:{ip}:{r['id']}"
                ex = c.execute("SELECT id, detail FROM alerts WHERE dedupe=? AND status IN ('open','investigating','acknowledged')", (dedupe,)).fetchone()
                if ex:
                    d = util.jl(ex["detail"])
                    d["hits"] = d.get("hits", 1) + 1
                    d["domains"][domain] = d["domains"].get(domain, 0) + 1
                    d["last"] = ts
                    c.execute("UPDATE alerts SET detail=?, updated_at=? WHERE id=?", (json.dumps(d), ts, ex["id"]))
                    stats["alerts_updated"] += 1
                    continue
                who = dev["label"] if dev else ip
                known = [f"Client address: {ip}", f"Device: {dev['label'] if dev else 'not in the inventory'}", f"Network zone: {zone}",
                         f"Rule: {r['name']} (applies to {r['zone'] or 'All zones'})", f"A request for {domain} was recorded at {util.local(ts)}"]
                if blocked:
                    known.append("Netrik's DNS monitor refused to resolve this name.")
                aid = detect.raise_alert(
                    c, "policy_site", did, dedupe, r["severity"], "high" if source != "test event" else "high",
                    f"Restricted site requested: {domain} from {who}",
                    {"what": f"{who} asked for {domain}, which your rule '{r['name']}' restricts.", "asset": did, "when": ts, "source": source,
                     "evidence": [{"source": source, "at": ts, "note": f"{ip} requested {domain} (matches {hit})"}, {"source": "policy rule", "at": r["created_at"] or ts, "note": f"{r['name']}: {', '.join(r['patterns'])}"}],
                     "known": known,
                     "unknown": ["Whether a person visited it on purpose (adverts, redirects and background apps also trigger lookups)",
                                 "Whether the page actually loaded", "Who was using the device"],
                     "why": "You wrote this rule, so a matching request is a policy event worth a conversation. On its own it is not proof of misuse.",
                     "hits": 1, "domains": {domain: 1}, "rule_id": r["id"]}, "policy_site", None, ts)
                stats["alerts_new"] += 1
        c.execute("DELETE FROM web_events WHERE id NOT IN (SELECT id FROM web_events ORDER BY id DESC LIMIT 5000)")
    return stats
