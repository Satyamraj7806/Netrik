"""Normalised observations in, evidence + derived state out."""

from __future__ import annotations

import json

from . import classify, config, db, dedupe, detect, identity, util
from .sources import names


def in_spec(port: int, spec: str | None) -> bool:
    if not spec:
        return False
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            if int(a) <= port <= int(b):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


def _update_services(c, did, ports, ts, scan_id, tag, spec):
    ev = {"new": [], "closed": [], "open": []}
    seen = set()
    for p in ports:
        if p.get("state") != "open":
            continue
        key = (int(p["port"]), p.get("protocol", "tcp"))
        seen.add(key)
        item = {"port": key[0], "proto": key[1], "name": p.get("service") or "unknown"}
        ev["open"].append(item)
        row = c.execute("SELECT id,open_now FROM services WHERE device_id=? AND port=? AND proto=?", (did, *key)).fetchone()
        if row:
            c.execute("""UPDATE services SET name=?,product=?,version=?,open_now=1,last_seen=?,last_scan_id=?,last_profile=?
                         WHERE id=?""", (item["name"], p.get("product", ""), p.get("version", ""), ts, scan_id, tag, row["id"]))
            if not row["open_now"]:
                ev["new"].append(item)
        else:
            c.execute("""INSERT INTO services(device_id,port,proto,name,product,version,open_now,first_seen,last_seen,last_scan_id,last_profile)
                         VALUES(?,?,?,?,?,?,1,?,?,?,?)""", (did, *key, item["name"], p.get("product", ""), p.get("version", ""), ts, ts, scan_id, tag))
            ev["new"].append(item)
    for r in c.execute("SELECT * FROM services WHERE device_id=? AND open_now=1", (did,)).fetchall():
        if (r["port"], r["proto"]) not in seen:
            confident = r["last_profile"] == tag or in_spec(r["port"], spec)
            if confident:  # only claim "closed" for ports this scan actually covered
                c.execute("UPDATE services SET open_now=0,last_scan_id=? WHERE id=?", (scan_id, r["id"]))
                ev["closed"].append({"port": r["port"], "proto": r["proto"], "name": r["name"]})
    return ev


def _reclassify(c, did, o, gw):
    d = c.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
    ports = [dict(r, state="open", protocol=r["proto"], service=r["name"]) for r in
             c.execute("SELECT port,proto,name,product,version FROM services WHERE device_id=? AND open_now=1", (did,))]
    ip = o.get("ip") or (c.execute("SELECT value FROM identifiers WHERE device_id=? AND type='ip' ORDER BY last_seen DESC LIMIT 1", (did,)).fetchone() or [None])[0]
    kind, os_label, _ = classify.kind_for(ip, o.get("hostname"), d["vendor"], ports, o.get("os_matches"), bool(d["randomized"]), gw)
    c.execute("UPDATE devices SET kind=?, os=COALESCE(?,os) WHERE id=?", (kind, os_label, did))


def ingest(observations: list, scan_id=None, vantage=None, ts=None, profile=None, ports_spec=None) -> dict:
    ts = ts or util.now()
    vantage = vantage or config.collector_name()
    gw = config.default_gateway()
    tag = f"{profile}|{ports_spec or ''}"
    created, ids, svc_events = [], [], []
    with db.tx() as c:
        for o in observations:
            r = identity.resolve(c, o, ts)
            did = r["device_id"]
            ids.append(did)
            if r["created"]:
                created.append(did)
            if r["conflict"]:
                detect.ip_conflict(c, did, r["conflict"], ts, scan_id)
            c.execute("""INSERT INTO observations(device_id,source,observed_at,scan_id,ip,mac,hostname,vantage,detail)
                         VALUES(?,?,?,?,?,?,?,?,?)""",
                      (did, o["source"], ts, scan_id, o.get("ip"), util.norm_mac(o.get("mac")), o.get("hostname"), vantage,
                       json.dumps(o.get("detail") or {})))
            if o.get("ports") is not None:
                svc_events.append((did, _update_services(c, did, o["ports"], ts, scan_id, tag, ports_spec), o))
                _reclassify(c, did, o, gw)
        merged = dedupe.auto_merge(c)  # duplicates are merged before detection so a duplicate never raises a "new device" finding
        if merged:
            ids = [merged.get(i, i) for i in ids]
            created = [merged.get(i, i) for i in created if merged.get(i, i) == i]
            svc_events = [(merged.get(did, did), ev, o) for did, ev, o in svc_events]
        detect.after_ingest(c, ts, scan_id, created, set(ids), vantage, svc_events, observations, ids)
    return {"device_ids": ids, "created": created, "merged": len(merged)}


def ingest_flows(flows: list, source: str, ts=None):
    ts = ts or util.now()
    with db.tx() as c:
        for f in flows:
            c.execute("""INSERT INTO flows(src_ip,dst_ip,port,proto,count,last_seen,source) VALUES(?,?,?,?,?,?,?)
                         ON CONFLICT(src_ip,dst_ip,port,proto) DO UPDATE SET count=count+excluded.count,last_seen=excluded.last_seen""",
                      (f["src"], f["dst"], int(f["port"]), f.get("proto", "tcp"), int(f.get("count", 1)), ts, source))


def store_hosts(scan_id: int, observations: list, ids: list):
    gw = config.default_gateway()
    with db.tx() as c:
        for o, did in zip(observations, ids):
            if o["source"] != "nmap":
                continue
            ports = o.get("ports") or []
            kind, os_label, info = classify.kind_for(o.get("ip"), o.get("hostname"), o.get("vendor"), ports, o.get("os_matches"), util.is_random_mac(util.norm_mac(o.get("mac")) or ""), gw)
            data = {"ip": o.get("ip"), "mac": o.get("mac"), "vendor": o.get("vendor"), "hostname": o.get("hostname"),
                    "ports": ports if o.get("ports") is not None else None, "kind": kind, "classification": info}
            c.execute("INSERT INTO scan_hosts(scan_id,device_id,ip,data) VALUES(?,?,?,?)", (scan_id, did, o.get("ip"), json.dumps(data)))


def apply_names(mapping: dict, extras: dict | None = None) -> int:
    """mapping: {ip: (name, method)}. Updates labels and name identifiers; creates no observations.

    A name from a weaker source never replaces one from a stronger source (DHCP > DNS > mDNS > NetBIOS/LLMNR > UPnP).
    """
    n = 0
    with db.tx() as c:
        for ip, (name, method) in mapping.items():
            r = c.execute("SELECT device_id FROM identifiers WHERE type='ip' AND value=? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
            if not r:
                continue
            did, ts = r["device_id"], util.now()
            identity._set_ident(c, did, "hostname", name.lower(), ts)
            d = c.execute("SELECT label, label_auto, name_source FROM devices WHERE id=?", (did,)).fetchone()
            if d["label_auto"] and (d["label"].startswith("Unknown") or not d["name_source"] or names.RANK.get(method, 0) >= names.RANK.get(d["name_source"], 0)):
                c.execute("UPDATE devices SET label=?, name_source=? WHERE id=?", (name, method, did))
            n += 1
        _apply_extras(c, extras or {})
        dedupe.auto_merge(c)  # a newly learned name can reveal duplicates
    return n


def _apply_extras(c, extras: dict) -> None:
    for ip, e in extras.items():
        r = c.execute("SELECT device_id FROM identifiers WHERE type='ip' AND value=? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
        if not r:
            continue
        if e.get("vendor"):
            c.execute("UPDATE devices SET vendor=? WHERE id=? AND (vendor IS NULL OR vendor='')", (e["vendor"], r["device_id"]))
        if e.get("kind"):
            c.execute("UPDATE devices SET kind=? WHERE id=? AND (kind IS NULL OR kind IN ('Unknown','Windows host (likely)','Mobile device (likely)'))", (e["kind"], r["device_id"]))


def apply_extras(extras: dict) -> None:
    """Device hints (vendor, role) learned from UPnP descriptions."""
    with db.tx() as c:
        _apply_extras(c, extras)
