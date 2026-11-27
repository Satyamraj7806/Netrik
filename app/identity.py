"""Device identity: a device is not an IP address. Observations are linked to devices by evidence."""

from __future__ import annotations

import re

from . import config, util
from .sources.names import RANK


def _set_ident(c, did, typ, val, ts):
    if val:
        c.execute("""INSERT INTO identifiers(device_id,type,value,first_seen,last_seen) VALUES(?,?,?,?,?)
                     ON CONFLICT(device_id,type,value) DO UPDATE SET last_seen=excluded.last_seen""", (did, typ, val, ts, ts))


GENERIC_HOSTS = {"localhost", "raspberrypi", "ubuntu", "kali", "debian", "android", "iphone", "ipad", "unknown", "router", "gateway", "admin", "pc", "desktop", "laptop", "host", "user"}
MODEL_NAME = re.compile(r"^(galaxy|iphone|ipad|redmi|pixel|oneplus|android|samsung|huawei|oppo|vivo|realme|poco|moto)([-_ ]?\w{0,12})?$", re.I)


def short_host(h: str) -> str:
    return (h or "").strip().lower().split(".")[0]


def generic_host(h: str) -> bool:
    """Names shared by many unrelated devices (default hostnames, phone model names) must never join devices on their own."""
    s = short_host(h)
    return len(s) < 4 or s in GENERIC_HOSTS or bool(MODEL_NAME.match(s))


def resolve(c, o: dict, ts: str) -> dict:
    mac, ip, ip6 = util.norm_mac(o.get("mac")), o.get("ip"), o.get("ip6")
    host = (o.get("hostname") or "").strip().lower() or None
    rand = util.is_random_mac(mac) if mac else False
    did, conflict = None, None
    name_source = (o.get("detail") or {}).get("name_source") or (("dhcp" if o.get("source") in ("dhcp", "ap") else "dns") if o.get("hostname") else None)

    if mac:
        r = c.execute("SELECT device_id FROM identifiers WHERE type='mac' AND value=?", (mac,)).fetchone()
        did = r["device_id"] if r else None
    if did is None and mac and ip:
        # A device first seen without a MAC (for example by an unprivileged scan) is the same device if it holds this IP now.
        r = c.execute("""SELECT i.device_id FROM identifiers i WHERE i.type='ip' AND i.value=? AND i.last_seen>=?
                         AND NOT EXISTS (SELECT 1 FROM identifiers m WHERE m.device_id=i.device_id AND m.type='mac')
                         ORDER BY i.last_seen DESC LIMIT 1""", (ip, util.shift(config.cfg()["ip_match_hours"]))).fetchone()
        if r:
            did = r["device_id"]
    if did is None and host and not generic_host(host) and (not mac or rand):
        # A hostname joins observations only when no stable MAC contradicts it.
        r = c.execute("""SELECT i.device_id, d.randomized FROM identifiers i JOIN devices d ON d.id=i.device_id
                         WHERE i.type='hostname' AND i.value=? ORDER BY i.last_seen DESC LIMIT 1""", (host,)).fetchone()
        if r and (not mac or r["randomized"]):
            did = r["device_id"]
    if did is None and ip and not mac:
        r = c.execute("""SELECT device_id, last_seen FROM identifiers WHERE type='ip' AND value=?
                         ORDER BY last_seen DESC LIMIT 1""", (ip,)).fetchone()
        if r and util.hours_since(r["last_seen"]) < config.cfg()["ip_match_hours"]:
            did = r["device_id"]

    created = did is None
    zone = o.get("zone") or config.zone_for_ip(ip)
    if created:
        label = o.get("hostname") or (f"{o['vendor']} device" if o.get("vendor") else None) or f"Unknown device {ip or mac or ''}".strip()
        did = c.execute("""INSERT INTO devices(label,vendor,zone,first_seen,last_seen,randomized,name_source) VALUES(?,?,?,?,?,?,?)""",
                        (label, o.get("vendor"), zone, ts, ts, 1 if rand else 0, name_source if o.get("hostname") else None)).lastrowid
    else:
        d = c.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
        sets, args = ["last_seen=?"], [ts]
        if o.get("vendor") and not d["vendor"]:
            sets.append("vendor=?"); args.append(o["vendor"])
        if o.get("hostname") and d["label_auto"] and d["label"] != o["hostname"] and (
                d["label"].startswith("Unknown") or not d["name_source"] or RANK.get(name_source, 0) >= RANK.get(d["name_source"], 0)):
            sets += ["label=?", "name_source=?"]; args += [o["hostname"], name_source]
        if zone != "Unassigned" and zone != d["zone"]:
            sets.append("zone=?"); args.append(zone)
        c.execute(f"UPDATE devices SET {','.join(sets)} WHERE id=?", (*args, did))

    if ip and mac:  # two different MACs claiming one IP within minutes deserves a look
        other = c.execute("""SELECT i.device_id, m.value mac FROM identifiers i
                             JOIN identifiers m ON m.device_id=i.device_id AND m.type='mac'
                             WHERE i.type='ip' AND i.value=? AND i.device_id<>? AND i.last_seen>=? LIMIT 1""",
                          (ip, did, _minutes_ago(ts, 10))).fetchone()
        if other:
            conflict = {"ip": ip, "other_device": other["device_id"], "other_mac": other["mac"], "mac": mac}

    _set_ident(c, did, "mac", mac, ts); _set_ident(c, did, "ip", ip, ts)
    _set_ident(c, did, "ipv6", ip6, ts); _set_ident(c, did, "hostname", host, ts)
    if rand:
        c.execute("UPDATE devices SET randomized=1 WHERE id=?", (did,))
    types = {r["type"]: r["value"] for r in c.execute("SELECT type,value FROM identifiers WHERE device_id=?", (did,))}
    d = c.execute("SELECT randomized FROM devices WHERE id=?", (did,)).fetchone()
    has_universal = any(not util.is_random_mac(r["value"]) for r in c.execute(
        "SELECT value FROM identifiers WHERE device_id=? AND type='mac'", (did,)))
    conf = "high" if has_universal else ("medium" if ("mac" in types or "hostname" in types) else "low")
    c.execute("UPDATE devices SET confidence=? WHERE id=?", (conf, did))
    return {"device_id": did, "created": created, "conflict": conflict}


def _minutes_ago(ts: str, minutes: int) -> str:
    from datetime import timedelta
    return (util.parse(ts) - timedelta(minutes=minutes)).strftime(util.FMT)
