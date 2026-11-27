"""What Netrik can and cannot see. Evidence counts, never a claim about the true device count."""

from __future__ import annotations

from . import config, db, util

SOURCES = {
    "nmap": ("Active scan", "Responded to Nmap probes from this machine."),
    "arp": ("Neighbour table", "In this machine's ARP/neighbour cache. Entries can be stale."),
    "dhcp": ("DHCP lease", "Holds an address lease. A lease does not prove the device is online."),
    "ap": ("Wi-Fi / AP client list", "Reported by the access point or controller as associated."),
    "zeek": ("Passive monitoring", "Seen in traffic that reached the sensor. Misses anything that never crossed it."),
    "bundle": ("Imported collector", "Reported by a collector running on another machine."),
}


def device_status(d, baseline: bool) -> str:
    if util.hours_since(d["last_seen"]) > config.cfg()["stale_hours"]:
        return "stale"
    if baseline and not d["approved"]:
        return "new"
    return "ok" if d["approved"] else "unreviewed"


def sources_by_device(window_h=None) -> dict:
    cutoff = util.shift(window_h) if window_h else "0000"
    out = {}
    for r in db.q("SELECT device_id, source, MAX(observed_at) last FROM observations WHERE observed_at>=? GROUP BY device_id, source", (cutoff,)):
        out.setdefault(r["device_id"], {})[r["source"]] = r["last"]
    return out


def summary() -> dict:
    hrs = config.cfg()["stale_hours"]
    recent = sources_by_device(hrs)
    devices = db.q("SELECT * FROM devices")
    cats = {"active": [], "infra": [], "passive": [], "neighbour": [], "stale": []}
    unknown_identity = []
    per_source = {k: 0 for k in SOURCES}
    zones = {}
    for d in devices:
        src = recent.get(d["id"], {})
        for s in src:
            per_source[s] = per_source.get(s, 0) + 1
        z = zones.setdefault(d["zone"] or "Unassigned", {"devices": 0, **{k: 0 for k in SOURCES}})
        z["devices"] += 1
        for s in src:
            z[s] = z.get(s, 0) + 1
        if not src:
            cats["stale"].append(d)
        elif "nmap" in src:
            cats["active"].append(d)
        elif src.keys() & {"dhcp", "ap", "bundle"}:
            cats["infra"].append(d)
        elif "zeek" in src:
            cats["passive"].append(d)
        else:
            cats["neighbour"].append(d)
        if d["randomized"] and d["label"].startswith("Unknown"):
            unknown_identity.append(d)
    tips = []
    if not per_source.get("ap"):
        tips.append("No Wi-Fi/AP client list has been imported. This is the best source for phones that ignore active probes.")
    if not per_source.get("dhcp"):
        tips.append("No DHCP lease data. Add a lease file path in config.yaml or import a CSV export from the router.")
    if not per_source.get("zeek"):
        tips.append("No passive monitoring. A Zeek sensor on a mirrored port would reveal quiet devices and who talks to whom (optional).")
    if len(zones) > 1 or any(z != "Unassigned" for z in zones):
        silent = [n for n, z in zones.items() if z["nmap"] == 0 and z["devices"]]
        for n in silent:
            tips.append(f"Zone '{n}' has no active-scan evidence. A collector inside that segment, or an import from it, would improve coverage.")
    return {"cats": cats, "unknown_identity": unknown_identity, "per_source": per_source, "zones": zones, "tips": tips,
            "total": len(devices), "window": hrs}


def completeness(tokens: list) -> dict:
    found, missing = [], []
    for t in tokens:
        key = util.norm_mac(t) or t.strip().lower()
        row = db.one("SELECT device_id FROM identifiers WHERE value=? AND type IN ('mac','ip','hostname') LIMIT 1", (key,))
        if row:
            srcs = sorted({r["source"] for r in db.q("SELECT DISTINCT source FROM observations WHERE device_id=?", (row["device_id"],))})
            found.append({"token": t, "device_id": row["device_id"], "sources": srcs})
        else:
            missing.append(t)
    n = len(found) + len(missing)
    return {"found": found, "missing": missing, "pct": round(100 * len(found) / n) if n else 0}
