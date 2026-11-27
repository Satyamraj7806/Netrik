"""Duplicate devices: safe automatic merges and a reviewed list for the risky ones.

Reliable identifiers, strongest first:
  1. the same hardware (universal) MAC address
  2. an IP address that a device without a MAC and a device with a MAC both held recently
  3. the same specific hostname when no stable MAC contradicts it
Generic names ("Galaxy-S23", "raspberrypi") and devices with two different hardware MACs are never merged automatically.
"""

from __future__ import annotations

import json
from datetime import datetime

from . import config, db, identity, util


def _info(c) -> dict:
    devs = {d["id"]: dict(d, macs=set(), umacs=set(), ips={}, hosts=set()) for d in c.execute("SELECT * FROM devices")}
    for r in c.execute("SELECT device_id,type,value,last_seen FROM identifiers"):
        d = devs.get(r["device_id"])
        if not d:
            continue
        if r["type"] == "mac":
            d["macs"].add(r["value"])
            if not util.is_random_mac(r["value"]):
                d["umacs"].add(r["value"])
        elif r["type"] == "ip":
            d["ips"][r["value"]] = r["last_seen"]
        elif r["type"] == "hostname":
            d["hosts"].add(identity.short_host(r["value"]))
    return devs


def _overlap(a, b) -> bool:
    return a["first_seen"] <= b["last_seen"] and b["first_seen"] <= a["last_seen"]


def merge(c, keep: int, drop: int, reason: str, user: str = "system") -> None:
    """Fold device `drop` into `keep`: identifiers, evidence, services, findings and names move over; the merge is logged."""
    k = c.execute("SELECT * FROM devices WHERE id=?", (keep,)).fetchone()
    d = c.execute("SELECT * FROM devices WHERE id=?", (drop,)).fetchone()
    if not k or not d or keep == drop:
        return
    snapshot = {"device": dict(d), "identifiers": [dict(r) for r in c.execute("SELECT type,value,first_seen,last_seen FROM identifiers WHERE device_id=?", (drop,))]}
    c.execute("UPDATE OR IGNORE identifiers SET device_id=? WHERE device_id=?", (keep, drop))
    c.execute("DELETE FROM identifiers WHERE device_id=?", (drop,))
    for t in ("observations", "scan_hosts", "web_events"):
        c.execute(f"UPDATE {t} SET device_id=? WHERE device_id=?", (keep, drop))
    for s in c.execute("SELECT * FROM services WHERE device_id=?", (drop,)).fetchall():
        ex = c.execute("SELECT * FROM services WHERE device_id=? AND port=? AND proto=?", (keep, s["port"], s["proto"])).fetchone()
        if ex:
            newer = s if (s["last_seen"] or "") > (ex["last_seen"] or "") else ex
            c.execute("UPDATE services SET open_now=?, last_seen=?, first_seen=?, name=?, product=?, version=? WHERE id=?",
                      (newer["open_now"], max(s["last_seen"] or "", ex["last_seen"] or ""), min(s["first_seen"] or "z", ex["first_seen"] or "z"),
                       newer["name"], newer["product"], newer["version"], ex["id"]))
            c.execute("DELETE FROM services WHERE id=?", (s["id"],))
        else:
            c.execute("UPDATE services SET device_id=? WHERE id=?", (keep, s["id"]))
    c.execute("""UPDATE alerts SET status='resolved', updated_at=?, note=? WHERE device_id=? AND type IN ('new_device','stale_device')
                 AND status IN ('open','investigating','acknowledged')""", (util.now(), f"Merged: this record was a duplicate of device #{keep}.", drop))
    c.execute("UPDATE alerts SET device_id=? WHERE device_id=?", (keep, drop))
    sets, args = {}, []
    sets["first_seen"] = min(k["first_seen"], d["first_seen"])
    sets["last_seen"] = max(k["last_seen"], d["last_seen"])
    sets["approved"] = max(k["approved"], d["approved"])
    if (d["label_auto"] == 0 and k["label_auto"] != 0) or (k["label"].startswith("Unknown") and not d["label"].startswith("Unknown") and k["label_auto"] != 0):
        sets["label"], sets["label_auto"], sets["name_source"] = d["label"], d["label_auto"], d["name_source"]
    for col in ("vendor", "os", "name_source"):
        if not k[col] and d[col]:
            sets.setdefault(col, d[col])
    if (k["kind"] or "Unknown") == "Unknown" and d["kind"] and d["kind"] != "Unknown":
        sets["kind"] = d["kind"]
    if (k["zone"] in (None, "Unassigned")) and d["zone"] not in (None, "Unassigned"):
        sets["zone"] = d["zone"]
    if d["note"]:
        sets["note"] = (k["note"] + " " + d["note"]).strip()[:300]
    sets["demo"] = min(k["demo"], d["demo"])
    c.execute(f"UPDATE devices SET {','.join(f'{col}=?' for col in sets)} WHERE id=?", (*sets.values(), keep))
    macs = [r["value"] for r in c.execute("SELECT value FROM identifiers WHERE device_id=? AND type='mac'", (keep,))]
    umac = any(not util.is_random_mac(m) for m in macs)
    has_host = c.execute("SELECT 1 FROM identifiers WHERE device_id=? AND type='hostname'", (keep,)).fetchone()
    c.execute("UPDATE devices SET randomized=?, confidence=? WHERE id=?",
              (1 if macs and not umac else 0, "high" if umac else ("medium" if macs or has_host else "low"), keep))
    c.execute("DELETE FROM devices WHERE id=?", (drop,))
    c.execute("INSERT INTO device_merges(kept,dropped,reason,ts,user,dropped_json) VALUES(?,?,?,?,?,?)", (keep, drop, reason, util.now(), user, json.dumps(snapshot)))


def auto_merge(c, user: str = "system") -> dict:
    """Apply only the safe rules. Returns {dropped_id: kept_id}."""
    mapping, ttl = {}, config.cfg()["ip_match_hours"]
    devs = _info(c)

    def do(keep, drop, reason):
        keep = mapping.get(keep, keep)
        if keep == drop or drop in mapping or keep not in devs or drop not in devs:
            return
        merge(c, keep, drop, reason, user)
        mapping[drop] = keep
        devs[keep]["umacs"] |= devs[drop]["umacs"]; devs[keep]["macs"] |= devs[drop]["macs"]; devs[keep]["hosts"] |= devs[drop]["hosts"]
        devs[keep]["ips"].update(devs[drop]["ips"])
        devs[keep]["first_seen"] = min(devs[keep]["first_seen"], devs[drop]["first_seen"])
        devs[keep]["last_seen"] = max(devs[keep]["last_seen"], devs[drop]["last_seen"])
        del devs[drop]

    by_mac = {}
    for d in devs.values():
        for m in d["umacs"]:
            by_mac.setdefault(m, []).append(d)
    for m, group in by_mac.items():
        group.sort(key=lambda x: x["first_seen"])
        for other in group[1:]:
            do(group[0]["id"], other["id"], f"same hardware MAC address {m}")

    for x in sorted(devs.values(), key=lambda v: v["id"]):
        if x["id"] not in devs or x["macs"]:
            continue
        for ip, seen in x["ips"].items():
            if util.hours_since(seen) >= ttl:
                continue
            cand = [y for y in devs.values() if y["id"] != x["id"] and y["macs"] and ip in y["ips"] and util.hours_since(y["ips"][ip]) < ttl]
            if cand:
                do(max(cand, key=lambda y: y["ips"][ip])["id"], x["id"], f"held IP {ip} with no MAC; a device with a MAC held the same address")
                break

    by_host = {}
    for d in devs.values():
        for h in d["hosts"]:
            if not identity.generic_host(h):
                by_host.setdefault(h, []).append(d)
    for h, group in by_host.items():
        group = [g for g in group if g["id"] in devs]
        if len(group) < 2:
            continue
        with_u = [g for g in group if g["umacs"]]
        if len(with_u) > 1:
            continue  # two different hardware MACs: could be Wi-Fi and Ethernet of one PC, or two machines. A person decides.
        if with_u:
            base = with_u[0]
        else:
            if any(_overlap(a, b) for i, a in enumerate(group) for b in group[i + 1:]):
                continue  # random-MAC devices active at the same time are different devices
            base = min(group, key=lambda g: g["first_seen"])
        for g in group:
            if g["id"] != base["id"]:
                do(base["id"], g["id"], f"same specific hostname '{h}' and no conflicting hardware MAC")
    return mapping


def candidates() -> list:
    """Possible duplicates that need a human decision."""
    with db.tx() as c:
        devs = _info(c)
        ips = {}
        for did, d in devs.items():
            ips[did] = max(d["ips"], key=lambda k: d["ips"][k]) if d["ips"] else ""
        out, seen = [], set()
        groups = {}
        for d in devs.values():
            for h in d["hosts"]:
                groups.setdefault(h, []).append(d)
        for h, g in sorted(groups.items()):
            if len(g) < 2:
                continue
            key = tuple(sorted(x["id"] for x in g))
            if key in seen:
                continue
            seen.add(key)
            why = ("The name is generic (shared by many devices), so Netrik will not merge on it alone." if identity.generic_host(h) else
                   "Same hostname but different hardware MAC addresses: one PC with Wi-Fi and Ethernet, or two machines?")
            out.append({"reason": f"Hostname '{h}': {why}", "devices": [{"id": x["id"], "label": x["label"], "ip": ips[x["id"]], "zone": x["zone"],
                        "macs": sorted(x["macs"]), "first_seen": x["first_seen"], "last_seen": x["last_seen"], "kind": x["kind"]} for x in g],
                        "suggested_keep": min(g, key=lambda x: x["first_seen"])["id"]})
        return out
