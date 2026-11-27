"""Evidence-backed network graph. Edge layers: observed flow, tested reachability, configured intent."""

from __future__ import annotations

from . import config, db, policy, util, visibility


def graph() -> dict:
    """Logical network model for the topology view: segments (zones), devices and evidence-labelled edges.

    Hierarchy: upstream -> gateway -> segment -> devices. Membership is containment; edges between devices exist only
    where evidence supports them: tested reachability, observed traffic (imported flows) or a policy-restricted website request.
    """
    baseline = db.setting("baseline_set") == "1"
    vz, vname = policy.vantage_zone(), config.collector_name()
    devices = db.q("SELECT * FROM devices ORDER BY zone, label")
    recent = visibility.sources_by_device(config.cfg()["stale_hours"])
    ip_of, port_by_dev, issues = {}, {}, {}
    for r in db.q("SELECT device_id, value FROM identifiers WHERE type='ip' ORDER BY last_seen"):
        ip_of[r["device_id"]] = r["value"]
    ip_to_dev = {v: k for k, v in ip_of.items()}
    for r in db.q("SELECT device_id, port, name FROM services WHERE open_now=1 ORDER BY port"):
        port_by_dev.setdefault(r["device_id"], []).append({"port": r["port"], "name": r["name"]})
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for r in db.q("SELECT device_id, severity FROM alerts WHERE status IN ('open','investigating') AND device_id IS NOT NULL"):
        cur = issues.setdefault(r["device_id"], {"n": 0, "sev": "info"})
        cur["n"] += 1
        if rank.get(r["severity"], 9) < rank[cur["sev"]]:
            cur["sev"] = r["severity"]

    real = not policy.demo_on()
    mine = config.local_ips() if real else set()
    gw_ip = config.default_gateway() if real else None
    me_id = next((d["id"] for d in devices if ip_of.get(d["id"]) in mine), None)  # the machine running Netrik is the test point, not a second device

    counts, new_counts, issue_counts = {}, {}, {}
    nodes, edges = [], []
    sens = config.cfg()["sensitive_ports"]
    for d in devices:
        z = d["zone"] or "Unassigned"
        gateway = d["kind"] == "Gateway / router" or (gw_ip and ip_of.get(d["id"]) == gw_ip)
        status = visibility.device_status(d, baseline)
        iss = issues.get(d["id"], {"n": 0, "sev": None})
        ports = port_by_dev.get(d["id"], [])
        bad = [p["port"] for p in ports if policy.violation(d["zone"], vz, p["port"])]
        if not gateway:
            counts[z] = counts.get(z, 0) + 1
            new_counts[z] = new_counts.get(z, 0) + (1 if status == "new" else 0)
            issue_counts[z] = issue_counts.get(z, 0) + (1 if iss["n"] else 0)
        is_me = d["id"] == me_id
        nodes.append({"data": {"id": f"d{d['id']}", "num": d["id"], "label": (d["label"] + (" (this machine)" if is_me else ""))[:26], "type": "device", "kind": d["kind"],
                               "status": status, "zone": z, "ip": ip_of.get(d["id"], ""), "gateway": bool(gateway), "vantage": is_me, "sources": len(recent.get(d["id"], {})),
                               "issues": iss["n"], "sev": iss["sev"], "violation": bool(bad), "ports": len(ports)}})
        exposed = [p["port"] for p in ports if p["port"] in sens]
        if (bad or exposed) and not is_me:
            edges.append({"data": {"id": f"t{d['id']}", "source": f"d{me_id}" if me_id else "vantage", "target": f"d{d['id']}", "layer": "tested",
                                   "label": ", ".join(str(x) for x in (bad or exposed)[:3]), "state": "violation" if bad else "sensitive"}})
    zone_names = [z for z in policy.zone_names() if counts.get(z) or (z == vz and not me_id)]
    for z in counts:
        if z not in zone_names:
            zone_names.append(z)
    zone_nodes = [{"data": {"id": f"z:{z}", "label": z, "type": "zone", "count": counts.get(z, 0), "new": new_counts.get(z, 0), "issues": issue_counts.get(z, 0)}} for z in zone_names]
    nodes = zone_nodes + nodes
    if not me_id:
        nodes.append({"data": {"id": "vantage", "label": vname, "type": "vantage", "zone": vz}})

    agg = {}
    for f in db.q("SELECT src_ip,dst_ip,port,proto FROM flows"):
        a, b = ip_to_dev.get(f["src_ip"]), ip_to_dev.get(f["dst_ip"])
        if a and b and a != b:
            agg.setdefault((a, b), set()).add(f"{f['proto']}/{f['port']}")
    for (a, b), ps in agg.items():
        edges.append({"data": {"id": f"f{a}-{b}", "source": f"d{a}", "target": f"d{b}", "layer": "observed", "label": ", ".join(sorted(ps)[:2])}})
    ids = {n["data"]["id"] for n in nodes}
    for i, r in enumerate(policy.rules()):
        if f"z:{r['from']}" in ids and f"z:{r['to']}" in ids:
            edges.append({"data": {"id": f"c{i}", "source": f"z:{r['from']}", "target": f"z:{r['to']}", "layer": "configured", "label": "deny " + (",".join(map(str, r["ports"])) or "all")}})
    seen_sites = set()
    for a in db.q("SELECT device_id, detail FROM alerts WHERE type='policy_site' AND status IN ('open','investigating') AND device_id IS NOT NULL ORDER BY id DESC LIMIT 40"):
        for dom, hits in (util.jl(a["detail"]).get("domains") or {}).items():
            if len(seen_sites) >= 12 and dom not in seen_sites:
                continue
            if dom not in seen_sites:
                seen_sites.add(dom)
                nodes.append({"data": {"id": f"s:{dom}", "label": dom, "type": "site", "hits": hits}})
            edges.append({"data": {"id": f"w{a['device_id']}-{dom}", "source": f"d{a['device_id']}", "target": f"s:{dom}", "layer": "web", "label": f"x{hits}"}})
    return {"nodes": nodes, "edges": edges, "vantage_zone": vz, "has_data": bool(devices)}


def snapshot() -> dict:
    """Plain-dict copy of the current model. The simulator edits this copy, never the database."""
    baseline = db.setting("baseline_set") == "1"
    recent = visibility.sources_by_device(config.cfg()["stale_hours"])
    ports = {}
    for r in db.q("SELECT device_id, port, name FROM services WHERE open_now=1"):
        ports.setdefault(r["device_id"], []).append({"port": r["port"], "name": r["name"]})
    ip_of = {}
    for r in db.q("SELECT device_id, value FROM identifiers WHERE type='ip' ORDER BY last_seen"):
        ip_of[r["device_id"]] = r["value"]
    devs = [{"id": d["id"], "label": d["label"], "kind": d["kind"], "zone": d["zone"] or "Unassigned", "approved": bool(d["approved"]),
             "ip": ip_of.get(d["id"]), "ports": ports.get(d["id"], []), "sources": sorted(recent.get(d["id"], {})), "down": False}
            for d in db.q("SELECT * FROM devices")]
    by_ip = {d["ip"]: d["id"] for d in devs if d["ip"]}
    flows = [{"src": by_ip.get(f["src_ip"]), "dst": by_ip.get(f["dst_ip"]), "port": f["port"], "proto": f["proto"], "count": f["count"]}
             for f in db.q("SELECT * FROM flows") if by_ip.get(f["src_ip"]) and by_ip.get(f["dst_ip"])]
    return {"devices": devs, "flows": flows, "policy": policy.rules(), "vantage_zone": policy.vantage_zone(),
            "zones": policy.zone_names(), "baseline": baseline, "sensitive": config.cfg()["sensitive_ports"]}
