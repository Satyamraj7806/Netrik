"""Deterministic detection rules. Observation, suspicion and confirmed evidence are kept apart."""

from __future__ import annotations

import json

from . import config, db, policy, util

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def raise_alert(c, typ, did, dedupe, severity, confidence, title, detail, rec_key, scan_id=None, ts=None):
    ts = ts or util.now()
    row = c.execute("SELECT id FROM alerts WHERE dedupe=? AND status IN ('open','investigating','acknowledged')", (dedupe,)).fetchone()
    if row:
        c.execute("UPDATE alerts SET updated_at=?, scan_id=COALESCE(?,scan_id) WHERE id=?", (ts, scan_id, row["id"]))
        return None
    return c.execute("""INSERT INTO alerts(type,device_id,dedupe,severity,confidence,title,detail,rec_key,status,created_at,updated_at,scan_id)
                        VALUES(?,?,?,?,?,?,?,?,'open',?,?,?)""",
                     (typ, did, dedupe, severity, confidence, title, json.dumps(detail), rec_key, ts, ts, scan_id)).lastrowid


def _dev(c, did):
    return c.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()


def _ip(c, did):
    r = c.execute("SELECT value FROM identifiers WHERE device_id=? AND type='ip' ORDER BY last_seen DESC LIMIT 1", (did,)).fetchone()
    return r["value"] if r else None


def _mac(c, did):
    r = c.execute("SELECT value FROM identifiers WHERE device_id=? AND type='mac' ORDER BY last_seen DESC LIMIT 1", (did,)).fetchone()
    return r["value"] if r else None


def _label(d, ip):
    return f"{d['label']} ({ip})" if ip and ip not in d["label"] else d["label"]


def after_ingest(c, ts, scan_id, created, touched, vantage, svc_events, observations, ids):
    baseline = db.setting_c(c, "baseline_set") == "1"
    by_dev = {}
    for o, did in zip(observations, ids):
        by_dev.setdefault(did, []).append(o)

    if baseline:
        for did in created:
            _new_device(c, did, ts, scan_id, by_dev.get(did, []))

    for did in touched:  # a device that is seen again closes its own "not seen" alert
        c.execute("""UPDATE alerts SET status='resolved', updated_at=?, note=? WHERE type='stale_device' AND device_id=?
                     AND status IN ('open','investigating')""", (ts, f"Closed automatically: evidence of this device was received again at {util.local(ts)}.", did))

    vz = policy.vantage_zone()
    for did, ev, obs in svc_events:
        d, ip = _dev(c, did), _ip(c, did)
        for s in ev["new"]:
            if baseline and d["approved"]:
                _new_service(c, d, ip, s, ts, scan_id, vantage)
        for s in ev["open"]:
            forb = policy.forbidden_port(d["zone"], s["port"])
            viol = policy.violation(d["zone"], vz, s["port"])
            if forb:
                _forbidden_port(c, d, ip, s, forb, ts, scan_id, vantage)
            elif viol:
                _policy_violation(c, d, ip, s, viol, vz, ts, scan_id, vantage)
            elif s["port"] in config.cfg()["sensitive_ports"]:
                _sensitive(c, d, ip, s, ts, scan_id, vantage)
        for s in ev["closed"]:
            c.execute("""UPDATE alerts SET note=? WHERE status IN ('open','investigating') AND device_id=? AND dedupe IN (?,?,?)""",
                      (f"A later scan did not find port {s['port']} open. Use Verify to record this as evidence.", did,
                       f"sens:{did}:{s['port']}", f"pol:{did}:{s['port']}", f"newsvc:{did}:{s['port']}"))
            if baseline and d["approved"]:
                raise_alert(c, "service_closed", did, f"closed:{did}:{s['port']}", "info", "medium",
                            f"Port {s['port']}/{s['proto']} no longer open on {d['label']}",
                            {"what": f"A service previously open on port {s['port']} ({s['name']}) was not found open in the latest scan.",
                             "asset": did, "when": ts, "source": "nmap", "evidence": [{"source": "nmap", "at": ts, "note": f"Scan #{scan_id} covered port {s['port']}; it was not open."}],
                             "known": [f"Previously open: {s['port']}/{s['proto']} ({s['name']})"],
                             "unknown": ["Whether the service was stopped on purpose", "Whether a firewall now blocks this vantage point only"],
                             "why": "Planned changes are normal, but an unexpected service stopping can mean a fault or a configuration change."},
                            "service_closed", scan_id, ts)


def _new_device(c, did, ts, scan_id, obs):
    d, ip, mac = _dev(c, did), _ip(c, did), _mac(c, did)
    sources = sorted({o["source"] for o in obs})
    unknown = ["Who owns this device", "Whether it is authorised to be on this network",
               "Whether it is a visitor's phone, a new lab machine or something else"]
    if d["randomized"]:
        unknown.append("The MAC address is randomised, so it may be a phone that will appear under a different address later.")
    raise_alert(c, "new_device", did, f"new:{did}", "low" if d["randomized"] else "medium", d["confidence"],
                f"New device observed: {_label(d, ip)}",
                {"what": "A device that is not part of the approved baseline was observed.", "asset": did, "when": ts,
                 "source": ", ".join(sources),
                 "evidence": [{"source": o["source"], "at": ts, "note": f"IP {o.get('ip') or '-'}, MAC {o.get('mac') or '-'}, hostname {o.get('hostname') or '-'}"} for o in obs[:6]],
                 "known": [f"IP address: {ip or 'unknown'}", f"MAC address: {mac or 'unknown'}", f"Network zone: {d['zone']}",
                           f"Vendor string: {d['vendor'] or 'unknown'}", f"Seen by: {', '.join(sources)}"],
                 "unknown": unknown,
                 "why": "A new device is not an attack by itself. It is worth a quick check because unmanaged devices cannot be patched or monitored."},
                "new_device_random" if d["randomized"] else "new_device", scan_id, ts)


def _test(ip, port, vantage):
    return {"target": ip, "ports": str(port), "profile": "quick", "vantage": vantage}


def _new_service(c, d, ip, s, ts, scan_id, vantage):
    sev = "medium" if s["port"] in config.cfg()["sensitive_ports"] else "low"
    raise_alert(c, "new_service", d["id"], f"newsvc:{d['id']}:{s['port']}", sev, "high",
                f"New service on {d['label']}: {s['port']}/{s['proto']} ({s['name']})",
                {"what": f"Port {s['port']}/{s['proto']} is now open on an approved device and was not open before.", "asset": d["id"], "when": ts,
                 "source": "nmap", "evidence": [{"source": "nmap", "at": ts, "note": f"Scan #{scan_id} from {vantage}: {s['port']}/{s['proto']} open ({s['name']})"}],
                 "known": [f"Address tested: {ip}", f"Service name reported: {s['name']}", f"Tested from: {vantage}"],
                 "unknown": ["Whether the change was planned", "What software is behind the port", "Whether it is reachable from other zones"],
                 "why": "Changes in exposed services are the most common sign of a configuration change or a new application.",
                 "test": _test(ip, s["port"], vantage)},
                "new_service", scan_id, ts)


def _sensitive(c, d, ip, s, ts, scan_id, vantage):
    name = config.cfg()["sensitive_ports"][s["port"]]
    sev = "high" if s["port"] in (23, 21) else "medium"
    raise_alert(c, "sensitive_service", d["id"], f"sens:{d['id']}:{s['port']}", sev, "high",
                f"{name} responded on {d['label']} (port {s['port']})",
                {"what": f"TCP port {s['port']} ({name}) accepted a connection from the scanning machine.", "asset": d["id"], "when": ts,
                 "source": "nmap", "evidence": [{"source": "nmap", "at": ts, "note": f"Scan #{scan_id} from {vantage}: {s['port']}/{s['proto']} open"}],
                 "known": [f"Address tested: {ip}", f"Tested from: {vantage}", "The port answered at the time of the scan"],
                 "unknown": ["Whether this access is required", "Whether the service is protected by strong authentication",
                             "Whether it is reachable from other network zones (only this vantage was tested)"],
                 "why": "An open port is not a vulnerability. It is an exposure to review: some services should not be reachable from user networks.",
                 "test": _test(ip, s["port"], vantage)},
                f"port_{s['port']}", scan_id, ts)


def _policy_violation(c, d, ip, s, rule, vz, ts, scan_id, vantage):
    name = config.cfg()["sensitive_ports"].get(s["port"], s["name"])
    raise_alert(c, "policy_violation", d["id"], f"pol:{d['id']}:{s['port']}", "high", "high",
                f"{vz} can reach {d['zone']} on port {s['port']} ({name})",
                {"what": f"Your intended policy says {rule['from']} must not reach {rule['to']}, but a test from {vantage} ({vz}) connected to port {s['port']}.",
                 "asset": d["id"], "when": ts, "source": "nmap",
                 "evidence": [{"source": "nmap", "at": ts, "note": f"Scan #{scan_id}: {ip}:{s['port']}/{s['proto']} open from {vantage}"},
                              {"source": "config", "at": ts, "note": f"Policy: deny {rule['from']} -> {rule['to']}" + (f" ports {rule['ports']}" if rule['ports'] else "")}],
                 "known": [f"Tested path: {vz} -> {d['zone']}", f"Port {s['port']} answered", "The policy rule is configured intent"],
                 "unknown": ["Which firewall rule allows this", "Whether other zones can also reach it", "Whether the service is in use"],
                 "why": "Reachability that contradicts your own rules usually means a firewall or VLAN misconfiguration.",
                 "test": _test(ip, s["port"], vantage)},
                "policy_violation", scan_id, ts)


def _forbidden_port(c, d, ip, s, rule, ts, scan_id, vantage):
    raise_alert(c, "policy_violation", d["id"], f"forb:{d['id']}:{s['port']}:{rule['id']}", rule["severity"], "high",
                f"Port {s['port']} must not be open in {d['zone']}: {d['label']}",
                {"what": f"Your rule '{rule['name']}' forbids port {s['port']} on devices in {rule['zone'] or 'any zone'}, but it answered from {vantage}.",
                 "asset": d["id"], "when": ts, "source": "nmap",
                 "evidence": [{"source": "nmap", "at": ts, "note": f"Scan #{scan_id}: {ip}:{s['port']}/{s['proto']} open"}, {"source": "policy rule", "at": rule["created_at"] or ts, "note": f"{rule['name']}: forbid port {rule['ports']}"}],
                 "known": [f"Address tested: {ip}", f"Zone: {d['zone']}", f"Rule: {rule['name']}"],
                 "unknown": ["Whether the service is in use", "Who enabled it", "Whether other devices in the zone also expose it"],
                 "why": "The service you decided must not run here is running. Disable it or update the rule if the policy has changed.",
                 "test": _test(ip, s["port"], vantage)},
                "port_forbidden", scan_id, ts)


def ip_conflict(c, did, conf, ts, scan_id):
    d = _dev(c, did)
    raise_alert(c, "ip_conflict", did, f"ipc:{conf['ip']}:{conf['mac']}", "medium", "medium",
                f"Two MAC addresses claimed {conf['ip']} within minutes",
                {"what": f"{conf['mac']} and {conf['other_mac']} were both observed using {conf['ip']} within ten minutes.", "asset": did, "when": ts,
                 "source": "network sources", "evidence": [{"source": "identity", "at": ts, "note": f"{conf['mac']} vs {conf['other_mac']} on {conf['ip']}"}],
                 "known": [f"IP: {conf['ip']}", f"MAC A: {conf['mac']}", f"MAC B: {conf['other_mac']}"],
                 "unknown": ["Whether this is a normal DHCP reassignment", "Whether a device is misconfigured or impersonating another"],
                 "why": "Usually a harmless DHCP reassignment or a static-address clash. Rarely, address spoofing looks the same."},
                "ip_conflict", scan_id, ts)


def sweep_stale():
    hours = config.cfg()["stale_hours"]
    with db.tx() as c:
        for d in c.execute("SELECT * FROM devices WHERE approved=1 AND last_seen<?", (util.shift(hours),)).fetchall():
            ip = _ip(c, d["id"])
            raise_alert(c, "stale_device", d["id"], f"stale:{d['id']}", "low", "low", f"Not seen recently: {_label(d, ip)}",
                        {"what": f"No source has reported this approved device for more than {hours} hours.", "asset": d["id"], "when": util.now(),
                         "source": "all sources", "evidence": [{"source": "inventory", "at": d["last_seen"], "note": f"Last evidence: {util.local(d['last_seen'])}"}],
                         "known": [f"Last evidence received: {util.local(d['last_seen'])}"],
                         "unknown": ["Whether it is switched off, asleep, moved or removed",
                                     "Whether it is hidden from our sources (client isolation, another VLAN, no probe response)"],
                         "why": "Silence is not proof the device is offline. It matters mostly for servers and infrastructure."},
                        "stale_device")
