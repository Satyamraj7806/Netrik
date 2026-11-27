"""Incident simulator. Works on a copy of the model and never touches evidence, scans or the network."""

from __future__ import annotations

import copy
import json

from . import advice, db, twin, util, visibility

SCENARIOS = {
    "unrecognised": {"title": "Unrecognised device joins a network zone", "needs": ["zone", "name"]},
    "exposure": {"title": "Sensitive service exposed to another zone", "needs": ["device", "port", "from_zone"]},
    "failure": {"title": "Critical server becomes unavailable", "needs": ["device"]},
    "restrict": {"title": "Restrict an insecure remote-access service", "needs": ["device", "port"]},
}


def evaluate(state: dict, from_zone: str | None = None) -> list:
    """The same rules the live detector uses, applied to a plain-dict state."""
    fz = from_zone or state["vantage_zone"]
    out = []
    for d in state["devices"]:
        if d["down"]:
            continue
        if state["baseline"] and not d["approved"]:
            out.append({"type": "new_device", "device": d["id"], "severity": "medium", "text": f"Unapproved device '{d['label']}' in {d['zone']}"})
        for p in d["ports"]:
            rule = next((r for r in state["policy"] if r["from"] == fz and r["to"] == d["zone"] and (not r["ports"] or p["port"] in r["ports"])), None)
            if rule:
                out.append({"type": "policy_violation", "device": d["id"], "severity": "high",
                            "text": f"{fz} can reach {d['label']} on port {p['port']}; policy says deny"})
            elif p["port"] in state["sensitive"]:
                out.append({"type": "sensitive_service", "device": d["id"], "severity": "medium",
                            "text": f"{state['sensitive'][p['port']]} reachable on {d['label']} (port {p['port']}) from {fz}"})
    return out


def _find(state, did):
    return next(d for d in state["devices"] if d["id"] == did)


def _result(key, narrative, before, after, affected, adv, limits, added=None):
    return {"scenario": key, "title": SCENARIOS[key]["title"], "hypothetical": True, "narrative": narrative,
            "before": before, "after": after, "affected": affected, "added": added or [], "advice": adv, "limits": limits}


def unrecognised(snap, zone, name):
    state = copy.deepcopy(snap)
    before = evaluate(state)
    sim = {"id": -1, "label": name or "Unknown device", "kind": "Unknown", "zone": zone, "approved": False, "ip": None, "ports": [], "sources": [], "down": False}
    state["devices"].append(sim)
    after = evaluate(state)
    peers = [d for d in snap["devices"] if d["zone"] == zone]
    cover = {s: sum(1 for d in peers if s in d["sources"]) for s in visibility.SOURCES}
    likely = [visibility.SOURCES[s][0] for s, n in cover.items() if peers and n / len(peers) >= 0.5]
    narr = [f"A device called '{sim['label']}' joins the zone '{zone}'."]
    if likely:
        narr.append("Based on how other devices in this zone are currently seen, it would most likely be noticed through: " + ", ".join(likely) + ".")
    else:
        narr.append("No source currently covers most devices in this zone, so this device might not be noticed at all. That is a visibility gap.")
    if not snap["baseline"]:
        narr.append("The baseline has not been set yet, so the live system would record it silently instead of alerting.")
    narr.append("The alert would say what was observed, which source saw it, and what is unknown (owner, authorisation).")
    limits = ["This assumes the device behaves like its neighbours. Client isolation or a different VLAN could hide it."]
    return _result("unrecognised", narr, {"findings": before}, {"findings": after}, [d["id"] for d in peers],
                   advice.get({"rec_key": "new_device"}), limits, added=[{"id": -1, "label": sim["label"], "zone": zone}])


def exposure(snap, device_id, port, from_zone):
    state = copy.deepcopy(snap)
    d = _find(state, device_id)
    before = evaluate(state, from_zone)
    if not any(p["port"] == port for p in d["ports"]):
        d["ports"].append({"port": port, "name": snap["sensitive"].get(port, "service")})
    after = evaluate(state, from_zone)
    rule = next((r for r in snap["policy"] if r["from"] == from_zone and r["to"] == d["zone"] and (not r["ports"] or port in r["ports"])), None)
    peers = [x for x in snap["devices"] if x["zone"] == d["zone"] and x["id"] != device_id and any(p["port"] == port for p in x["ports"])]
    narr = [f"Port {port} becomes reachable on {d['label']} ({d['zone']}) from {from_zone} because of a firewall mistake."]
    if rule:
        narr.append(f"Your intended policy forbids {rule['from']} -> {rule['to']}, so this would be flagged as a high-severity policy violation.")
    elif port in snap["sensitive"]:
        narr.append("No policy rule covers this path, so it would be raised as a sensitive service to review (medium).")
    else:
        narr.append("No rule covers this path and the port is not on the sensitive list, so nothing would be raised.")
    narr.append(f"{len(peers)} other device(s) in {d['zone']} already expose the same port, so a broad rule change could affect them too." if peers
                else f"No other device in {d['zone']} currently exposes this port.")
    narr.append("This is based on configured intent and current evidence. Real reachability would still need to be tested.")
    return _result("exposure", narr, {"findings": before}, {"findings": after}, [device_id] + [p["id"] for p in peers],
                   advice.get({"rec_key": f"port_{port}"}), ["Reachability is modelled from your policy file, not from a live test.", "Firewall rules are not read; only the intended policy is known."])


def failure(snap, device_id):
    state = copy.deepcopy(snap)
    d = _find(state, device_id)
    before = evaluate(state)
    d["down"] = True
    after = evaluate(state)
    deps = {}
    for f in snap["flows"]:
        if f["dst"] == device_id:
            deps.setdefault(f["src"], set()).add(f"{f['proto']}/{f['port']}")
    names = {x["id"]: x for x in snap["devices"]}
    narr = [f"{d['label']} ({d['zone']}) stops responding."]
    if d["ports"]:
        narr.append("Services that would be lost: " + ", ".join(f"{p['port']} ({p['name']})" for p in d["ports"]) + ".")
    if deps:
        narr.append(f"{len(deps)} device(s) were observed communicating with it, so they may be affected: " + ", ".join(names[i]["label"] for i in list(deps)[:8]) + ("..." if len(deps) > 8 else "") + ".")
        narr.append("Dependencies are inferred from observed traffic, not confirmed. Rare or scheduled jobs may be missing.")
    else:
        narr.append("No traffic data (for example an imported Zeek log) shows what depends on this device, so the impact on others is unknown.")
    adv = {"title": "Server unavailable", "plain": "A key system stopped responding. Nothing in the evidence says why.",
           "action": "Check power and network link first, then the service logs. Tell the people who use it. Have a recovery plan for this server.",
           "verify": "Confirm the services answer again from the same location after recovery."}
    zones = sorted({names[i]["zone"] for i in deps})
    return _result("failure", narr, {"findings": before}, {"findings": after}, [device_id, *deps.keys()], adv,
                   ["Impact is inferred from observed flows only.", f"Zones with observed dependents: {', '.join(zones) or 'none known'}."])


def restrict(snap, device_id, port):
    state = copy.deepcopy(snap)
    d = _find(state, device_id)
    if not any(p["port"] == port for p in d["ports"]):
        d["ports"].append({"port": port, "name": snap["sensitive"].get(port, "service")})
    before = evaluate(state)
    d["ports"] = [p for p in d["ports"] if p["port"] != port]
    after = evaluate(state)
    name = snap["sensitive"].get(port, f"port {port}")
    narr = [f"Today (hypothetically) {name} is reachable on {d['label']} from {snap['vantage_zone']}.",
            "Hypothetical change: limit access to approved administrator devices or a management network.",
            f"From {snap['vantage_zone']} the port would no longer connect, and {len(before) - len(after)} finding(s) would disappear."]
    return _result("restrict", narr, {"findings": before}, {"findings": after}, [device_id], advice.get({"rec_key": f"port_{port}"}),
                   ["The change is simulated. Apply it in a test environment first.", "After a real change, use Verify to repeat the test from the same location."])


def run(key: str, params: dict, user: str) -> dict:
    snap = twin.snapshot()
    if key == "unrecognised":
        res = unrecognised(snap, params["zone"], params.get("name", "").strip()[:40])
    elif key == "exposure":
        res = exposure(snap, int(params["device"]), int(params["port"]), params["from_zone"])
    elif key == "failure":
        res = failure(snap, int(params["device"]))
    elif key == "restrict":
        res = restrict(snap, int(params["device"]), int(params["port"]))
    else:
        raise ValueError("Unknown scenario")
    db.run("INSERT INTO scenario_runs(scenario,params,result,created_at,user) VALUES(?,?,?,?,?)", (key, json.dumps(params), json.dumps(res), util.now(), user))
    return res
