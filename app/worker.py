"""Background scan worker: one queued scan at a time, plus a periodic stale-device sweep."""

from __future__ import annotations

import ipaddress
import json
import shutil
import threading
import time
from pathlib import Path

from netrik.utils.validation import parse_targets, parse_ports

from . import config, db, detect, ingest, progress, util, verify
from .sources import arp_source, dhcp_source, names, nmap_source

_thread = None


def start():
    global _thread
    if _thread and _thread.is_alive():
        return
    db.run("UPDATE scans SET status='failed', error='Interrupted by a restart', finished_at=? WHERE status='running'", (util.now(),))
    _thread = threading.Thread(target=_loop, name="netrik-worker", daemon=True)
    _thread.start()


def _loop():
    last_sweep = 0
    while True:
        try:
            row = db.one("SELECT * FROM scans WHERE status='queued' ORDER BY id LIMIT 1")
            if row:
                execute(row)
                continue
            if time.time() - last_sweep > 60:
                detect.sweep_stale()
                last_sweep = time.time()
        except Exception as exc:  # the worker must survive any single failure
            print("worker error:", exc)
        time.sleep(1)


def _update(sid, **kw):
    sets = ",".join(f"{k}=?" for k in kw)
    db.run(f"UPDATE scans SET {sets} WHERE id=?", (*kw.values(), sid))


def _in_scope(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def known_live_ips(nets, hours=None) -> list:
    """Addresses that some source reported recently inside the given networks."""
    cutoff = util.shift(hours or config.cfg()["stale_hours"])
    ips = {r["value"] for r in db.q("SELECT value FROM identifiers WHERE type='ip' AND last_seen>=?", (cutoff,)) if _in_scope(r["value"], nets)}
    return sorted(ips, key=ipaddress.ip_address)


class _Live:
    """Writes the tracker snapshot to the scan row at most once a second."""

    def __init__(self, sid, tracker):
        self.sid, self.t, self.last = sid, tracker, 0.0

    def push(self, force=False):
        if not force and time.time() - self.last < 1.0:
            return
        self.last = time.time()
        snap = self.t.snapshot()
        rem = f", about {snap['remaining_s'] // 60}:{snap['remaining_s'] % 60:02d} left in this stage" if snap["remaining_s"] else ""
        _update(self.sid, progress=snap["percent"], live=json.dumps(snap), message=f"{snap['label']}: {snap['stage_percent']:.0f}%{rem}")


def _add_names(obs, nets, sid, live=None):
    """Fill missing hostnames (DNS via the router, mDNS, NetBIOS, LLMNR, UPnP). Labels only, never presence evidence."""
    need = sorted({o["ip"] for o in obs if o.get("ip") and not o.get("hostname") and _in_scope(o["ip"], nets)})
    if not need or not config.cfg()["name_lookup"]:
        return 0, {}
    _update(sid, message=f"Looking up hostnames for {len(need)} address(es)")
    if live:
        live.t.enter("names")
        live.t._event("info", f"Asking {len(need)} address(es) for their names: router DNS, mDNS, NetBIOS, LLMNR, UPnP")
        live.push(True)
    rep = names.resolve_report(need, nets=nets)
    for o in obs:
        r = rep.get(o.get("ip"))
        if r and r["name"] and not o.get("hostname"):
            o["hostname"] = r["name"]
            o["detail"] = {**(o.get("detail") or {}), "name_source": r["method"]}
    extras = {ip: r["extras"] for ip, r in rep.items() if ip != "_meta" and r["extras"]}
    return sum(1 for ip, r in rep.items() if ip != "_meta" and r["name"]), extras


def execute(s):
    sid = s["id"]
    _update(sid, status="running", started_at=util.now(), message="Starting")
    try:
        c = config.cfg()
        if s["kind"] == "names":
            return _run_names(s, c)
        targets = parse_targets(s["target"], config.allowed_networks(), c["max_targets"])  # re-check before running
        ports = parse_ports(s["ports"])
        profile = "discovery" if s["kind"] == "discovery" else s["profile"]
        if profile not in nmap_source.profiles():
            raise ValueError(f"Unknown scan profile '{profile}'.")
        nets = [ipaddress.ip_network(t, strict=False) for t in targets]
        if s["live_only"] and s["kind"] != "discovery":
            live = known_live_ips(nets)
            if not live:
                raise ValueError("No recently seen hosts in that range. Run a discovery scan first, or untick 'known live hosts only'.")
            targets = live
        obs, partial = [], False
        host_count = len(targets) if s["live_only"] else sum(n.num_addresses for n in nets)
        base_args = nmap_source.profiles()[profile]["nmap_args"]
        tracker = progress.Tracker(progress.plan_for(s["kind"], base_args, c["nmap_privileged"]),
                                   nmap_source.estimate_seconds(profile, host_count, ports, c["max_rate"]) if s["kind"] == "portscan" else None)
        live = _Live(sid, tracker)
        live.push(True)
        xml_path = str(config.RAW / f"scan_{sid}.xml")
        txt_path = str(config.RAW / f"scan_{sid}.txt")
        notes = util.jl(s["notes"], []) + (nmap_source.notes_for(profile, c["nmap_privileged"]) if shutil.which("nmap") else [])

        if shutil.which("nmap"):
            args = nmap_source.build_args(profile, targets, ports, c["nmap_privileged"], c["max_rate"], xml_path, txt_path, c["host_timeout_minutes"])
            _update(sid, command="nmap " + " ".join(args[:-len(targets)]) + (f" {targets[0]}" if len(targets) == 1 else f" <{len(targets)} addresses>"),
                    xml_path=xml_path, txt_path=txt_path)

            def on_line(line):
                tracker.on_line(line)
                live.push()

            def on_tick():
                if Path(xml_path).exists() and int(time.time()) % 2 == 0:
                    try:
                        tracker.on_xml(Path(xml_path).read_text(errors="replace"))
                    except OSError:
                        pass
                live.push()

            cancelled = lambda: bool(db.one("SELECT cancel FROM scans WHERE id=?", (sid,))["cancel"])
            text, rc = nmap_source.run(args, on_line, cancelled, c["scan_timeout_minutes"] * 60, on_tick)
            if rc == "cancelled":
                _update(sid, status="cancelled", finished_at=util.now(), message="Cancelled by the operator")
                return
            if rc == "timeout":
                partial = True
                notes.append(f"The scan reached the {c['scan_timeout_minutes']}-minute limit and was stopped. Only hosts that had finished are included; others were not covered.")
            elif rc != 0:
                raise RuntimeError(nmap_source.clean_text(text).strip()[-400:] or f"Nmap exited with status {rc}.")
            if Path(xml_path).exists():
                for h in nmap_source.parse_xml(xml_path):
                    obs.append({"source": "nmap", **h, "detail": {"profile": profile, **({"name_source": "dns"} if h.get("hostname") else {})}})
            if "skipping host" in text.lower():
                notes.append("At least one host hit the per-host time limit and was skipped. Scan it on its own from its device page.")
        elif s["kind"] != "discovery":
            raise RuntimeError("Nmap was not found. Install it (sudo apt install nmap) and retry.")

        if s["kind"] == "discovery":  # extra, independent evidence sources inside the authorised range
            tracker.enter("neighbours")
            tracker._event("info", "Reading the neighbour table and DHCP leases")
            live.push(True)
            _update(sid, message="Reading neighbour table and DHCP leases")
            for o in arp_source.collect() + dhcp_source.collect_configured():
                if o.get("ip") and _in_scope(o["ip"], nets):
                    obs.append(o)
                elif not o.get("ip") and o.get("ip6") and util.norm_mac(o.get("mac")) in {util.norm_mac(x.get("mac")) for x in obs if x.get("ip")}:
                    obs.append(o)

        names_found, extras = _add_names(obs, nets, sid, live)
        tracker.enter("save")
        live.push(True)
        res = ingest.ingest(obs, scan_id=sid, profile=profile, ports_spec=ports)
        ingest.store_hosts(sid, obs, res["device_ids"])
        ingest.apply_extras(extras)
        hosts = [o for o in obs if o["source"] == "nmap"]
        summary = {"hosts_up": len(hosts), "observations": len(obs), "new_devices": len(res["created"]), "names_found": names_found,
                   "open_ports": sum(1 for o in hosts for p in (o.get("ports") or []) if p["state"] == "open"),
                   "sources": sorted({o["source"] for o in obs}), "partial": partial,
                   "timeline": nmap_source.timeline(xml_path) if Path(xml_path).exists() else {}}
        summary["alerts"] = db.one("SELECT COUNT(*) n FROM alerts WHERE scan_id=?", (sid,))["n"]
        tracker.finish()
        _update(sid, status="partial" if partial else "complete", progress=100, finished_at=util.now(), summary=json.dumps(summary), live=json.dumps(tracker.snapshot()),
                notes=json.dumps(notes), message="Stopped at the time limit" if partial else "Complete")
        if s["verify_alert"]:
            verify.evaluate(s["verify_alert"], sid)
        db.audit(s["requested_by"], "scan_complete", f"scan #{sid} {s['target']} ({profile})")
    except Exception as exc:
        _update(sid, status="failed", error=str(exc), finished_at=util.now(), message="Failed")
        db.audit(s["requested_by"], "scan_failed", f"scan #{sid}: {exc}")


def _run_names(s, c):
    sid = s["id"]
    nets = config.allowed_networks()
    ips = known_live_ips(nets, hours=24 * 14)
    if not ips:
        raise ValueError("No known devices to look up. Run a discovery scan first.")
    tracker = progress.Tracker(["names", "save"])
    tracker._event("info", f"Asking {len(ips)} known address(es) for their names")
    _update(sid, message=f"Looking up names for {len(ips)} address(es)", live=json.dumps(tracker.snapshot()))
    rep = names.resolve_report(ips, total_timeout=60, nets=nets)
    meta = rep.pop("_meta")
    found = {ip: (r["name"], r["method"]) for ip, r in rep.items() if r["name"]}
    n = ingest.apply_names(found, {ip: r["extras"] for ip, r in rep.items() if r["extras"]})
    summary = {"looked_up": len(ips), "names_found": n, "meta": meta,
               "found": [{"ip": ip, "name": v[0], "method": v[1]} for ip, v in sorted(found.items())],
               "matrix": [{"ip": ip, "name": r["name"], "method": r["method"], "tried": r["tried"], "extras": r["extras"]} for ip, r in sorted(rep.items())][:300]}
    _update(sid, status="complete", progress=100, finished_at=util.now(), summary=json.dumps(summary), message=f"{n} name(s) found")
    db.audit(s["requested_by"], "name_lookup", f"scan #{sid}: {n} of {len(ips)}")
