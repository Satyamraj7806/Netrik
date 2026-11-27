"""Synthetic college network for rehearsals and as a fallback when no real network is available.

Everything created here is marked demo=1, shown with a DEMO banner, and removable. It runs through the
real ingest and detection code, so the alerts you see are produced by the actual rules.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from . import config, db, detect, ingest, util, webpolicy

ZONES = ["Computer Lab", "Staff Network", "Server Room", "Student Wi-Fi", "Guest Wi-Fi"]
POLICY = [{"from": "Student Wi-Fi", "to": "Server Room", "ports": [445, 3389, 3306]},
          {"from": "Guest Wi-Fi", "to": "Staff Network", "ports": []}]
NAMES = {22: "ssh", 80: "http", 135: "msrpc", 389: "ldap", 443: "https", 445: "microsoft-ds", 631: "ipp", 3306: "mysql", 3389: "ms-wbt-server"}


def _port(n):
    return {"port": n, "protocol": "tcp", "state": "open", "service": NAMES.get(n, "unknown"), "product": "", "version": ""}


def _ts(hours_ago):
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime(util.FMT)


def _devices(second: bool):
    d = []

    def add(host, zone, ip, mac, vendor, ports, kind, nmap=True, extra=()):
        d.append(dict(host=host, zone=zone, ip=ip, mac=mac, vendor=vendor, ports=ports, kind=kind, nmap=nmap, extra=extra))

    add("core-router", "Server Room", "10.20.3.1", "00:1a:2b:00:03:01", "Cisco", [443], "Gateway / router")
    for i in range(1, 9):
        p = [445] if i == 5 else []
        if second and i == 8:
            p = [3389]
        add(f"LAB-PC-{i:02d}", "Computer Lab", f"10.20.1.{10 + i}", f"00:50:56:01:00:{i:02x}", "Dell", p, "Windows host", extra=("dhcp",))
    for i in range(1, 4):
        add(f"STAFF-LAP-{i:02d}", "Staff Network", f"10.20.2.{20 + i}", f"3c:52:82:02:00:{i:02x}", "HP", [], "Windows host", nmap=(i != 3), extra=("dhcp",))
    for i in range(1, 3):
        add(f"FAC-PC-{i:02d}", "Staff Network", f"10.20.2.{30 + i}", f"3c:52:82:03:00:{i:02x}", "Lenovo", [], "Windows host", extra=("dhcp",))
    add("EXAM-SRV", "Server Room", "10.20.3.10", "00:0c:29:03:00:10", "VMware", [80, 443] + ([445] if second else []), "Linux host", extra=("zeek",) if second else ())
    add("FEE-DB-SRV", "Server Room", "10.20.3.11", "00:0c:29:03:00:11", "VMware", [22, 3306], "Linux host", extra=("zeek",) if second else ())
    add("AD-SRV", "Server Room", "10.20.3.12", "00:0c:29:03:00:12", "VMware", [389], "Windows host", extra=("zeek",) if second else ())
    add("WEB-PORTAL", "Server Room", "10.20.3.13", "00:0c:29:03:00:13", "VMware", [80, 443], "Linux host", extra=("zeek",) if second else ())
    add("PRN-LAB-01", "Computer Lab", "10.20.1.50", "00:17:c8:01:00:50", "Kyocera", [631], "Printer")
    add("PRN-STAFF-01", "Staff Network", "10.20.2.50", "00:17:c8:02:00:50", "Kyocera", [631], "Printer")
    add("AP-LIBRARY-01", "Student Wi-Fi", "10.20.4.2", "f4:92:bf:04:00:02", "Ubiquiti", [443], "Network appliance")
    if not second:
        add("OLD-NAS-01", "Server Room", "10.20.3.40", "00:11:32:03:00:40", "Synology", [80, 23], "Linux host")
    if second:
        add("", "Computer Lab", "10.20.1.77", "dc:a6:32:01:00:77", "Raspberry Pi Trading", [], "Unknown", extra=("dhcp",))
    return d


PHONES = [("Galaxy-S23", "da:11:22:33:44:01", "10.20.4.101"), ("", "2e:11:22:33:44:02", "10.20.4.102"), ("iPhone", "be:11:22:33:44:03", "10.20.4.103"),
          ("", "7a:11:22:33:44:04", "10.20.4.104"), ("Redmi-Note-12", "9a:11:22:33:44:05", "10.20.4.105"), ("", "c6:11:22:33:44:06", "10.20.4.106")]


def _observations(second: bool) -> list:
    obs = []
    for x in _devices(second):
        base = {"ip": x["ip"], "mac": x["mac"], "hostname": x["host"] or None, "zone": x["zone"]}
        obs.append({"source": "arp", **base})
        if x["nmap"]:
            obs.append({"source": "nmap", **base, "vendor": x["vendor"], "ports": [_port(p) for p in x["ports"]], "os_matches": []})
        if "dhcp" in x["extra"]:
            obs.append({"source": "dhcp", **base})
    for host, mac, ip in PHONES[: 6 if second else 4]:
        base = {"ip": ip, "mac": mac, "hostname": host or None, "zone": "Student Wi-Fi"}
        obs.append({"source": "ap", **base, "detail": {"ssid": "College-WiFi"}})
        obs.append({"source": "dhcp", **base})
        if not second:
            obs.append({"source": "arp", **base})
    if second:  # passive monitor only sees traffic that crosses it
        for x in _devices(True):
            if "zeek" in x["extra"]:
                obs.append({"source": "zeek", "ip": x["ip"]})
    return obs


def _scan(target, hours_ago, hosts, txt):
    sid = db.run("""INSERT INTO scans(kind,target,profile,status,progress,message,created_at,started_at,finished_at,requested_by,summary,demo)
                    VALUES('portscan',?,?,'complete',100,'Complete (demo)',?,?,?,'demo',?,1)""",
                 (target, "quick", _ts(hours_ago), _ts(hours_ago), _ts(hours_ago - 0.05), json.dumps({"hosts_up": hosts, "demo": True})))
    p = config.RAW / f"scan_{sid}.txt"
    p.write_text(txt)
    db.run("UPDATE scans SET txt_path=?, command='(demo data - no real command was run)' WHERE id=?", (str(p), sid))
    return sid


def seed():
    if db.one("SELECT 1 FROM devices LIMIT 1"):
        raise ValueError("Demo data can only be loaded into an empty database. Clear existing data first.")
    db.set_setting("demo", "1")
    db.set_setting("demo_policy", json.dumps(POLICY))
    db.set_setting("demo_vantage", "Student Wi-Fi")
    db.set_setting("baseline_set", "0")
    now = util.now()
    db.run("INSERT INTO policy_rules(kind,name,domains,zone,severity,block,enabled,created_by,created_at) VALUES('site','No social media or betting','facebook.com,instagram.com,bet365.com','All zones','high',0,1,'demo',?)", (now,))
    db.run("INSERT INTO policy_rules(kind,name,ports,zone,severity,enabled,created_by,created_at) VALUES('port_forbid','Telnet must never run','23','All zones','high',1,'demo',?)", (now,))
    note = "DEMO DATA - synthetic scan record, no real network was scanned.\n"
    for second, hours in ((False, 72), (True, 2)):
        obs = _observations(second)
        sid = _scan("10.20.0.0/21", hours, sum(1 for o in obs if o["source"] == "nmap"), note + f"Synthetic results for {sum(1 for o in obs if o['source'] == 'nmap')} hosts.\n")
        res = ingest.ingest(obs, scan_id=sid, ts=_ts(hours), vantage="Test laptop (demo)", profile="quick")
        ingest.store_hosts(sid, obs, res["device_ids"])
        if not second:
            db.run("UPDATE devices SET approved=1")
            db.set_setting("baseline_set", "1")
    flows = []
    for i in range(1, 9):
        flows += [{"src": f"10.20.1.{10 + i}", "dst": "10.20.3.10", "port": 443, "count": 40 + i}, {"src": f"10.20.1.{10 + i}", "dst": "10.20.3.12", "port": 389, "count": 90}]
    for i in range(1, 4):
        flows += [{"src": f"10.20.2.{20 + i}", "dst": "10.20.3.11", "port": 3306, "count": 25}, {"src": f"10.20.2.{20 + i}", "dst": "10.20.3.13", "port": 443, "count": 60}]
    flows += [{"src": "10.20.3.10", "dst": "10.20.3.11", "port": 3306, "count": 300}, {"src": "10.20.3.13", "dst": "10.20.3.11", "port": 3306, "count": 120}]
    ingest.ingest_flows(flows, "demo", _ts(2))
    kinds = {x["host"]: x["kind"] for x in _devices(True) + _devices(False) if x["host"]}
    for h, k in kinds.items():
        db.run("UPDATE devices SET kind=? WHERE label=?", (k, h))
    for host, mac, ip in PHONES:
        db.run("UPDATE devices SET kind='Mobile device (likely)' WHERE id IN (SELECT device_id FROM identifiers WHERE type='mac' AND value=?)", (mac,))
    db.run("UPDATE devices SET demo=1")
    webpolicy.record_many([(_ts(1.2), "10.20.1.18", "facebook.com"), (_ts(1.1), "10.20.1.18", "m.facebook.com"), (_ts(0.9), "10.20.1.18", "facebook.com"),
                           (_ts(0.5), "10.20.4.101", "bet365.com"), (_ts(0.3), "10.20.1.14", "instagram.com")], "demo web log")
    detect.sweep_stale()
    db.audit("system", "demo_loaded", "synthetic college network")


def clear():
    ids = [r["id"] for r in db.q("SELECT id FROM devices WHERE demo=1")]
    with db.tx() as c:
        marks = ",".join("?" * len(ids)) or "NULL"
        alert_ids = [r["id"] for r in c.execute(f"SELECT id FROM alerts WHERE device_id IN ({marks})", ids)]
        am = ",".join("?" * len(alert_ids)) or "NULL"
        c.execute(f"DELETE FROM verifications WHERE alert_id IN ({am})", alert_ids)
        c.execute(f"DELETE FROM alerts WHERE id IN ({am})", alert_ids)
        for t in ("identifiers", "observations", "services", "scan_hosts"):
            c.execute(f"DELETE FROM {t} WHERE device_id IN ({marks})", ids)
        c.execute("DELETE FROM devices WHERE demo=1")
        c.execute("DELETE FROM flows WHERE source='demo'")
        c.execute("DELETE FROM policy_rules WHERE created_by='demo'")
        c.execute("DELETE FROM web_events WHERE source LIKE 'demo%'")
        c.execute("DELETE FROM scan_hosts WHERE scan_id IN (SELECT id FROM scans WHERE demo=1)")
        c.execute("DELETE FROM scans WHERE demo=1")
        c.execute("DELETE FROM scenario_runs")
        c.execute("DELETE FROM settings WHERE key IN ('demo','demo_policy','demo_vantage')")
        if not c.execute("SELECT 1 FROM devices LIMIT 1").fetchone():
            c.execute("DELETE FROM settings WHERE key='baseline_set'")
    db.audit("system", "demo_cleared", "")
