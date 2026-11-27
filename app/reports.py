"""Exports: TXT, XML, JSON, HTML and PDF for scans; CSV, JSON and HTML for the inventory."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from . import advice, config, db, util, visibility

env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")), autoescape=True)
env.filters["local"] = util.local
env.filters["fromjson"] = util.jl


def scan_context(sid: int) -> dict | None:
    s = db.one("SELECT * FROM scans WHERE id=?", (sid,))
    if not s:
        return None
    hosts = []
    for h in db.q("SELECT sh.*, d.label FROM scan_hosts sh LEFT JOIN devices d ON d.id=sh.device_id WHERE sh.scan_id=? ORDER BY sh.id", (sid,)):
        data = util.jl(h["data"])
        data["device_id"], data["label"] = h["device_id"], h["label"]
        for p in data.get("ports") or []:
            p["note"] = advice.port_note(p["port"]) if p["state"] == "open" and p["port"] in config.cfg()["sensitive_ports"] else None
        hosts.append(data)
    alerts = [dict(a, detail=util.jl(a["detail"])) for a in db.q("SELECT * FROM alerts WHERE scan_id=? ORDER BY id", (sid,))]
    return {"scan": s, "summary": util.jl(s["summary"]), "hosts": hosts, "alerts": alerts, "generated": util.now(), "collector": config.collector_name()}


def scan_json(sid: int) -> str:
    c = scan_context(sid)
    c["scan"] = dict(c["scan"])
    for a in c["alerts"]:
        a.pop("detail", None)
    return json.dumps(c, indent=2, default=str)


def scan_html(sid: int) -> str:
    return env.get_template("report_scan.html").render(**scan_context(sid))


def _latin(t) -> str:
    return str(t).encode("latin-1", "replace").decode("latin-1")


def _pdf(title: str, sections: list) -> bytes:
    from fpdf import FPDF
    pdf = FPDF()
    pdf.set_auto_page_break(True, 15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.multi_cell(0, 9, _latin(title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5, _latin(f"Generated {util.local(util.now())} by Netrik. Findings are evidence from the stated sources, not proof of compromise."), new_x="LMARGIN", new_y="NEXT")
    for head, lines in sections:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 12)
        pdf.multi_cell(0, 7, _latin(head), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Courier", "", 8)
        for l in lines:
            pdf.multi_cell(0, 4.2, _latin(l), new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())


def scan_pdf(sid: int) -> bytes:
    c = scan_context(sid)
    s = c["scan"]
    secs = [("Scan", [f"ID: #{s['id']}   Kind: {s['kind']}   Profile: {s['profile'] or '-'}", f"Target: {s['target']}   Status: {s['status']}",
                      f"Started: {util.local(s['started_at'])}   Finished: {util.local(s['finished_at'])}   From: {c['collector']}"])]
    for h in c["hosts"]:
        lines = [f"{h['ip']}  {h.get('label') or ''}  MAC {h.get('mac') or '-'}  {h.get('vendor') or ''}", f"  Role: {h.get('kind')} ({h['classification']['confidence']} confidence)"]
        for p in h.get("ports") or []:
            if p["state"] == "open":
                lines.append(f"  {p['port']}/{p['protocol']}  {p['service']} {p.get('product', '')} {p.get('version', '')}".rstrip())
        secs.append((f"Host {h['ip']}", lines))
    if c["alerts"]:
        secs.append(("Findings from this scan", [f"[{a['severity']}] {a['title']}" for a in c["alerts"]]))
    return _pdf(f"Scan report #{sid}", secs)


def inventory_rows() -> list:
    baseline = db.setting("baseline_set") == "1"
    recent = visibility.sources_by_device(config.cfg()["stale_hours"])
    rows = []
    for d in db.q("SELECT * FROM devices ORDER BY zone, label"):
        ids = {}
        for i in db.q("SELECT type,value FROM identifiers WHERE device_id=? ORDER BY last_seen DESC", (d["id"],)):
            ids.setdefault(i["type"], i["value"])
        ports = ", ".join(str(p["port"]) for p in db.q("SELECT port FROM services WHERE device_id=? AND open_now=1 ORDER BY port", (d["id"],)))
        rows.append({"label": d["label"], "ip": ids.get("ip", ""), "mac": ids.get("mac", ""), "hostname": ids.get("hostname", ""), "zone": d["zone"], "kind": d["kind"],
                     "status": visibility.device_status(d, baseline), "sources": ", ".join(sorted(recent.get(d["id"], {}))), "open_ports": ports,
                     "first_seen": d["first_seen"], "last_seen": d["last_seen"], "confidence": d["confidence"]})
    return rows


def inventory_csv() -> str:
    rows = inventory_rows()
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()) if rows else ["label"])
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def inventory_json() -> str:
    return json.dumps({"generated": util.now(), "note": "Evidence counts, not a guaranteed count of all connected devices.", "devices": inventory_rows()}, indent=2)


def inventory_html() -> str:
    return env.get_template("report_inventory.html").render(rows=inventory_rows(), vis=visibility.summary(), generated=util.now(), collector=config.collector_name())


def inventory_pdf() -> bytes:
    rows = inventory_rows()
    vis = visibility.summary()
    secs = [("Coverage", [f"{vis['total']} devices have evidence from at least one source. This is not a guaranteed count of all connected devices.",
                          *[f"{visibility.SOURCES[k][0]}: {n} device(s) in the last {vis['window']} h" for k, n in vis["per_source"].items() if n]]),
            ("Inventory", [f"{r['ip']:<15} {r['label'][:24]:<24} {r['zone'][:16]:<16} {r['status']:<10} {r['sources']}" for r in rows])]
    return _pdf("Network visibility report", secs)
