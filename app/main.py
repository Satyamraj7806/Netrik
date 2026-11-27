"""Netrik web application."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from netrik.core.profiles import scan_profiles
from netrik.utils.validation import parse_ports, parse_targets

from . import advice, auth, charts, config, db, dedupe, demo, dnsmon, webpolicy, ingest, policy, reports, simulate, twin, util, verify, visibility, worker
from .sources import import_source, names as names_mod, nmap_source, weblog_source

BASE = Path(__file__).parent


@asynccontextmanager
async def lifespan(app):
    db.init()
    worker.start()
    if db.setting("dns_monitor") == "1":
        try:
            dnsmon.start_from_config()
        except OSError as e:
            print("DNS monitor could not start:", e)
    yield
    dnsmon.stop()


app = FastAPI(title="Netrik", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=config.secret_key(), same_site="strict", https_only=False, max_age=8 * 3600, session_cookie="netrik_session")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.filters.update(local=util.local, ago=util.ago, fromjson=util.jl)


class NeedLogin(Exception):
    pass


@app.exception_handler(NeedLogin)
async def _need_login(request, exc):
    return RedirectResponse("/login" if db.one("SELECT 1 FROM users LIMIT 1") else "/setup", 303)


@app.middleware("http")
async def _guard(request: Request, call_next):
    if request.method == "POST":  # simple CSRF defence on top of SameSite=strict cookies
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host"):
            return PlainTextResponse("Cross-site request blocked.", status_code=403)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; frame-ancestors 'none'"
    return resp


def need(request: Request) -> str:
    u = request.session.get("user")
    if not u:
        raise NeedLogin()
    return u


def flash(request, msg, kind="ok"):
    request.session["flash"] = {"msg": msg, "kind": kind}


def render(request, name, **ctx):
    ctx.update(user=request.session.get("user"), flash=request.session.pop("flash", None), demo=policy.demo_on(), path=request.url.path,
               open_alerts=db.one("SELECT COUNT(*) n FROM alerts WHERE status IN ('open','investigating')")["n"],
               baseline=db.setting("baseline_set") == "1")
    return templates.TemplateResponse(request, name, ctx)


# ---------------------------------------------------------------- auth
_fails: dict = {}


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if db.one("SELECT 1 FROM users LIMIT 1"):
        return RedirectResponse("/login", 303)
    return render(request, "login.html", mode="setup", error=None)


@app.post("/setup")
async def setup_post(request: Request):
    if db.one("SELECT 1 FROM users LIMIT 1"):
        return RedirectResponse("/login", 303)
    f = await request.form()
    try:
        if f.get("password") != f.get("confirm"):
            raise ValueError("The two passwords do not match.")
        auth.set_user((f.get("username") or "admin").strip()[:40] or "admin", f.get("password", ""))
    except ValueError as e:
        return render(request, "login.html", mode="setup", error=str(e))
    request.session["user"] = (f.get("username") or "admin").strip()[:40] or "admin"
    db.audit(request.session["user"], "setup", "administrator created")
    return RedirectResponse("/", 303)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not db.one("SELECT 1 FROM users LIMIT 1"):
        return RedirectResponse("/setup", 303)
    return render(request, "login.html", mode="login", error=None)


@app.post("/login")
async def login_post(request: Request):
    ip = request.client.host if request.client else "?"
    recent = [t for t in _fails.get(ip, []) if time.time() - t < 300]
    if len(recent) >= 5:
        return render(request, "login.html", mode="login", error="Too many failed attempts. Wait five minutes.")
    f = await request.form()
    name = (f.get("username") or "").strip()
    if auth.verify(name, f.get("password", "")):
        request.session["user"] = name
        db.audit(name, "login", ip)
        return RedirectResponse("/", 303)
    _fails[ip] = recent + [time.time()]
    db.audit(name or "?", "login_failed", ip)
    return render(request, "login.html", mode="login", error="Wrong username or password.")


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", 303)


# ---------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    need(request)
    vis = visibility.summary()
    sev = {r["severity"]: r["n"] for r in db.q("SELECT severity, COUNT(*) n FROM alerts WHERE status IN ('open','investigating') GROUP BY severity")}
    alerts = db.q("""SELECT a.*, d.label dlabel FROM alerts a LEFT JOIN devices d ON d.id=a.device_id WHERE a.status IN ('open','investigating')
                     ORDER BY CASE a.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, a.updated_at DESC LIMIT 6""")
    c = vis["cats"]
    segs = [("Responded to active scan", len(c["active"]), "var(--ok)"), ("Reported by infrastructure only", len(c["infra"]), "var(--info)"),
            ("Passive monitoring only", len(c["passive"]), "#7d8fa6"), ("Neighbour table only", len(c["neighbour"]), "var(--warn)"),
            ("Not seen recently", len(c["stale"]), "#4a5667")]
    days = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(13, -1, -1)]
    per_day = {r["day"]: r["n"] for r in db.q("SELECT substr(observed_at,1,10) day, COUNT(DISTINCT device_id) n FROM observations WHERE observed_at>=? GROUP BY day", (days[0],))}
    last_scan = db.one("SELECT * FROM scans WHERE status IN ('complete','partial') ORDER BY id DESC LIMIT 1")
    return render(request, "dashboard.html", vis=vis, sevs=sev, alerts=alerts, scans=db.q("SELECT * FROM scans ORDER BY id DESC LIMIT 5"),
                  src_labels=visibility.SOURCES, last_scan=last_scan, segs=segs, activity=db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 7"),
                  donut=charts.donut(segs, center=str(vis["total"]), sub="devices"),
                  bars=charts.bars([per_day.get(d, 0) for d in days], days),
                  scanning=db.one("SELECT COUNT(*) n FROM scans WHERE status IN ('queued','running')")["n"])


# ---------------------------------------------------------------- devices
@app.get("/devices", response_class=HTMLResponse)
async def devices(request: Request):
    need(request)
    qp = request.query_params
    baseline = db.setting("baseline_set") == "1"
    recent = visibility.sources_by_device(config.cfg()["stale_hours"])
    ips = {}
    for r in db.q("SELECT device_id, type, value FROM identifiers WHERE type IN ('ip','mac') ORDER BY last_seen"):
        ips.setdefault(r["device_id"], {})[r["type"]] = r["value"]
    rows = []
    for d in db.q("SELECT * FROM devices ORDER BY last_seen DESC"):
        st = visibility.device_status(d, baseline)
        i = ips.get(d["id"], {})
        row = dict(d, status=st, ip=i.get("ip", ""), mac=i.get("mac", ""), sources=sorted(recent.get(d["id"], {})))
        text = qp.get("q", "").lower().strip()
        if text and text not in " ".join(str(v) for v in (row["label"], row["ip"], row["mac"], row["vendor"], row["kind"], row["zone"])).lower():
            continue
        if qp.get("zone") and row["zone"] != qp["zone"]:
            continue
        if qp.get("status") and row["status"] != qp["status"]:
            continue
        if qp.get("source") and qp["source"] not in row["sources"]:
            continue
        rows.append(row)
    return render(request, "devices.html", rows=rows, zones=policy.zone_names(), q=qp, src_labels=visibility.SOURCES, total=db.one("SELECT COUNT(*) n FROM devices")["n"])


@app.get("/devices/duplicates", response_class=HTMLResponse)
async def duplicates_page(request: Request):
    need(request)
    return render(request, "duplicates.html", groups=dedupe.candidates(), merges=db.q("SELECT * FROM device_merges ORDER BY id DESC LIMIT 25"))


@app.post("/devices/dedupe")
async def dedupe_run(request: Request):
    u = need(request)
    with db.tx() as c:
        merged = dedupe.auto_merge(c, u)
    db.audit(u, "dedupe", f"{len(merged)} duplicate(s) merged")
    flash(request, f"{len(merged)} duplicate device(s) merged." if merged else "No safe duplicates found. Anything uncertain is listed below for you to decide.")
    return RedirectResponse("/devices/duplicates", 303)


@app.post("/devices/merge")
async def dedupe_merge(request: Request):
    u = need(request)
    f = await request.form()
    try:
        keep, drop = int(f["keep"]), int(f["drop"])
        with db.tx() as c:
            dedupe.merge(c, keep, drop, "merged by an administrator", u)
        db.audit(u, "device_merge", f"#{drop} into #{keep}")
        flash(request, "Devices merged. Their evidence, services and findings now belong to one device.")
    except (KeyError, ValueError):
        flash(request, "Choose two different devices to merge.", "err")
    return RedirectResponse("/devices/duplicates", 303)


@app.get("/devices/{did}", response_class=HTMLResponse)
async def device(request: Request, did: int):
    need(request)
    d = db.one("SELECT * FROM devices WHERE id=?", (did,))
    if not d:
        raise HTTPException(404, "Device not found")
    baseline = db.setting("baseline_set") == "1"
    return render(request, "device.html", d=d, dstatus=visibility.device_status(d, baseline), src_labels=visibility.SOURCES,
                  idents=db.q("SELECT * FROM identifiers WHERE device_id=? ORDER BY type, last_seen DESC", (did,)),
                  obs=db.q("SELECT * FROM observations WHERE device_id=? ORDER BY observed_at DESC, id DESC LIMIT 40", (did,)),
                  services=db.q("SELECT * FROM services WHERE device_id=? ORDER BY open_now DESC, port", (did,)),
                  alerts=db.q("SELECT * FROM alerts WHERE device_id=? ORDER BY id DESC LIMIT 20", (did,)),
                  scans=db.q("SELECT s.* FROM scans s JOIN scan_hosts h ON h.scan_id=s.id WHERE h.device_id=? ORDER BY s.id DESC LIMIT 10", (did,)),
                  recent=visibility.sources_by_device(config.cfg()["stale_hours"]).get(did, {}), sensitive=config.cfg()["sensitive_ports"],
                  profiles={k: v for k, v in nmap_source.profiles().items() if k != "discovery"}, name_labels=names_mod.LABEL)


@app.post("/devices/{did}/update")
async def device_update(request: Request, did: int):
    u = need(request)
    f = await request.form()
    if not db.one("SELECT 1 FROM devices WHERE id=?", (did,)):
        raise HTTPException(404)
    if "approve" in f:
        db.run("UPDATE devices SET approved=? WHERE id=?", (1 if f["approve"] == "1" else 0, did))
        db.audit(u, "device_approval", f"device #{did} -> {f['approve']}")
    if "label" in f and f["label"].strip():
        db.run("UPDATE devices SET label=?, note=?, label_auto=0 WHERE id=?", (f["label"].strip()[:60], (f.get("note") or "")[:300], did))
        db.audit(u, "device_renamed", f"device #{did}")
    flash(request, "Device updated.")
    return RedirectResponse(f"/devices/{did}", 303)


@app.get("/api/device/{did}")
async def api_device(request: Request, did: int):
    need(request)
    d = db.one("SELECT * FROM devices WHERE id=?", (did,))
    if not d:
        raise HTTPException(404)
    ident = {r["type"]: r["value"] for r in db.q("SELECT type,value FROM identifiers WHERE device_id=? ORDER BY last_seen", (did,))}
    return {"id": did, "label": d["label"], "kind": d["kind"], "zone": d["zone"], "vendor": d["vendor"], "ip": ident.get("ip"), "mac": ident.get("mac"),
            "last_seen": util.local(d["last_seen"]), "approved": bool(d["approved"]), "confidence": d["confidence"],
            "sources": sorted(visibility.sources_by_device(config.cfg()["stale_hours"]).get(did, {})),
            "ports": [{"port": s["port"], "name": s["name"]} for s in db.q("SELECT port,name FROM services WHERE device_id=? AND open_now=1 ORDER BY port", (did,))],
            "alerts": [{"id": a["id"], "title": a["title"], "severity": a["severity"]} for a in db.q("SELECT * FROM alerts WHERE device_id=? AND status IN ('open','investigating') LIMIT 5", (did,))]}


# ---------------------------------------------------------------- topology
@app.get("/topology", response_class=HTMLResponse)
async def topology(request: Request):
    need(request)
    return render(request, "topology.html", graph=twin.graph())


@app.get("/api/topology")
async def api_topology(request: Request):
    need(request)
    return twin.graph()


# ---------------------------------------------------------------- scans
@app.get("/scans", response_class=HTMLResponse)
async def scans(request: Request):
    need(request)
    return render(request, "scans.html", scans=db.q("SELECT * FROM scans ORDER BY id DESC LIMIT 100"), profiles=nmap_source.profiles(),
                  allowed=[str(n) for n in config.allowed_networks()], nmap_ok=bool(__import__("shutil").which("nmap")),
                  privileged=config.cfg()["nmap_privileged"], default_target=str(config.allowed_networks()[0]) if config.allowed_networks() else "")


def _queue_scan(u, kind, target_text, profile, ports, live_only):
    """Validate and queue a scan. Raises ValueError with a plain-language reason."""
    nets_text = parse_targets(target_text, config.allowed_networks(), config.cfg()["max_targets"])
    ports = parse_ports(ports) if kind == "portscan" else None
    if kind == "portscan" and profile not in scan_profiles:
        raise ValueError("Unknown scan profile.")
    if db.one("SELECT COUNT(*) n FROM scans WHERE status IN ('queued','running')")["n"] >= 5:
        raise ValueError("Five scans are already waiting. Let them finish first.")
    nets = [ipaddress.ip_network(t, strict=False) for t in nets_text]
    hosts = sum(n.num_addresses for n in nets)
    if live_only and kind == "portscan" and hosts > 1:
        live = worker.known_live_ips(nets)
        if not live:
            raise ValueError("No recently seen hosts in that range. Run a discovery scan first, or untick 'known live hosts only'.")
        hosts = len(live)
    else:
        live_only = False
    profile = "discovery" if kind == "discovery" else profile
    est = nmap_source.estimate_seconds(profile, hosts, ports, config.cfg()["max_rate"])
    notes = [f"Probe time alone is about {nmap_source.fmt_duration(est)} ({hosts} host(s) x {nmap_source.port_count(profile, ports)} ports at "
             f"{config.cfg()['max_rate']} packets/s). Service and OS detection add more."] if kind == "portscan" else []
    sid = db.run("INSERT INTO scans(kind,target,profile,ports,status,message,created_at,requested_by,live_only,notes) VALUES(?,?,?,?,'queued','Queued',?,?,?,?)",
                 (kind, " ".join(nets_text), profile, ports, util.now(), u, 1 if live_only else 0, json.dumps(notes)))
    db.audit(u, "scan_requested", f"scan #{sid}: {kind} {' '.join(nets_text)} ({profile})")
    return sid


@app.post("/scans")
async def scan_create(request: Request):
    u = need(request)
    f = await request.form()
    try:
        kind = f.get("kind", "discovery")
        if kind not in ("discovery", "portscan"):
            raise ValueError("Unknown scan type.")
        sid = _queue_scan(u, kind, f.get("target", ""), f.get("profile", "quick"), f.get("ports"), bool(f.get("live_only")))
    except ValueError as e:
        flash(request, str(e), "err")
        return RedirectResponse("/scans", 303)
    return RedirectResponse(f"/scans/{sid}", 303)


@app.post("/devices/lookup-names")
async def lookup_names(request: Request):
    u = need(request)
    if db.one("SELECT COUNT(*) n FROM scans WHERE status IN ('queued','running')")["n"] >= 5:
        flash(request, "Five scans are already waiting. Let them finish first.", "err")
        return RedirectResponse("/devices", 303)
    sid = db.run("INSERT INTO scans(kind,target,status,message,created_at,requested_by) VALUES('names','known devices','queued','Queued',?,?)", (util.now(), u))
    db.audit(u, "name_lookup_requested", f"scan #{sid}")
    return RedirectResponse(f"/scans/{sid}", 303)


@app.post("/devices/{did}/scan")
async def device_scan(request: Request, did: int):
    u = need(request)
    f = await request.form()
    r = db.one("SELECT value FROM identifiers WHERE device_id=? AND type='ip' ORDER BY last_seen DESC LIMIT 1", (did,))
    try:
        if not r:
            raise ValueError("This device has no known IP address to scan.")
        sid = _queue_scan(u, "portscan", r["value"], f.get("profile", "quick"), f.get("ports"), False)
    except ValueError as e:
        flash(request, str(e), "err")
        return RedirectResponse(f"/devices/{did}", 303)
    return RedirectResponse(f"/scans/{sid}", 303)


@app.get("/scans/{sid}", response_class=HTMLResponse)
async def scan_view(request: Request, sid: int):
    need(request)
    ctx = reports.scan_context(sid)
    if not ctx:
        raise HTTPException(404, "Scan not found")
    s = ctx["scan"]
    raw = ""
    if s["txt_path"] and Path(s["txt_path"]).exists():
        raw = Path(s["txt_path"]).read_text(errors="replace")
    prev = db.one("""SELECT id FROM scans WHERE id<? AND status='complete' AND kind=? AND target=? AND COALESCE(profile,'')=COALESCE(?, '') ORDER BY id DESC LIMIT 1""",
                  (sid, s["kind"], s["target"], s["profile"]))
    return render(request, "scan.html", raw=raw, prev=prev, notes=util.jl(s["notes"], []), tab=request.query_params.get("tab", "interpretation"),
                  profile_name=nmap_source.profiles().get(s["profile"], {}).get("name", s["profile"]), **ctx)


@app.get("/api/scans/{sid}")
async def scan_api(request: Request, sid: int):
    need(request)
    s = db.one("SELECT status,progress,message,error,live,started_at,kind,target FROM scans WHERE id=?", (sid,))
    if not s:
        raise HTTPException(404)
    pos = db.one("SELECT COUNT(*) n FROM scans WHERE id<? AND status IN ('queued','running')", (sid,))["n"] if s["status"] == "queued" else 0
    return {"status": s["status"], "progress": s["progress"], "message": s["message"], "error": s["error"], "live": util.jl(s["live"]),
            "elapsed_s": int(util.hours_since(s["started_at"]) * 3600) if s["started_at"] else 0, "queue_pos": pos}


@app.get("/api/activity")
async def activity_api(request: Request):
    need(request)
    r = db.one("SELECT id,kind,target,live,progress,started_at FROM scans WHERE status='running' ORDER BY id LIMIT 1")
    queued = db.one("SELECT COUNT(*) n FROM scans WHERE status='queued'")["n"]
    if not r:
        return {"running": False, "queued": queued}
    live = util.jl(r["live"])
    return {"running": True, "id": r["id"], "kind": r["kind"], "target": r["target"], "percent": r["progress"] or 0, "stage": live.get("label", "Starting"),
            "remaining_s": live.get("remaining_s"), "elapsed_s": int(util.hours_since(r["started_at"]) * 3600) if r["started_at"] else 0, "queued": queued}


@app.post("/scans/{sid}/cancel")
async def scan_cancel(request: Request, sid: int):
    u = need(request)
    db.run("UPDATE scans SET cancel=1 WHERE id=? AND status IN ('queued','running')", (sid,))
    db.run("UPDATE scans SET status='cancelled', finished_at=?, message='Cancelled before it started' WHERE id=? AND status='queued'", (util.now(), sid))
    db.audit(u, "scan_cancel", f"scan #{sid}")
    return RedirectResponse(f"/scans/{sid}", 303)


@app.get("/scans/{sid}/export/{fmt}")
async def scan_export(request: Request, sid: int, fmt: str):
    need(request)
    s = db.one("SELECT * FROM scans WHERE id=?", (sid,))
    if not s:
        raise HTTPException(404)
    name = f"netrik_scan_{sid}"
    dl = lambda ext: {"Content-Disposition": f'attachment; filename="{name}.{ext}"'}
    if fmt in ("txt", "xml"):
        p = s["txt_path"] if fmt == "txt" else s["xml_path"]
        if not p or not Path(p).exists():
            raise HTTPException(404, f"No raw {fmt.upper()} file exists for this scan (demo data has none).")
        return Response(Path(p).read_bytes(), media_type="text/plain" if fmt == "txt" else "application/xml", headers=dl(fmt))
    if fmt == "json":
        return Response(reports.scan_json(sid), media_type="application/json", headers=dl("json"))
    if fmt == "html":
        return HTMLResponse(reports.scan_html(sid), headers=dl("html"))
    if fmt == "pdf":
        return Response(reports.scan_pdf(sid), media_type="application/pdf", headers=dl("pdf"))
    raise HTTPException(404, "Unknown format")


@app.get("/compare", response_class=HTMLResponse)
async def compare(request: Request):
    need(request)
    qp = request.query_params
    all_scans = db.q("SELECT id,kind,target,profile,finished_at FROM scans WHERE status='complete' ORDER BY id DESC LIMIT 60")
    diff = None
    if qp.get("a") and qp.get("b"):
        a, b = int(qp["a"]), int(qp["b"])
        sa, sb = db.one("SELECT * FROM scans WHERE id=?", (a,)), db.one("SELECT * FROM scans WHERE id=?", (b,))
        if not sa or not sb:
            raise HTTPException(404)

        def load(sid):
            out = {}
            for h in db.q("SELECT ip, data FROM scan_hosts WHERE scan_id=?", (sid,)):
                data = util.jl(h["data"])
                out[h["ip"]] = {"label": data.get("hostname") or h["ip"], "ports": {(p["port"], p["protocol"]): p["service"] for p in (data.get("ports") or []) if p["state"] == "open"}, "scanned": data.get("ports") is not None}
            return out
        A, B = load(a), load(b)
        diff = {"a": sa, "b": sb, "new_hosts": sorted(set(B) - set(A)), "gone_hosts": sorted(set(A) - set(B)), "opened": [], "closed": [],
                "warn": [] if (sa["profile"], sa["ports"]) == (sb["profile"], sb["ports"]) else ["The two scans used different profiles or ports, so some differences may only reflect what each scan covered."]}
        for ip in sorted(set(A) & set(B)):
            if A[ip]["scanned"] and B[ip]["scanned"]:
                for k in sorted(set(B[ip]["ports"]) - set(A[ip]["ports"])):
                    diff["opened"].append((ip, k[0], k[1], B[ip]["ports"][k]))
                for k in sorted(set(A[ip]["ports"]) - set(B[ip]["ports"])):
                    diff["closed"].append((ip, k[0], k[1], A[ip]["ports"][k]))
        if sa["kind"] == "discovery" or sb["kind"] == "discovery":
            diff["warn"].append("A host missing from a later discovery scan is not proof that it went offline.")
    return render(request, "compare.html", all_scans=all_scans, diff=diff, qa=qp.get("a"), qb=qp.get("b"))


# ---------------------------------------------------------------- alerts
@app.get("/alerts", response_class=HTMLResponse)
async def alerts(request: Request):
    need(request)
    qp = request.query_params
    where, args = [], []
    st = qp.get("status", "active")
    if st == "active":
        where.append("a.status IN ('open','investigating')")
    elif st != "all":
        where.append("a.status=?"); args.append(st)
    if qp.get("severity"):
        where.append("a.severity=?"); args.append(qp["severity"])
    if qp.get("type"):
        where.append("a.type=?"); args.append(qp["type"])
    sql = "SELECT a.*, d.label dlabel FROM alerts a LEFT JOIN devices d ON d.id=a.device_id"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY CASE a.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, a.updated_at DESC LIMIT 300"
    types = [r["type"] for r in db.q("SELECT DISTINCT type FROM alerts")]
    return render(request, "alerts.html", rows=db.q(sql, args), q=qp, types=types, st=st)


@app.get("/alerts/{aid}", response_class=HTMLResponse)
async def alert_view(request: Request, aid: int):
    need(request)
    a = db.one("SELECT * FROM alerts WHERE id=?", (aid,))
    if not a:
        raise HTTPException(404)
    detail = util.jl(a["detail"])
    return render(request, "alert.html", a=a, detail=detail, adv=advice.get(a), device=db.one("SELECT * FROM devices WHERE id=?", (a["device_id"],)),
                  ver=db.q("SELECT * FROM verifications WHERE alert_id=? ORDER BY id DESC", (aid,)), can_verify=bool(detail.get("test")),
                  pending=db.one("SELECT id FROM scans WHERE verify_alert=? AND status IN ('queued','running')", (aid,)))


@app.post("/alerts/{aid}/decide")
async def alert_decide(request: Request, aid: int):
    u = need(request)
    f = await request.form()
    status = f.get("status")
    if status not in ("open", "investigating", "acknowledged", "resolved", "false_positive"):
        raise HTTPException(400)
    db.run("UPDATE alerts SET status=?, note=?, updated_at=? WHERE id=?", (status, (f.get("note") or "")[:500], util.now(), aid))
    db.audit(u, "alert_decision", f"alert #{aid} -> {status}: {(f.get('note') or '')[:120]}")
    flash(request, "Decision recorded.")
    return RedirectResponse(f"/alerts/{aid}", 303)


@app.post("/alerts/{aid}/verify")
async def alert_verify(request: Request, aid: int):
    u = need(request)
    try:
        sid = verify.start(aid, u)
    except ValueError as e:
        flash(request, str(e), "err")
        return RedirectResponse(f"/alerts/{aid}", 303)
    db.audit(u, "verification_requested", f"alert #{aid} -> scan #{sid}")
    flash(request, f"Verification scan #{sid} queued. Refresh this page when it finishes.")
    return RedirectResponse(f"/alerts/{aid}", 303)


# ---------------------------------------------------------------- visibility, sources
@app.get("/visibility", response_class=HTMLResponse)
async def visibility_page(request: Request):
    need(request)
    return render(request, "visibility.html", vis=visibility.summary(), src=visibility.SOURCES, check=None)


@app.post("/visibility/check", response_class=HTMLResponse)
async def visibility_check(request: Request):
    need(request)
    f = await request.form()
    tokens = [t for t in (f.get("known") or "").replace(",", "\n").splitlines() if t.strip()][:500]
    return render(request, "visibility.html", vis=visibility.summary(), src=visibility.SOURCES, check=visibility.completeness(tokens), known=f.get("known", ""))


@app.get("/sources", response_class=HTMLResponse)
async def sources(request: Request):
    need(request)
    rows = db.q("SELECT source, COUNT(*) n, MAX(observed_at) last FROM observations GROUP BY source")
    return render(request, "sources.html", rows=rows, src=visibility.SOURCES, leases=config.cfg()["dhcp_lease_files"], flows=db.one("SELECT COUNT(*) n FROM flows")["n"])


@app.post("/sources/import")
async def sources_import(request: Request):
    u = need(request)
    f = await request.form()
    up = f.get("file")
    try:
        if not up or not getattr(up, "filename", ""):
            raise ValueError("Choose a file to import.")
        raw = await up.read()
        if len(raw) > 5_000_000:
            raise ValueError("File is larger than 5 MB.")
        text, kind, msg = raw.decode("utf-8", errors="replace"), f.get("type"), ""
        if kind in ("dhcp", "ap"):
            from .sources import dhcp_source
            obs = dhcp_source.parse_text(text, source=kind) if kind == "dhcp" else import_source.parse_ap(text)
            if not obs:
                raise ValueError("No clients found. Expected dnsmasq/ISC leases or a CSV with mac, ip and hostname columns.")
            ingest.ingest(obs, vantage=f"import:{up.filename}")
            msg = f"Imported {len(obs)} {'DHCP lease' if kind == 'dhcp' else 'Wi-Fi client'} records."
        elif kind == "zeek":
            obs, flows = import_source.parse_zeek_conn(text)
            if not flows:
                raise ValueError("No connections found. Expected a Zeek conn.log (TSV with a #fields header).")
            ingest.ingest(obs, vantage=f"import:{up.filename}")
            ingest.ingest_flows(flows, "zeek")
            msg = f"Imported {len(flows)} flow summaries covering {len(obs)} addresses."
        elif kind == "web":
            ev = weblog_source.parse(text)
            if not ev:
                raise ValueError("No web requests found. Supported: Zeek dns.log, dnsmasq/Pi-hole query log, Squid access.log, CSV (client_ip,domain) or lines like '10.0.0.5 facebook.com'.")
            st = webpolicy.record_many([(None, ip, dom) for ip, dom in ev], f"web log: {up.filename}")
            msg = f"Read {st['processed']} web requests: {st['matched']} matched your rules, {st['alerts_new']} new finding(s)." if webpolicy.site_rules() else \
                  f"Read {st['processed']} web requests, but no website rules exist yet. Add one in Settings and import again."
        elif kind == "bundle":
            obs, flows, who = import_source.parse_bundle(text)
            for o in obs:
                o["source"] = "bundle" if o.get("source") not in ("nmap", "arp", "dhcp", "ap") else o["source"]
            ingest.ingest(obs, vantage=f"collector:{who}")
            if flows:
                ingest.ingest_flows(flows, "bundle")
            msg = f"Imported {len(obs)} observations from collector '{who}'."
        else:
            raise ValueError("Choose what kind of file this is.")
        db.audit(u, "import", f"{kind}: {up.filename}")
        flash(request, msg)
    except (ValueError, json.JSONDecodeError) as e:
        flash(request, f"Import failed: {e}", "err")
    return RedirectResponse("/sources", 303)


# ---------------------------------------------------------------- simulator
def _sim_ctx():
    return dict(scenarios=simulate.SCENARIOS, zones=policy.zone_names(), devices=db.q("SELECT id,label,zone FROM devices ORDER BY zone,label"),
                sensitive=config.cfg()["sensitive_ports"], recent=db.q("SELECT id,scenario,created_at FROM scenario_runs ORDER BY id DESC LIMIT 5"),
                vantage=policy.vantage_zone())


@app.get("/simulator", response_class=HTMLResponse)
async def simulator(request: Request):
    need(request)
    return render(request, "simulator.html", result=None, graph=None, form={}, **_sim_ctx())


@app.post("/simulator", response_class=HTMLResponse)
async def simulator_run(request: Request):
    u = need(request)
    f = dict(await request.form())
    result, err = None, None
    try:
        result = simulate.run(f.get("scenario", ""), f, u)
    except (ValueError, KeyError, StopIteration) as e:
        err = f"Could not run that scenario: {e or 'check the selected options'}"
    return render(request, "simulator.html", result=result, graph=twin.graph() if result else None, form=f, error=err, **_sim_ctx())


# ---------------------------------------------------------------- reports, settings
@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    need(request)
    return render(request, "reports.html", scans=db.q("SELECT * FROM scans WHERE status='complete' ORDER BY id DESC LIMIT 30"))


@app.get("/export/inventory.{fmt}")
async def inventory_export(request: Request, fmt: str):
    need(request)
    dl = {"Content-Disposition": f'attachment; filename="netrik_inventory.{fmt}"'}
    if fmt == "csv":
        return Response(reports.inventory_csv(), media_type="text/csv", headers=dl)
    if fmt == "json":
        return Response(reports.inventory_json(), media_type="application/json", headers=dl)
    if fmt == "html":
        return HTMLResponse(reports.inventory_html(), headers=dl)
    if fmt == "pdf":
        return Response(reports.inventory_pdf(), media_type="application/pdf", headers=dl)
    raise HTTPException(404)


@app.get("/settings", response_class=HTMLResponse)
async def settings(request: Request):
    need(request)
    c = config.cfg()
    return render(request, "settings.html", cfg=c, allowed=[str(n) for n in config.allowed_networks()], zones=policy.zone_names(), rules=policy.rules(),
                  vantage=policy.vantage_zone(), collector=config.collector_name(), audit=db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 80"),
                  devices=db.one("SELECT COUNT(*) n FROM devices")["n"], prules=db.q("SELECT * FROM policy_rules ORDER BY id DESC"), zone_list=policy.zone_names(),
                  dns=dnsmon.status(), dns_cfg=c["dns_monitor"], ports=c["sensitive_ports"], my_ips=sorted(config.local_ips() - {"127.0.0.1"}),
                  web_events=db.q("SELECT w.*, d.label FROM web_events w LEFT JOIN devices d ON d.id=w.device_id ORDER BY w.id DESC LIMIT 8"),
                  test_devices=db.q("SELECT d.id, d.label, (SELECT value FROM identifiers i WHERE i.device_id=d.id AND i.type='ip' ORDER BY last_seen DESC LIMIT 1) ip FROM devices d ORDER BY d.label"))


@app.post("/settings/baseline")
async def set_baseline(request: Request):
    u = need(request)
    db.run("UPDATE devices SET approved=1")
    db.set_setting("baseline_set", "1")
    db.audit(u, "baseline_set", "all current devices approved")
    flash(request, "Baseline set. New devices and services from now on will raise findings.")
    return RedirectResponse("/settings", 303)


@app.post("/settings/demo")
async def settings_demo(request: Request):
    u = need(request)
    f = await request.form()
    try:
        if f.get("action") == "load":
            demo.seed()
            flash(request, "Demo network loaded. Everything shown is synthetic and marked DEMO.")
        else:
            demo.clear()
            flash(request, "Demo data removed.")
        db.audit(u, "demo_" + f.get("action", ""), "")
    except ValueError as e:
        flash(request, str(e), "err")
    return RedirectResponse("/settings", 303)


# ---------------------------------------------------------------- policies
def _ports_text(text):
    ports = [p for p in re.split(r"[,\s]+", (text or "").strip()) if p]
    if any(not (p.isdigit() and 1 <= int(p) <= 65535) for p in ports):
        raise ValueError("Ports must be numbers between 1 and 65535, separated by commas.")
    return ",".join(ports)


@app.post("/settings/policy/add")
async def policy_add(request: Request):
    u = need(request)
    f = await request.form()
    try:
        kind = f.get("kind")
        name = (f.get("name") or "").strip()[:80]
        sev = f.get("severity") if f.get("severity") in ("high", "medium", "low") else "high"
        zone = (f.get("zone") or "All zones")[:60]
        if kind == "site":
            domains = ",".join(webpolicy.parse_domains(f.get("domains", "")))
            if not domains:
                raise ValueError("Enter at least one website, for example facebook.com.")
            db.run("INSERT INTO policy_rules(kind,name,domains,zone,severity,block,enabled,created_by,created_at) VALUES('site',?,?,?,?,?,1,?,?)",
                   (name or "Restricted websites", domains, zone, sev, 1 if f.get("block") else 0, u, util.now()))
        elif kind == "zone_deny":
            a, b = f.get("from_zone", ""), f.get("to_zone", "")
            if not a or not b or a == b:
                raise ValueError("Choose two different zones.")
            db.run("INSERT INTO policy_rules(kind,name,from_zone,to_zone,ports,severity,enabled,created_by,created_at) VALUES('zone_deny',?,?,?,?,?,1,?,?)",
                   (name or f"{a} must not reach {b}", a, b, _ports_text(f.get("ports")), sev, u, util.now()))
        elif kind == "port_forbid":
            ports = _ports_text(f.get("ports"))
            if not ports:
                raise ValueError("Enter at least one port, for example 23 for Telnet.")
            db.run("INSERT INTO policy_rules(kind,name,ports,zone,severity,enabled,created_by,created_at) VALUES('port_forbid',?,?,?,?,1,?,?)",
                   (name or f"Port {ports} must not be open", ports, zone, sev, u, util.now()))
        else:
            raise ValueError("Choose a rule type.")
        db.audit(u, "policy_added", f"{kind}: {name}")
        flash(request, "Rule added. It applies to new evidence from now on.")
    except ValueError as e:
        flash(request, str(e), "err")
    return RedirectResponse("/settings#policies", 303)


@app.post("/settings/policy/{rid}/toggle")
async def policy_toggle(request: Request, rid: int):
    u = need(request)
    db.run("UPDATE policy_rules SET enabled=1-enabled WHERE id=?", (rid,))
    db.audit(u, "policy_toggled", f"rule #{rid}")
    return RedirectResponse("/settings#policies", 303)


@app.post("/settings/policy/{rid}/delete")
async def policy_delete(request: Request, rid: int):
    u = need(request)
    db.run("DELETE FROM policy_rules WHERE id=?", (rid,))
    db.audit(u, "policy_deleted", f"rule #{rid}")
    flash(request, "Rule deleted. Findings already raised stay in the list.")
    return RedirectResponse("/settings#policies", 303)


@app.post("/settings/policy/test")
async def policy_test(request: Request):
    u = need(request)
    f = await request.form()
    try:
        scope = f.get("scope", "device")
        dom = webpolicy.parse_domains(f.get("domain", ""))
        if len(dom) != 1:
            raise ValueError("Enter one website, for example facebook.com.")
        rows = db.q("""SELECT d.id, d.label, d.zone, d.kind, (SELECT value FROM identifiers i WHERE i.device_id=d.id AND i.type='ip' ORDER BY last_seen DESC LIMIT 1) ip
                       FROM devices d""")
        chosen = (f.get("client") or "").strip()
        if scope == "device":
            ip = chosen
            if ip.isdigit():
                r = db.one("SELECT value FROM identifiers WHERE device_id=? AND type='ip' ORDER BY last_seen DESC LIMIT 1", (int(ip),))
                ip = r["value"] if r else ""
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                raise ValueError("Choose a device that has an IP address, or type one.")
            ips, where = [ip], "1 device"
        else:
            if scope == "segment_of":
                me = next((r for r in rows if str(r["id"]) == chosen), None)
                if not me:
                    raise ValueError("Choose the device whose segment should be used.")
                zone = me["zone"]
            elif scope == "segment":
                zone = f.get("zone") or ""
            elif scope == "all":
                zone = None
            else:
                raise ValueError("Unknown target.")
            skip = config.local_ips() if f.get("skip_infra") else set()
            ips = [r["ip"] for r in rows if r["ip"] and (zone is None or r["zone"] == zone) and not (f.get("skip_infra") and (r["kind"] == "Gateway / router" or r["ip"] in skip))][:500]
            where = f"every device on the network" if zone is None else f"every device in {zone}"
            if not ips:
                raise ValueError("No devices with an IP address in that scope.")
        st = webpolicy.record_many([(None, ip, dom[0]) for ip in ips], "test event")
        db.audit(u, "policy_test", f"{len(ips)} device(s) -> {dom[0]}: {st['matched']} matched")
        if st["matched"]:
            flash(request, f"Test visit to {dom[0]} sent from {len(ips)} device(s) ({where}): {st['matched']} matched a rule, {st['alerts_new']} new finding(s), {st['alerts_updated']} updated.")
            if len(ips) == 1:
                a = db.one("SELECT id FROM alerts WHERE type='policy_site' ORDER BY updated_at DESC, id DESC LIMIT 1")
                return RedirectResponse(f"/alerts/{a['id']}", 303)
            return RedirectResponse("/alerts?type=policy_site", 303)
        flash(request, f"No rule matched {dom[0]} for {where}, so nothing was raised. Check the website and the zone each rule applies to.")
    except ValueError as e:
        flash(request, str(e), "err")
    return RedirectResponse("/settings#policies", 303)


@app.post("/settings/dns")
async def dns_toggle(request: Request):
    u = need(request)
    f = await request.form()
    try:
        if f.get("action") == "start":
            dnsmon.start_from_config()
            db.set_setting("dns_monitor", "1")
            flash(request, f"DNS monitor listening on port {dnsmon.status()['port']}.")
        else:
            dnsmon.stop()
            db.set_setting("dns_monitor", "0")
            flash(request, "DNS monitor stopped.")
        db.audit(u, "dns_monitor", f.get("action", ""))
    except OSError as e:
        flash(request, f"Could not start the DNS monitor: {e}. Ports below 1024 need extra permission; see config.yaml.", "err")
    return RedirectResponse("/settings#policies", 303)


# ---------------------------------------------------------------- reset and cleanup
from . import reset as reset_mod  # noqa: E402


@app.post("/settings/reset")
async def settings_reset(request: Request):
    u = need(request)
    f = await request.form()
    what = f.get("what", "")
    try:
        if what not in ("scans", "findings", "devices", "rules", "everything"):
            raise ValueError("Unknown reset option.")
        if what == "everything" and (f.get("confirm") or "").strip().upper() != "RESET":
            raise ValueError("Type RESET in the box to confirm a full reset.")
        msg = reset_mod.wipe(what)
        db.audit(u, "reset", what)
        flash(request, msg)
    except ValueError as e:
        flash(request, str(e), "err")
    return RedirectResponse("/settings#reset", 303)


@app.post("/devices/{did}/delete")
async def device_delete(request: Request, did: int):
    u = need(request)
    reset_mod.delete_device(did)
    db.audit(u, "device_deleted", f"device #{did}")
    flash(request, "Device deleted, with its evidence and findings.")
    return RedirectResponse("/devices", 303)


@app.post("/scans/{sid}/delete")
async def scan_delete(request: Request, sid: int):
    u = need(request)
    try:
        reset_mod.delete_scan(sid)
        db.audit(u, "scan_deleted", f"scan #{sid}")
        flash(request, "Scan deleted.")
    except ValueError as e:
        flash(request, str(e), "err")
        return RedirectResponse(f"/scans/{sid}", 303)
    return RedirectResponse("/scans", 303)
