"""Remediation verification: repeat the same test from the same place and compare with earlier evidence."""

from __future__ import annotations

import json

from . import config, db, util


def start(alert_id: int, user: str) -> int:
    a = db.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
    t = util.jl(a["detail"]).get("test") if a else None
    if not t:
        raise ValueError("This finding has no automatic verification test. Resolve it manually.")
    return db.run("""INSERT INTO scans(kind,target,profile,ports,status,created_at,requested_by,verify_alert)
                     VALUES('verify',?,?,?,'queued',?,?,?)""", (t["target"], t.get("profile", "quick"), t["ports"], util.now(), user, alert_id))


def evaluate(alert_id: int, scan_id: int):
    a = db.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
    t = util.jl(a["detail"])["test"]
    port = int(t["ports"])
    here = config.collector_name()
    host = db.one("SELECT data FROM scan_hosts WHERE scan_id=? AND ip=?", (scan_id, t["target"]))
    if t.get("vantage") and t["vantage"] != here:
        result, why = "inconclusive", f"The original test ran from {t['vantage']} but this one ran from {here}. Different locations cannot be compared."
    elif host is None:
        result, why = "inconclusive", f"{t['target']} did not respond to the verification scan. It may be off, or blocking all probes; this does not prove the exposure is gone."
    else:
        ports = util.jl(host["data"]).get("ports") or []
        is_open = any(p["port"] == port and p["state"] == "open" for p in ports)
        if is_open:
            result, why = "still_present", f"Port {port} is still open on {t['target']} from {here}."
        else:
            result, why = "resolved", (f"Port {port} was not open on {t['target']} when tested from {here}. This confirms the exposure is gone from this location only; "
                                       "other network zones were not tested.")
    db.run("INSERT INTO verifications(alert_id,scan_id,result,explanation,created_at) VALUES(?,?,?,?,?)", (alert_id, scan_id, result, why, util.now()))
    if result == "resolved":
        db.run("UPDATE alerts SET status='verified', updated_at=? WHERE id=?", (util.now(), alert_id))
    db.audit("system", "verification", f"alert #{alert_id}: {result}")
