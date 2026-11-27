"""Reset and cleanup: delete a device, a scan, or wipe parts of the data for a fresh start."""

from . import config, db, util

DEVICE_TABLES = ("observations", "services", "identifiers", "scan_hosts", "web_events")


def _busy(c) -> bool:
    return c.execute("SELECT 1 FROM scans WHERE status IN ('queued','running') LIMIT 1").fetchone() is not None


def _remove_raw(ids=None) -> None:
    for p in config.RAW.glob("scan_*"):
        if ids is None or any(p.name.startswith(f"scan_{i}.") for i in ids):
            p.unlink(missing_ok=True)


def delete_device(did: int) -> None:
    with db.tx() as c:
        for t in DEVICE_TABLES:
            c.execute(f"DELETE FROM {t} WHERE device_id=?", (did,))
        c.execute("DELETE FROM verifications WHERE alert_id IN (SELECT id FROM alerts WHERE device_id=?)", (did,))
        c.execute("DELETE FROM alerts WHERE device_id=?", (did,))
        c.execute("DELETE FROM devices WHERE id=?", (did,))


def delete_scan(sid: int) -> None:
    with db.tx() as c:
        row = c.execute("SELECT status FROM scans WHERE id=?", (sid,)).fetchone()
        if row and row["status"] in ("queued", "running"):
            raise ValueError("Cancel the scan first, then delete it.")
        c.execute("DELETE FROM scan_hosts WHERE scan_id=?", (sid,))
        c.execute("UPDATE alerts SET scan_id=NULL WHERE scan_id=?", (sid,))
        c.execute("DELETE FROM scans WHERE id=?", (sid,))
    _remove_raw([sid])


def wipe(what: str) -> str:
    """what: scans | findings | devices | rules | everything. Users and the audit log are always kept."""
    with db.tx() as c:
        if what in ("scans", "everything") and _busy(c):
            raise ValueError("A scan is queued or running. Cancel it or wait, then try again.")
        if what in ("scans", "everything"):
            for t in ("scan_hosts", "scans"):
                c.execute(f"DELETE FROM {t}")
        if what in ("findings", "devices", "everything"):
            for t in ("verifications", "alerts", "web_events"):
                c.execute(f"DELETE FROM {t}")
        if what in ("devices", "everything"):
            for t in ("scan_hosts", "observations", "services", "identifiers", "flows", "device_merges", "scenario_runs", "devices"):
                c.execute(f"DELETE FROM {t}")
            c.execute("DELETE FROM settings WHERE key IN ('baseline_set','demo','demo_policy','demo_vantage')")
        if what in ("rules", "everything"):
            c.execute("DELETE FROM policy_rules")
    if what in ("scans", "everything"):
        _remove_raw()
    return {"scans": "All scans and their saved output deleted.", "findings": "All findings deleted.", "devices": "All devices, evidence and findings deleted. Next scan starts fresh.",
            "rules": "All policy rules deleted.", "everything": "Everything was reset: devices, scans, findings, evidence and rules. Your login and the audit log were kept."}[what]
