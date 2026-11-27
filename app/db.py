"""SQLite access. Evidence (observations) is append-only; devices and alerts are derived views."""

from __future__ import annotations

import contextlib
import sqlite3

from . import config, util

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, label TEXT, kind TEXT DEFAULT 'Unknown', vendor TEXT, os TEXT,
  zone TEXT, first_seen TEXT, last_seen TEXT, approved INTEGER DEFAULT 0, randomized INTEGER DEFAULT 0,
  confidence TEXT DEFAULT 'low', note TEXT DEFAULT '', demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS identifiers(id INTEGER PRIMARY KEY, device_id INTEGER, type TEXT, value TEXT,
  first_seen TEXT, last_seen TEXT, UNIQUE(device_id, type, value));
CREATE INDEX IF NOT EXISTS ix_ident ON identifiers(type, value);
CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY, device_id INTEGER, source TEXT, observed_at TEXT,
  scan_id INTEGER, ip TEXT, mac TEXT, hostname TEXT, vantage TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_obs_dev ON observations(device_id, observed_at);
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY, device_id INTEGER, port INTEGER, proto TEXT, name TEXT,
  product TEXT, version TEXT, open_now INTEGER DEFAULT 1, first_seen TEXT, last_seen TEXT, last_scan_id INTEGER,
  last_profile TEXT, UNIQUE(device_id, port, proto));
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, kind TEXT, target TEXT, profile TEXT, ports TEXT, status TEXT,
  progress REAL DEFAULT 0, message TEXT, created_at TEXT, started_at TEXT, finished_at TEXT, requested_by TEXT,
  xml_path TEXT, txt_path TEXT, command TEXT, summary TEXT, error TEXT, verify_alert INTEGER, cancel INTEGER DEFAULT 0,
  demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS scan_hosts(id INTEGER PRIMARY KEY, scan_id INTEGER, device_id INTEGER, ip TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS flows(id INTEGER PRIMARY KEY, src_ip TEXT, dst_ip TEXT, port INTEGER, proto TEXT,
  count INTEGER, last_seen TEXT, source TEXT, UNIQUE(src_ip, dst_ip, port, proto));
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, type TEXT, device_id INTEGER, dedupe TEXT, severity TEXT,
  confidence TEXT, title TEXT, detail TEXT, rec_key TEXT, status TEXT DEFAULT 'open', note TEXT DEFAULT '',
  created_at TEXT, updated_at TEXT, scan_id INTEGER);
CREATE TABLE IF NOT EXISTS verifications(id INTEGER PRIMARY KEY, alert_id INTEGER, scan_id INTEGER, result TEXT,
  explanation TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, user TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS device_merges(id INTEGER PRIMARY KEY, kept INTEGER, dropped INTEGER, reason TEXT, ts TEXT, user TEXT, dropped_json TEXT);
CREATE TABLE IF NOT EXISTS policy_rules(id INTEGER PRIMARY KEY, kind TEXT, name TEXT, domains TEXT, zone TEXT, from_zone TEXT, to_zone TEXT,
  ports TEXT, severity TEXT DEFAULT 'high', block INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS web_events(id INTEGER PRIMARY KEY, ts TEXT, client_ip TEXT, device_id INTEGER, domain TEXT, source TEXT, matched_rule INTEGER, blocked INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_web ON web_events(ts);
CREATE TABLE IF NOT EXISTS scenario_runs(id INTEGER PRIMARY KEY, scenario TEXT, params TEXT, result TEXT,
  created_at TEXT, user TEXT);
"""


def connect() -> sqlite3.Connection:
    config.ensure_dirs()
    c = sqlite3.connect(config.DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


@contextlib.contextmanager
def tx():
    c = connect()
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def q(sql, args=()):
    with tx() as c:
        return c.execute(sql, args).fetchall()


def one(sql, args=()):
    rows = q(sql, args)
    return rows[0] if rows else None


def run(sql, args=()):
    with tx() as c:
        return c.execute(sql, args).lastrowid


MIGRATIONS = [("devices", "label_auto", "INTEGER DEFAULT 1"), ("devices", "name_source", "TEXT"),
              ("scans", "live_only", "INTEGER DEFAULT 0"), ("scans", "notes", "TEXT"), ("scans", "live", "TEXT")]


def init():
    with tx() as c:
        c.executescript(SCHEMA)
        for table, col, ddl in MIGRATIONS:  # keeps databases created by earlier versions working
            if col not in {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")


def setting(key, default=None):
    row = one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


def setting_c(c, key, default=None):
    row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    run("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def audit(user, action, detail=""):
    run("INSERT INTO audit(ts,user,action,detail) VALUES(?,?,?,?)", (util.now(), user or "system", action, detail))
