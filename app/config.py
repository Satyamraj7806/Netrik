"""Configuration, local-network detection and zone helpers."""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import socket
import subprocess
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("NETRIK_DATA", ROOT / "data"))
RAW = DATA / "raw"
DB_PATH = DATA / "netrik.db"
CONFIG_PATH = Path(os.environ.get("NETRIK_CONFIG", ROOT / "config.yaml"))

DEFAULTS = {
    "host": "127.0.0.1", "port": 8000, "collector_name": "",
    "allowed_ranges": [], "zones": [], "policy": {"deny": []},
    "stale_hours": 24, "max_rate": 1000, "max_targets": 1024,
    "scan_timeout_minutes": 120, "host_timeout_minutes": 15, "name_lookup": True, "nmap_privileged": False,
    "dhcp_lease_files": [], "ip_match_hours": 24,
    "dns_monitor": {"bind": "0.0.0.0", "port": 5353, "upstream": "1.1.1.1", "upstream_port": 53},
    "sensitive_ports": {21: "FTP", 23: "Telnet", 135: "Windows RPC", 139: "NetBIOS", 445: "SMB file sharing",
                        1433: "SQL Server", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL",
                        5900: "VNC remote screen", 9100: "Printer raw port"},
}


def ensure_dirs():
    DATA.mkdir(exist_ok=True)
    RAW.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def cfg() -> dict:
    ensure_dirs()
    data = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        data.update(yaml.safe_load(CONFIG_PATH.read_text()) or {})
    data["sensitive_ports"] = {int(k): v for k, v in data["sensitive_ports"].items()}
    data["policy"] = data.get("policy") or {"deny": []}
    return data


def secret_key() -> str:
    ensure_dirs()
    p = DATA / "secret.key"
    if not p.exists():
        p.write_text(secrets.token_hex(32))
        p.chmod(0o600)
    return p.read_text().strip()


def collector_name() -> str:
    return cfg()["collector_name"] or socket.gethostname()


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""


def local_networks() -> list:
    nets = []
    for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", _run(["ip", "-4", "-o", "addr", "show", "scope", "global"])):
        iface = ipaddress.ip_interface(m.group(1))
        net = iface.network if iface.network.prefixlen >= 20 else ipaddress.ip_network((iface.ip, 24), strict=False)
        if net not in nets:
            nets.append(net)
    if not nets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            nets.append(ipaddress.ip_network((s.getsockname()[0], 24), strict=False))
            s.close()
        except Exception:
            pass
    return nets


def local_ips() -> set:
    return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", _run(["ip", "-4", "-o", "addr", "show"])))


def allowed_networks() -> list:
    ranges = cfg()["allowed_ranges"]
    if ranges:
        return [ipaddress.ip_network(r, strict=False) for r in ranges]
    return local_networks()


def default_gateway() -> str | None:
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", _run(["ip", "route", "show", "default"]))
    return m.group(1) if m else None


def configured_zones() -> list:
    zones = [{"name": z["name"], "net": ipaddress.ip_network(z["cidr"], strict=False)} for z in cfg()["zones"]]
    if not zones:
        zones = [{"name": f"Local network {n}", "net": n} for n in local_networks()]
    return zones


def zone_for_ip(ip: str | None) -> str:
    if not ip:
        return "Unassigned"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "Unassigned"
    for z in configured_zones():
        if addr in z["net"]:
            return z["name"]
    return "Unassigned"
