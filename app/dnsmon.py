"""Optional DNS monitor: a tiny forwarding resolver that checks every lookup against your site rules.

Point a device's DNS server at this machine and a request for a restricted site raises a finding immediately.
Rules marked "block" are answered with NXDOMAIN. Everything else is forwarded unchanged to the upstream resolver.
Only private-network clients are served, and nothing is stored except requests that match a rule.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading

from . import config, webpolicy

_state = {"sock": None, "thread": None, "port": None, "bind": None, "queries": 0, "matched": 0}


def _qname(data: bytes):
    labels, off = [], 12
    while off < len(data) and data[off]:
        n = data[off]
        labels.append(data[off + 1: off + 1 + n].decode("ascii", "ignore"))
        off += 1 + n
        if n > 63:
            return None, 0
    return ".".join(labels).lower(), off + 5  # end of the question section (name + type + class)


def _nxdomain(req: bytes, qend: int) -> bytes:
    return req[:2] + struct.pack(">HHHHH", 0x8183, 1, 0, 0, 0) + req[12:qend]


def _handle(sock, data, addr, upstream, up_port):
    try:
        if not ipaddress.ip_address(addr[0]).is_private and not ipaddress.ip_address(addr[0]).is_loopback:
            return
        name, qend = _qname(data)
        if not name or len(data) < 17:
            return
        _state["queries"] += 1
        rule = webpolicy.blocked_domain(name)
        stats = webpolicy.record_many([(None, addr[0], name)], "DNS monitor", blocked=bool(rule))
        _state["matched"] += stats["matched"]
        if rule:
            sock.sendto(_nxdomain(data, qend), addr)
            return
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.settimeout(3)
        try:
            up.sendto(data, (upstream, up_port))
            sock.sendto(up.recv(4096), addr)
        finally:
            up.close()
    except Exception:
        pass


def start(bind: str, port: int, upstream: str, upstream_port: int = 53) -> None:
    stop()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.settimeout(1.0)
    _state.update(sock=s, port=s.getsockname()[1], bind=bind, queries=0, matched=0)

    def loop():
        while _state["sock"] is s:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_handle, args=(s, data, addr, upstream, upstream_port), daemon=True).start()
    t = threading.Thread(target=loop, name="netrik-dns", daemon=True)
    _state["thread"] = t
    t.start()


def stop() -> None:
    s = _state.get("sock")
    _state["sock"] = None
    if s:
        try:
            s.close()
        except OSError:
            pass


def status() -> dict:
    return {"running": _state["sock"] is not None, "port": _state["port"], "bind": _state["bind"], "queries": _state["queries"], "matched": _state["matched"]}


def start_from_config() -> None:
    c = config.cfg()["dns_monitor"]
    start(c["bind"], int(c["port"]), c["upstream"], int(c.get("upstream_port", 53)))
