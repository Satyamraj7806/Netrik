"""Hostname discovery, the way a good network scanner does it.

Per address, in order (stopping at the first answer):
  dns      PTR lookup asked of your router, then your configured DNS servers, then the OS resolver. Home and campus routers
           register DHCP clients here, which is where names like "LGwebOSTV" usually come from.
  mdns     the device's own announced name (.local): Apple devices, Linux, many TVs and printers
  netbios  Windows computer name (UDP 137)
  llmnr    Windows / Linux name via LLMNR (UDP 5355), works when NetBIOS is off
For the whole network at once:
  mDNS browse and SSDP/UPnP discovery. TVs, speakers, printers, routers and media boxes announce a friendly name
  and model there even when they have no DNS record.

A name is a label that helps people recognise a device. It is not an identity, and a DNS record is not proof the device
is online, so names are applied without creating presence evidence.
"""

from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import re
import socket
import struct
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from xml.etree import ElementTree as ET

from .. import config

MDNS_PORT, NETBIOS_PORT, LLMNR_PORT, SSDP_PORT = 5353, 137, 5355, 1900
MDNS_GROUP, SSDP_GROUP = "224.0.0.251", "239.255.255.250"
ORDER = ["dns", "mdns", "netbios", "llmnr"]
LABEL = {"dns": "DNS reverse record", "mdns": "mDNS (the device announced it)", "netbios": "NetBIOS (Windows computer name)",
         "llmnr": "LLMNR (Windows/Linux name)", "upnp": "UPnP (friendly name)", "dhcp": "DHCP lease", "ap": "Wi-Fi client list"}
RANK = {"dhcp": 6, "ap": 6, "dns": 5, "mdns": 4, "netbios": 3, "llmnr": 3, "upnp": 2}  # which source's name wins when they differ
SERVICES = ["_services._dns-sd._udp", "_airplay._tcp", "_googlecast._tcp", "_raop._tcp", "_hap._tcp", "_workstation._tcp", "_smb._tcp", "_ipp._tcp", "_printer._tcp",
            "_http._tcp", "_companion-link._tcp", "_device-info._tcp", "_spotify-connect._tcp", "_sleep-proxy._udp", "_lg-smart-tv._tcp", "_androidtvremote2._tcp"]


def _clean(name):
    if not name:
        return None
    name = re.sub(r"[^\w .'\-\[\]()+]", "", name.strip().rstrip("."))[:63].strip()
    return name or None


def _short(name: str) -> str:
    return re.sub(r"\.(local|lan|home|localdomain|internal)$", "", (name or "").rstrip("."), flags=re.I)


# ---------------------------------------------------------------- DNS wire format
def _read_name(data: bytes, off: int):
    labels, jumped, end = [], False, off
    for _ in range(64):
        if off >= len(data):
            return None, end
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                return None, end
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            continue
        labels.append(data[off + 1: off + 1 + n].decode("utf-8", "ignore"))
        off += 1 + n
    if not jumped:
        end = off
    return ".".join(labels), end


def _question(name: str, qtype: int, qclass: int = 1) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", qtype, qclass)


def _ptr_packet(ip: str, flags: int) -> bytes:
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    return struct.pack(">HHHHHH", 0x1234, flags, 1, 0, 0, 0) + _question(rev, 12)


def _records(data: bytes):
    """Yield (owner, type, rdata_offset, rdlen) for every record in a DNS packet, additional section included."""
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
        off = 12
        for _ in range(qd):
            _, off = _read_name(data, off)
            off += 4
        for _ in range(an + ns + ar):
            owner, off = _read_name(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off: off + 10])
            off += 10
            yield owner, rtype, off, rdlen
            off += rdlen
    except (struct.error, IndexError, TypeError):
        return


def _first_ptr(data: bytes):
    for _, rtype, off, _ in _records(data):
        if rtype == 12:
            name, _ = _read_name(data, off)
            return _clean(name)
    return None


def _udp_ptr(server: str, port: int, ip: str, timeout: float, flags: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(_ptr_packet(ip, flags), (server, port))
        data, _ = s.recvfrom(1500)
    except OSError:
        return None
    finally:
        s.close()
    return _first_ptr(data)


# ---------------------------------------------------------------- per-address methods
def dns_servers() -> list:
    out = []
    gw = config.default_gateway()
    if gw:
        out.append(gw)  # the router knows the names its DHCP clients announced
    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            for line in Path(path).read_text().splitlines():
                m = re.match(r"\s*nameserver\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m and not m.group(1).startswith("127.") and m.group(1) not in out:
                    out.append(m.group(1))
        except OSError:
            pass
    return out


def dns_ptr(ip: str, servers=None):
    for srv in (servers if servers is not None else dns_servers()):
        n = _udp_ptr(srv, 53, ip, 1.2, 0x0100)
        if n and n != ip and not n.replace("-", ".").startswith(ip):
            return n
    try:
        n = socket.gethostbyaddr(ip)[0]
        return None if n == ip else _clean(n)
    except OSError:
        return None


def mdns(ip: str, timeout: float = 1.0):
    """Ask the host directly (unicast) for the mDNS name it announces for its own address."""
    return _udp_ptr(ip, MDNS_PORT, ip, timeout, 0x0000)


def llmnr(ip: str, timeout: float = 1.0):
    return _udp_ptr(ip, LLMNR_PORT, ip, timeout, 0x0000)


def netbios(ip: str, timeout: float = 1.0):
    """NetBIOS node status (UDP 137): Windows machines report their computer name."""
    pkt = struct.pack(">HHHHHH", 0x4242, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\x00" + struct.pack(">HH", 0x21, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, NETBIOS_PORT))
        data, _ = s.recvfrom(1500)
    except OSError:
        return None
    finally:
        s.close()
    try:
        count, off = data[56], 57
        for _ in range(count):
            entry = data[off: off + 18]
            flags = struct.unpack(">H", entry[16:18])[0]
            if entry[15] == 0x00 and not flags & 0x8000:
                return _clean(entry[:15].decode("ascii", "ignore"))
            off += 18
    except (IndexError, struct.error):
        return None
    return None


# ---------------------------------------------------------------- network-wide discovery
def mdns_records(data: bytes, src_ip: str) -> dict:
    """What a device announced about itself in one mDNS packet: host name, friendly name, services."""
    host = friendly = None
    services, srv_targets = [], []
    for owner, rtype, off, rdlen in _records(data):
        if rtype == 1 and rdlen == 4 and socket.inet_ntoa(data[off: off + 4]) == src_ip and owner and not host:
            host = _short(owner)
        elif rtype == 33 and rdlen > 6:
            t, _ = _read_name(data, off + 6)
            if t:
                srv_targets.append(_short(t))
        elif rtype == 12:
            inst, _ = _read_name(data, off)
            if inst and "._" in inst:
                services.append(inst.split("._", 1)[1].split(".local")[0])
                friendly = friendly or inst.split("._", 1)[0]
        elif rtype == 16:
            blob, i = data[off: off + rdlen], 0
            while i < len(blob):
                ln = blob[i]
                kv = blob[i + 1: i + 1 + ln].decode("utf-8", "ignore")
                if kv.lower().startswith(("fn=", "name=")) and not friendly:
                    friendly = kv.split("=", 1)[1]
                i += 1 + ln
    return {"host": _clean(host or (srv_targets[0] if srv_targets else None)), "friendly": _clean(friendly), "services": sorted(set(services))}


def mdns_browse(local_ips: list, seconds: float = 3.0) -> dict:
    """Multicast a query for common services; devices answer us directly (unicast reply requested)."""
    found = {}
    end = time.time() + seconds
    socks = []
    for lip in local_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lip))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            s.bind((lip, 0))
            s.settimeout(0.25)
            for svc in SERVICES:
                s.sendto(struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + _question(svc + ".local", 12, 0x8001), (MDNS_GROUP, MDNS_PORT))
            socks.append(s)
        except OSError:
            continue
    while socks and time.time() < end:
        for s in socks:
            try:
                data, addr = s.recvfrom(4096)
            except OSError:
                continue
            rec = mdns_records(data, addr[0])
            if rec["host"] or rec["friendly"]:
                cur = found.setdefault(addr[0], {"host": None, "friendly": None, "services": []})
                cur["host"] = cur["host"] or rec["host"]
                cur["friendly"] = cur["friendly"] or rec["friendly"]
                cur["services"] = sorted(set(cur["services"]) | set(rec["services"]))
    for s in socks:
        s.close()
    return found


def _parse_ssdp(data: bytes):
    head = data.decode("utf-8", "ignore")
    m = re.search(r"^location:\s*(\S+)", head, re.I | re.M)
    return m.group(1) if m else None


def ssdp_discover(local_ips: list, seconds: float = 3.0) -> dict:
    """{ip: description URL} for devices that answer UPnP discovery."""
    found, socks = {}, []
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    for lip in local_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lip))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
            s.bind((lip, 0))
            s.settimeout(0.25)
            for _ in range(2):
                s.sendto(msg, (SSDP_GROUP, SSDP_PORT))
            socks.append(s)
        except OSError:
            continue
    end = time.time() + seconds
    while socks and time.time() < end:
        for s in socks:
            try:
                data, addr = s.recvfrom(4096)
            except OSError:
                continue
            loc = _parse_ssdp(data)
            if loc and addr[0] not in found:
                found[addr[0]] = loc
    for s in socks:
        s.close()
    return found


def upnp_describe(location: str, ip: str):
    """Fetch a device description and read its friendly name. Only the responding device itself is contacted."""
    try:
        u = urllib.parse.urlparse(location)
        if u.scheme != "http" or u.hostname != ip or not ipaddress.ip_address(ip).is_private:
            return None
        with urllib.request.urlopen(location, timeout=2.0) as r:
            data = r.read(65536)
        out = {}
        for el in ET.fromstring(data).iter():
            tag = el.tag.split("}")[-1]
            if tag in ("friendlyName", "manufacturer", "modelName", "deviceType") and el.text and tag not in out:
                out[tag] = el.text.strip()
        return out or None
    except Exception:
        return None


def kind_hint(desc: dict) -> str | None:
    t = " ".join((desc.get("deviceType", ""), desc.get("friendlyName", ""), desc.get("modelName", ""))).lower()
    if "internetgatewaydevice" in t or "wanconnectiondevice" in t:
        return "Gateway / router"
    if "printer" in t:
        return "Printer"
    if "wlanaccesspoint" in t:
        return "Network appliance"
    if re.search(r"mediarenderer|dial-multiscreen|\btv\b|webos|bravia|roku|chromecast|firetv|fire tv|shield|smarttv", t):
        return "TV / media device"
    return None


# ---------------------------------------------------------------- orchestration
def resolve_report(ips, total_timeout: float = 40.0, nets=None) -> dict:
    """{ip: {name, method, tried:{method: name|None}, extras:{vendor, kind}}} plus a "_meta" entry with what was asked."""
    ips = list(ips)
    servers = dns_servers()
    local = [i for i in config.local_ips() if not nets or any(ipaddress.ip_address(i) in n for n in nets)]
    bulk = {"mdns": {}, "ssdp": {}, "desc": {}}

    def run_bulk():
        try:
            bulk["mdns"] = mdns_browse(local)
            bulk["ssdp"] = ssdp_discover(local)
            for ip, loc in list(bulk["ssdp"].items())[:150]:
                d = upnp_describe(loc, ip)
                if d:
                    bulk["desc"][ip] = d
        except Exception:
            pass
    t = threading.Thread(target=run_bulk, daemon=True)
    t.start()

    fns = {"dns": lambda ip: dns_ptr(ip, servers), "mdns": mdns, "netbios": netbios, "llmnr": llmnr}

    def one(ip):
        tried = {}
        for m in ORDER:
            try:
                n = fns[m](ip)
            except Exception:
                n = None
            tried[m] = n
            if n:
                break
        return ip, tried

    ex = cf.ThreadPoolExecutor(max_workers=48)
    futs = [ex.submit(one, ip) for ip in ips]
    done, _ = cf.wait(futs, timeout=total_timeout)
    ex.shutdown(wait=False, cancel_futures=True)
    per = {}
    for f in done:
        ip, tried = f.result()
        per[ip] = tried
    t.join(timeout=max(0.5, 10))
    out = {}
    for ip in ips:
        tried = dict(per.get(ip, {m: None for m in ORDER}))
        b_m, desc = bulk["mdns"].get(ip), bulk["desc"].get(ip)
        if b_m and not tried.get("mdns"):
            tried["mdns"] = b_m["host"] or b_m["friendly"]
        if desc:
            tried["upnp"] = _clean(desc.get("friendlyName"))
        name, method = None, None
        for m in ("dns", "mdns", "netbios", "llmnr", "upnp"):
            if tried.get(m):
                name, method = tried[m], m
                break
        extras = {}
        if desc:
            if desc.get("manufacturer"):
                extras["vendor"] = _clean(desc["manufacturer"])
            k = kind_hint(desc)
            if k:
                extras["kind"] = k
        out[ip] = {"name": name, "method": method, "tried": tried, "extras": extras}
    out["_meta"] = {"dns_servers": servers, "interfaces": local, "mdns_devices": len(bulk["mdns"]), "upnp_devices": len(bulk["ssdp"])}
    return out


def resolve_many(ips, total_timeout: float = 25.0, nets=None) -> dict:
    """Compatibility wrapper: {ip: (name, method)} for the addresses that produced a name."""
    rep = resolve_report(ips, total_timeout, nets)
    return {ip: (r["name"], r["method"]) for ip, r in rep.items() if ip != "_meta" and r["name"]}
