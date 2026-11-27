"""Active discovery and port scanning through the existing Netrik profiles."""

from __future__ import annotations

import os
import pty
import re
import select
import shutil
import signal
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from netrik.core.profiles import scan_profiles

DISCOVERY = {
    "name": "Host discovery (ping sweep)",
    "nmap_args": ["-sn"],
    "description": "Finds hosts that answer probes. Silent hosts are not proof of absence.",
}


def profiles() -> dict:
    return {"discovery": DISCOVERY, **scan_profiles}


def build_args(profile: str, targets: list, ports: str | None, privileged: bool, max_rate: int, xml_path: str, txt_path: str, host_timeout_min: int = 15) -> list:
    args = list(profiles()[profile]["nmap_args"])
    if not privileged:  # raw sockets unavailable: fall back to connect scans, skip OS detection
        args = ["-sT" if a == "-sS" else a for a in args if a != "-O"]
    if ports:
        cleaned, skip = [], False
        for a in args:
            if skip:
                skip = False
            elif a == "--top-ports":
                skip = True
            elif a != "-p-":
                cleaned.append(a)
        args = cleaned + ["-p", ports]
    if profile != "discovery":
        if "-O" in args and "--osscan-limit" not in args:
            args.append("--osscan-limit")  # OS guesses need one open and one closed port; skip hosts that cannot give one
        args += ["--host-timeout", f"{host_timeout_min}m"]  # one stubborn host must not stall the whole scan
        if len(targets) > 1 or "/" in targets[0]:
            args += ["--min-hostgroup", "32"]  # scan hosts in bigger parallel groups
    args += ["-v", "--stats-every", "2s", "--max-rate", str(max_rate), "-oX", xml_path, "-oN", txt_path]
    if privileged:
        args.append("--privileged")
    return args + list(targets)


def run(args: list, on_line, cancelled, timeout_s: int, on_tick=None):
    """Run Nmap, streaming lines to on_line. Returns (text, returncode or 'cancelled'/'timeout').

    Nmap runs on a pseudo-terminal so it prints line by line (through a pipe it buffers for minutes, which would
    freeze progress and make cancel and the time limit react late). On cancel or timeout it gets SIGINT, which
    makes it save the hosts it has already finished.
    """
    master, slave = pty.openpty()
    # `setsid --ctty` makes the terminal Nmap's controlling terminal; only then does Nmap print its periodic progress lines.
    launcher = ["setsid", "--ctty"] if shutil.which("setsid") else []
    proc = subprocess.Popen([*launcher, "nmap", *args], stdin=slave if launcher else subprocess.DEVNULL, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    t0, out, buf, stop, deadline = time.time(), [], "", None, 0.0
    try:
        while True:
            ready, _, _ = select.select([master], [], [], 1.0)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError:  # EIO: Nmap closed the terminal
                    chunk = b""
                if not chunk:
                    break
                buf += chunk.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
                *lines, buf = buf.split("\n")
                for line in lines:
                    out.append(line + "\n")
                    on_line(line)
            elif proc.poll() is not None:
                break
            if on_tick:
                on_tick()
            if stop is None and (cancelled() or time.time() - t0 > timeout_s):
                stop = "cancelled" if cancelled() else "timeout"
                proc.send_signal(signal.SIGINT)
                deadline = time.time() + 20
            if stop and time.time() > deadline:
                proc.kill()
                break
    finally:
        os.close(master)
        proc.wait()
    if buf:
        out.append(buf)
        on_line(buf)
    return "".join(out), stop or proc.returncode


def notes_for(profile: str, privileged: bool) -> list:
    args, notes = profiles()[profile]["nmap_args"], []
    if not privileged:
        if "-O" in args:
            notes.append("OS detection was skipped: it needs raw-socket access. Run scripts/setup_nmap_caps.sh, then set nmap_privileged: true in config.yaml.")
        if "-sS" in args:
            notes.append("Raw sockets are not enabled, so a slower TCP connect scan was used instead of a SYN scan.")
    return notes


def port_count(profile: str, ports: str | None) -> int:
    if ports:
        total = 0
        for part in ports.split(","):
            a, _, b = part.partition("-")
            total += (int(b) - int(a) + 1) if b else 1
        return total
    args = profiles()[profile]["nmap_args"]
    if "-p-" in args:
        return 65535
    if "--top-ports" in args:
        return int(args[args.index("--top-ports") + 1])
    return 100 if "-F" in args else 1000


def estimate_seconds(profile: str, hosts: int, ports: str | None, rate: int) -> int:
    """Lower bound from probe volume alone. Version and OS detection add more."""
    if profile == "discovery":
        return max(5, hosts // 20)
    return int(hosts * port_count(profile, ports) / max(rate, 1) + hosts * 2)


def fmt_duration(sec: int) -> str:
    return f"{sec} s" if sec < 90 else (f"{sec // 60} min" if sec < 5400 else f"{sec / 3600:.1f} h")


_NOISE = re.compile(r"^(Stats:|[\w ]+ Timing:)")


def clean_text(text: str) -> str:
    return "".join(l for l in text.splitlines(True) if not _NOISE.match(l))


def progress_of(line: str):
    m = re.search(r"About\s+(\d+(?:\.\d+)?)%\s+done", line)
    if not m:
        return None
    left = re.search(r"\(([\d:]+) remaining\)", line)
    return float(m.group(1)), (left.group(1) if left else None)


def timeline(path: str) -> dict:
    """Per-phase durations and total time from the XML's own timestamps."""
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return {}
    begins = [(m.group(1), int(m.group(2))) for m in re.finditer(r'<taskbegin task="([^"]+)" time="(\d+)"', text)]
    ends = [(m.group(1), int(m.group(2)), m.group(3) or "") for m in re.finditer(r'<taskend task="([^"]+)" time="(\d+)"(?: extrainfo="([^"]*)")?', text)]
    phases = []
    for task, t0 in begins:
        end = next(((e, t, info) for e, t, info in ends if e == task and t >= t0), None)
        if end:
            phases.append({"task": task, "seconds": end[1] - t0, "info": end[2]})
    fin = re.search(r'<finished time="\d+"[^>]*elapsed="([\d.]+)"', text)
    return {"phases": phases, "elapsed": float(fin.group(1)) if fin else None}


def parse_xml(path: str) -> list:
    text = Path(path).read_text(errors="replace")
    if "</nmaprun>" not in text:  # interrupted scan: keep only hosts that were fully written
        cut = text.rfind("</host>")
        if cut < 0:
            return []
        text = text[: cut + 7] + "</nmaprun>"
    hosts = []
    for h in ET.fromstring(text).findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip = mac = vendor = None
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t == "ipv4":
                ip = a.get("addr")
            elif t == "mac":
                mac, vendor = a.get("addr"), a.get("vendor")
        names = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        pe = h.find("ports")
        ports = None
        if pe is not None:
            ports = []
            for p in pe.findall("port"):
                s, sv = p.find("state"), p.find("service")
                ports.append({
                    "port": int(p.get("portid")), "protocol": p.get("protocol", "tcp"),
                    "state": s.get("state") if s is not None else "unknown",
                    "reason": s.get("reason", "") if s is not None else "",
                    "service": (sv.get("name") if sv is not None else None) or "unknown",
                    "product": (sv.get("product") if sv is not None else "") or "",
                    "version": (sv.get("version") if sv is not None else "") or "",
                })
        osm = [{"name": m.get("name"), "accuracy": m.get("accuracy")} for m in h.findall("os/osmatch")]
        if ip:
            hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": names[0] if names else None,
                          "ports": ports, "os_matches": osm})
    return hosts
