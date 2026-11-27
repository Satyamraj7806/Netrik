"""One honest progress picture from Nmap's live output, the XML phase timestamps and a probe-volume estimate."""

from __future__ import annotations

import re
import time

LABELS = {"discover": "Finding live hosts", "ports": "Scanning ports", "services": "Identifying services", "os": "Detecting operating systems",
          "scripts": "Running checks", "neighbours": "Reading neighbour table and DHCP", "names": "Looking up hostnames", "save": "Saving evidence"}
SHORT = {"discover": "Discover", "ports": "Ports", "services": "Services", "os": "OS", "scripts": "Checks", "neighbours": "Sources", "names": "Names", "save": "Save"}
WEIGHTS = {"discover": 6, "ports": 52, "services": 24, "os": 12, "scripts": 6, "neighbours": 8, "names": 8, "save": 4}

TIMING = re.compile(r"(\S.*?) Timing: About ([\d.]+)% done(?:; ETC: [\d:]+ \(([\d:]+) remaining\))?")
STATS = re.compile(r"Stats: [\d:]+ elapsed; (\d+) hosts? completed \((\d+) up\), (\d+) undergoing (.+)")
INIT = re.compile(r"^Initiating (.+?) at \d")
COMPLETED = re.compile(r"^Completed (.+?) at \d")
OPEN = re.compile(r"Discovered open port (\d+)/(tcp|udp) on ([\d.]+)")
SCANNING = re.compile(r"^Scanning (.+?) \[(\d+) ports?\]")
SKIP = re.compile(r"Skipping host (\S+)")


def plan_for(kind: str, args: list, privileged: bool) -> list:
    if kind == "names":
        return ["names", "save"]
    if kind == "discovery":
        return ["discover", "neighbours", "names", "save"]
    plan = ["discover", "ports"]
    if "-sV" in args:
        plan.append("services")
    if "-O" in args and privileged:
        plan.append("os")
    return plan + ["names", "save"]


def phase_of(task: str):
    t = task.lower()
    if any(k in t for k in ("ping scan", "arp", "host discovery", "dns")):
        return "discover"
    if "service scan" in t:
        return "services"
    if "os detection" in t or t.startswith("os "):
        return "os"
    if "nse" in t or "script" in t:
        return "scripts"
    if "scan" in t:
        return "ports"
    return None


def _secs(hms: str | None):
    if not hms:
        return None
    parts = [int(p) for p in hms.split(":")]
    while len(parts) < 3:
        parts.insert(0, 0)
    return parts[0] * 3600 + parts[1] * 60 + parts[2]


class Tracker:
    def __init__(self, plan: list, ports_estimate_s: float | None = None):
        self.plan, self.t0 = plan, time.time()
        self.phase, self.done = plan[0], set()
        self.pct, self.remaining, self.last_timing = 0.0, None, 0.0
        self.phase_start, self.est = self.t0, ports_estimate_s
        self.hosts_up = self.hosts_done = 0
        self.feed, self.seen_xml = [], 0

    def _event(self, kind: str, text: str):
        self.feed.append({"t": int(time.time() - self.t0), "kind": kind, "text": text})
        del self.feed[:-40]

    def enter(self, phase: str):
        """Move forward to a later phase; never backwards."""
        if phase not in self.plan or self.plan.index(phase) <= self.plan.index(self.phase):
            return
        for p in self.plan[: self.plan.index(phase)]:
            self.done.add(p)
        self.phase, self.pct, self.remaining, self.phase_start = phase, 0.0, None, time.time()
        self._event("phase", f"Started: {LABELS[phase]}")

    def on_line(self, line: str):
        m = TIMING.search(line)
        if m:
            ph = phase_of(m.group(1))
            if ph:
                self.enter(ph)
                if ph == self.phase:
                    self.pct, self.remaining, self.last_timing = float(m.group(2)), _secs(m.group(3)), time.time()
            return
        m = STATS.search(line)
        if m:
            self.hosts_done, self.hosts_up = int(m.group(1)), int(m.group(2))
            ph = phase_of(m.group(4))
            if ph:
                self.enter(ph)
            return
        m = INIT.match(line)
        if m and phase_of(m.group(1)):
            self.enter(phase_of(m.group(1)))
            return
        m = COMPLETED.match(line)
        if m and phase_of(m.group(1)) == self.phase:
            self.pct, self.remaining = 100.0, 0
            return
        m = OPEN.search(line)
        if m:
            self._event("port", f"{m.group(1)}/{m.group(2)} open on {m.group(3)}")
            return
        m = SCANNING.match(line)
        if m:
            self._event("info", f"Scanning {m.group(1)} ({m.group(2)} ports)")
            return
        m = SKIP.search(line)
        if m:
            self._event("warn", f"Skipped {m.group(1)}: per-host time limit reached")

    def on_xml(self, text: str):
        """Fallback: the XML records when each phase began, even if no progress lines arrive."""
        begins = re.findall(r'<taskbegin task="([^"]+)"', text)
        if len(begins) > self.seen_xml:
            self.seen_xml = len(begins)
            ph = phase_of(begins[-1])
            if ph:
                self.enter(ph)

    def finish(self):
        self.done.update(self.plan)
        self.pct, self.remaining = 100.0, 0

    def snapshot(self) -> dict:
        now = time.time()
        pct, estimated, remaining = self.pct, False, self.remaining
        if self.phase == "ports" and self.est and now - self.last_timing > 6 and self.phase not in self.done:
            spent = now - self.phase_start
            pct, estimated, remaining = min(95.0, spent / self.est * 100), True, max(0, int(self.est - spent))
        total = sum(WEIGHTS[p] for p in self.plan)
        base = sum(WEIGHTS[p] for p in self.plan if p in self.done)
        active = 0 if self.phase in self.done else WEIGHTS[self.phase] * pct / 100
        overall = min(100.0, (base + active) / total * 100)
        known = pct > 0 or self.phase in self.done
        steps = [{"key": p, "label": SHORT[p], "weight": WEIGHTS[p],
                  "state": "done" if p in self.done else ("active" if p == self.phase else "todo")} for p in self.plan]
        return {"phase": self.phase, "label": LABELS[self.phase], "percent": round(overall, 1), "stage_percent": round(pct, 1),
                "remaining_s": remaining, "estimated": estimated, "indeterminate": not known, "hosts_up": self.hosts_up,
                "hosts_done": self.hosts_done, "steps": steps, "feed": self.feed[-14:]}
