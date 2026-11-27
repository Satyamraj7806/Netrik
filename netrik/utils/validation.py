"""Target and port validation shared by the CLI and the web application."""

from __future__ import annotations

import ipaddress
import re

_PORTS = re.compile(r"^\d{1,5}([,-]\d{1,5})*$")


def parse_targets(text: str, allowed: list, max_hosts: int = 1024) -> list[str]:
    """Return normalised IPv4 targets, or raise ValueError with a plain-language reason.

    Only literal IP addresses or CIDR ranges inside the authorised networks are accepted.
    Hostnames, Nmap options and anything starting with '-' are rejected.
    """
    items = [i for i in re.split(r"[,\s]+", (text or "").strip()) if i]
    if not items:
        raise ValueError("Enter at least one target.")
    nets = []
    for item in items:
        if item.startswith("-"):
            raise ValueError(f"'{item}' looks like a command option, not a target.")
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"'{item}' is not an IPv4 address or CIDR range (hostnames are not accepted).")
        if net.version != 4:
            raise ValueError("Only IPv4 targets are supported.")
        if not any(net.subnet_of(a) for a in allowed):
            shown = ", ".join(str(a) for a in allowed) or "none configured"
            raise ValueError(f"{net} is outside the authorised ranges ({shown}). Edit allowed_ranges in config.yaml.")
        nets.append(net)
    if sum(n.num_addresses for n in nets) > max_hosts:
        raise ValueError(f"That is more than {max_hosts} addresses. Scan a smaller range.")
    return [str(n.network_address) if n.num_addresses == 1 else str(n) for n in nets]


def parse_ports(text: str | None) -> str | None:
    text = (text or "").strip().replace(" ", "")
    if not text:
        return None
    if not _PORTS.match(text) or len(text) > 100:
        raise ValueError("Ports must look like 22,80,443 or 1-1024.")
    for part in re.split(r"[,-]", text):
        if not 1 <= int(part) <= 65535:
            raise ValueError("Port numbers must be between 1 and 65535.")
    return text
