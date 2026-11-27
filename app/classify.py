"""Conservative device-role labels built on the existing Netrik classifier."""

from __future__ import annotations

from netrik.stages.classification import classify_host


def kind_for(ip, hostname, vendor, ports, os_matches, randomized, gateway_ip):
    services = [{"port": p["port"], "protocol": p["protocol"], "service": p.get("service", "unknown"),
                 "product": p.get("product", ""), "version": p.get("version", "")} for p in ports if p.get("state") == "open"]
    info = classify_host({"matches": os_matches} if os_matches else {}, services, hostname, vendor)
    openp = {s["port"] for s in services}
    label = info["label"]
    if gateway_ip and ip == gateway_ip:
        kind = "Gateway / router"
    elif openp & {9100, 515, 631}:
        kind = "Printer"
    elif label.startswith("Likely Windows"):
        kind = "Windows host"
    elif label.startswith("Likely Linux"):
        kind = "Linux host"
    elif label.startswith("Likely Apple"):
        kind = "Apple device"
    elif label.startswith("Likely network appliance"):
        kind = "Network appliance"
    elif label.startswith("Likely embedded"):
        kind = "Embedded / IoT"
    elif openp & {445, 3389, 135}:
        kind = "Windows host (likely)"
    elif randomized and not openp:
        kind = "Mobile device (likely)"
    else:
        kind = "Unknown"
    return kind, (None if label.startswith("Unknown") else label), info
