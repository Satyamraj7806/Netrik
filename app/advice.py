"""Plain-language explanations and actions. Fixed rules, no generated text, no invented evidence."""

from __future__ import annotations

PORTS = {
    21: ("File Transfer (FTP)", "sends passwords and files without encryption"),
    23: ("Telnet remote login", "sends everything, including passwords, without encryption"),
    135: ("Windows RPC", "is used for Windows management and is rarely needed across zones"),
    139: ("NetBIOS file sharing", "is an older Windows sharing service"),
    445: ("Windows file sharing (SMB)", "lets other computers read and write shared files"),
    1433: ("SQL Server database", "should normally only be reachable by the applications that use it"),
    3306: ("MySQL database", "should normally only be reachable by the applications that use it"),
    3389: ("Remote Desktop", "lets someone control the computer's screen from the network"),
    5432: ("PostgreSQL database", "should normally only be reachable by the applications that use it"),
    5900: ("VNC remote screen", "lets someone view and control the screen, often with weak protection"),
    9100: ("Printer raw printing", "accepts print jobs directly from any computer that can reach it"),
}

BASE = {
    "new_device": dict(title="Unrecognised device", plain="A device we have not seen before appeared on the network.",
        action="Find out whose device it is. If it belongs to someone, approve it. If nobody knows, check which port or Wi-Fi network it joined and decide whether to block it.",
        verify="Approve it once identified, or confirm it no longer appears in later scans."),
    "new_device_random": dict(title="New device with a randomised address", plain="A new device appeared that hides its real hardware address. This is normal for modern phones.",
        action="Treat it as a likely visitor phone. If your policy is to track personal devices, check it against the Wi-Fi controller's client list.",
        verify="No technical fix is needed. Check again later; the same phone may appear under a new address."),
    "new_service": dict(title="New service on an approved device", plain="A device now offers a network service it did not offer before.",
        action="Ask the device owner whether the change was planned. If not, find what software opened the port and whether it should be reachable.",
        verify="Run another test from the same location after the change is reviewed."),
    "service_closed": dict(title="Service no longer open", plain="A service that was open earlier was not found in the latest scan.",
        action="Check whether the service was stopped on purpose. If it was expected to be running, investigate the device.",
        verify="Scan again from the same location to confirm the state is stable."),
    "policy_violation": dict(title="Access that your own policy forbids", plain="A test connected to a service that your written policy says should be blocked from this network zone.",
        action="Find the firewall rule or network setting that allows this path and restrict it to the approved zones or administrator devices.",
        verify="After the change, run the same test from the same location. It should no longer connect."),
    "stale_device": dict(title="Device not seen recently", plain="No source has reported this device for a while.",
        action="Check whether the device was switched off or moved. For a server or network device, investigate promptly.",
        verify="It will close automatically when any source sees the device again."),
    "ip_conflict": dict(title="Address clash", plain="Two different hardware addresses used the same IP address within minutes.",
        action="Check DHCP settings and look for a device with a fixed address that clashes. If it keeps recurring, investigate the second device.",
        verify="Re-check the neighbour table and DHCP leases after the fix."),
    "policy_site": dict(title="Restricted website requested", plain="A device asked for a website that your own rule restricts.",
        action="Talk to the device owner or check who was using it. If the site must stay blocked, enforce it on the firewall or DNS filter so the request cannot succeed.",
        verify="Watch for new matching requests after the change: import a fresh DNS or proxy log, or use the DNS monitor, and confirm none appear."),
    "port_forbidden": dict(title="Forbidden service running", plain="A service that your policy says must not run in this zone is running.",
        action="Stop or disable the service on the device, or update the rule if the policy has changed.",
        verify="Run the same test again from the same location. The port should no longer answer."),
    "sensitive_default": dict(title="Sensitive service reachable", plain="A service that is usually restricted answered from the tested network location.",
        action="Confirm whether this access is needed. If not, restrict it to approved administrator devices or a management network.",
        verify="Run another authorised test from the same location and compare the result."),
}


def get(alert) -> dict:
    key = alert["rec_key"] or ""
    if key.startswith("port_"):
        port = int(key.split("_")[1])
        name, risk = PORTS.get(port, ("Network service", "is exposed on the network"))
        return dict(title=f"{name} reachable", plain=f"{name} appears accessible from the tested network location. This service {risk}. Verify whether this access is required.",
                    action=f"Review the access policy for {name}. If it is not required from this network zone, restrict access to approved administrator devices or a dedicated management network.",
                    verify="Run another authorised test from the same network location and compare the result.")
    return BASE.get(key, BASE["sensitive_default"])


def port_note(port: int) -> str | None:
    p = PORTS.get(port)
    return f"{p[0]} {p[1]}." if p else None
