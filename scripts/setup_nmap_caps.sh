#!/usr/bin/env bash
# Lets Nmap send raw packets (ARP/SYN/OS detection) without running the web app as root.
# Run once with sudo, then set nmap_privileged: true in config.yaml.
set -e
NMAP="$(command -v nmap)"
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP"
getcap "$NMAP"
echo "Done. Set nmap_privileged: true in config.yaml and restart Netrik."
