#!/usr/bin/env bash
# Bayora PoC - network segmentation demo (run on the Docker host as root).
# Simulates deny-by-default micro-segmentation between tenants: red and
# blue can only reach the backend; the LLM is reachable ONLY from the
# backend. In compose this is approximated by the internal `bayora`
# bridge (Ollama publishes no port); this script is the iptables version
# for hosts running tenants as plain containers.
set -euo pipefail

BACKEND_CIDR="172.20.0.0/24"
RED_CIDR="172.20.1.0/24"
BLUE_CIDR="172.20.2.0/24"
LLM_IP="172.20.0.30"

iptables -N BAYORA 2>/dev/null || true
iptables -F BAYORA
iptables -A BAYORA -j LOG --log-prefix "bayora-deny " --log-level 4
iptables -A BAYORA -j DROP

iptables -A FORWARD -s "$RED_CIDR"  -d "$BACKEND_CIDR" -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -s "$RED_CIDR"  -j BAYORA
iptables -A FORWARD -s "$BLUE_CIDR" -d "$BACKEND_CIDR" -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -s "$BLUE_CIDR" -j BAYORA
iptables -A FORWARD -d "$LLM_IP" ! -s "$BACKEND_CIDR" -j BAYORA

echo "[bayora] tenant segmentation applied."