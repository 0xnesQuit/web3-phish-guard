#!/usr/bin/env bash
# Block the sandbox container's network from reaching anything private on this VPS.
#
# The sandbox opens hostile pages. Even though the container has its own loopback, a page's scripts could still try
# to reach the host's LAN, the VPN (10.8.0.0), the Docker gateway, or the cloud metadata endpoint. This inserts
# DROP rules in Docker's DOCKER-USER chain for the sandbox subnet -> every private destination. Public IPs (sites,
# the RPC endpoints) stay reachable.
#
# Run once after `docker compose up -d`, and again after the Docker daemon restarts (rules live in the kernel, not
# in compose). Idempotent: it removes its own rules first. Requires root.
set -euo pipefail

SUBNET="172.31.253.0/24"   # must match docker-compose.yml
CHAIN="DOCKER-USER"

# private / internal destinations the container must never reach
BLOCK=(
  10.0.0.0/8        # RFC1918 (includes the 10.8.0.0 VPN)
  172.16.0.0/12     # RFC1918 (includes Docker bridges / the gateway)
  192.168.0.0/16    # RFC1918
  169.254.0.0/16    # link-local + cloud metadata (169.254.169.254)
  127.0.0.0/8       # loopback
  100.64.0.0/10     # CGNAT / Tailscale
)

# also block this host's own public IP(s): a service bound to 0.0.0.0 (e.g. sshd) would otherwise be reachable
for ip in $(hostname -I 2>/dev/null); do
  case "$ip" in
    10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*|169.254.*|127.*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|*:*) : ;;
    *) BLOCK+=("$ip/32") ;;
  esac
done

need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }
need iptables

# remove any rules we added before (match on the comment), so re-running is clean
while iptables -L "$CHAIN" -n --line-numbers 2>/dev/null | grep -q "w3pg-sandbox-egress"; do
  n=$(iptables -L "$CHAIN" -n --line-numbers | awk '/w3pg-sandbox-egress/{print $1; exit}')
  iptables -D "$CHAIN" "$n"
done

# insert DROPs at the top of DOCKER-USER (processed before Docker's own ACCEPTs)
for dst in "${BLOCK[@]}"; do
  iptables -I "$CHAIN" -s "$SUBNET" -d "$dst" -m comment --comment "w3pg-sandbox-egress" -j DROP
done

echo "egress block installed for $SUBNET -> ${BLOCK[*]}"
echo "verify:  iptables -L $CHAIN -n --line-numbers | grep w3pg-sandbox-egress"
echo "NOTE: re-run this after any Docker daemon restart."
