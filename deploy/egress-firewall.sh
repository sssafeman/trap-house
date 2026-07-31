#!/usr/bin/env bash
# egress-firewall.sh: Restrict outbound traffic from the attacker-facing Docker
# network so a compromised honeypot cannot be used as a pivot, exfil path, or
# C2 relay. Applies default-deny egress to the trap-external bridge subnet on
# the host DOCKER-USER chain, allowing only DNS, replies to inbound
# connections, and traffic to private ranges.
#
# Why: Cowrie emulates wget/curl by making real outbound fetches, and the
# external bridge otherwise has unrestricted NAT egress. This closes that.
#
# Trade-offs (both features reach the public internet and are blocked by this):
#   - Frontend IP geolocation (ip-api.com): the attack map still renders, just
#     without lat/long. Add an ACCEPT rule for its IPs if you want geo back.
#   - Future external canary integration: add an explicit destination rule
#     only after reviewing its privacy and egress implications.
#
# Run as root on the VPS, after the stack is up:  sudo bash deploy/egress-firewall.sh
# Rules are inserted with a comment tag so re-running replaces them cleanly.
# They are not persisted across reboot by default; install iptables-persistent
# or re-run from a systemd unit if you want them to survive a restart.

set -euo pipefail

TAG="trap-egress"
EXT_NET="trap-external"

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root." >&2
  exit 1
fi

# Resolve the subnet of the external bridge network.
SUBNET="$(docker network inspect "$EXT_NET" \
  --format '{{ (index .IPAM.Config 0).Subnet }}' 2>/dev/null || true)"
if [ -z "$SUBNET" ]; then
  echo "Could not find subnet for docker network '$EXT_NET'. Is the stack up?" >&2
  exit 1
fi
echo "External network subnet: $SUBNET"

# Remove any rules we previously added (idempotent), matched by the comment tag.
while IFS= read -r rule; do
  rule="${rule#-A DOCKER-USER }"
  read -r -a rule_args <<< "$rule"
  iptables -D DOCKER-USER "${rule_args[@]}" 2>/dev/null || true
done < <(iptables -S DOCKER-USER | grep -F "$TAG" | sed 's/^-A DOCKER-USER //')

# Rules are inserted at the top of DOCKER-USER in reverse priority order.
# Final effect (top to bottom): allow established/related, allow DNS, allow
# private ranges, then drop everything else from the honeypot subnet.

# 4) Default deny for new egress from the honeypot subnet.
iptables -I DOCKER-USER 1 -s "$SUBNET" -j DROP -m comment --comment "$TAG-default-deny"

# 3) Allow traffic to private/internal ranges (inter-container, host, LAN).
for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  iptables -I DOCKER-USER 1 -s "$SUBNET" -d "$cidr" -j RETURN -m comment --comment "$TAG-allow-private"
done

# 2) Allow DNS so name resolution still works.
iptables -I DOCKER-USER 1 -s "$SUBNET" -p udp --dport 53 -j RETURN -m comment --comment "$TAG-allow-dns"
iptables -I DOCKER-USER 1 -s "$SUBNET" -p tcp --dport 53 -j RETURN -m comment --comment "$TAG-allow-dns"

# 1) Allow replies to connections the honeypot did not initiate.
iptables -I DOCKER-USER 1 -s "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN -m comment --comment "$TAG-allow-established"

# --- ALLOWLIST -------------------------------------------------------------
# To permit a specific public destination (for future canary integration or geolocation),
# add its IP above the default-deny, for example:
#   iptables -I DOCKER-USER 1 -s "$SUBNET" -d <IP> -p tcp --dport 443 -j RETURN \
#     -m comment --comment "$TAG-allow-canary"
# ---------------------------------------------------------------------------

echo "Egress rules applied for $SUBNET (tag: $TAG). Current DOCKER-USER chain:"
iptables -S DOCKER-USER | grep -- "$TAG" || true
