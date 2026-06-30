#!/bin/bash
# dhclient6 exit hook for DS-Lite (RFC 6334)
#
# On every successful DHCPv6 binding:
#   1. Record the AFTR FQDN learned from option 64 in /var/run/ds-lite-aftr-name
#   2. Resolve that FQDN via the DHCPv6-provided DNS and, if a ds-lite tunnel
#      already exists, rebuild it whenever EITHER the AFTR name changed OR the
#      address it resolves to changed. This models a real CPE (re-resolves on
#      renewal) and covers both AFTR attacks:
#        T14  Rogue AFTR substitution — a NEW (attacker) AFTR FQDN is adopted.
#        T14B Transparent AFTR hijack — the LEGIT FQDN is kept but a rogue DNS
#             (handed to the B4 via Option 23) resolves it to the attacker, so
#             the cached name still looks legitimate while traffic is redirected.

AFTR_FILE="/var/run/ds-lite-aftr-name"
HIJACK_LOG="/var/log/ds-lite-hijack.log"

# Diagnostic trace (every invocation) so AFTR-hijack attacks are debuggable.
printf '{"event":"hook_fired","reason":"%s","aftr_name":"%s","name_servers":"%s","ts":"%s"}\n' \
    "$reason" "$new_dhcp6_aftr_name" "$new_dhcp6_name_servers" "$(date -u +%FT%TZ)" >>"$HIJACK_LOG" 2>/dev/null

[ -z "$new_dhcp6_aftr_name" ] && exit 0

OLD_FQDN=""
[ -f "$AFTR_FILE" ] && OLD_FQDN=$(tr -d '[:space:]' <"$AFTR_FILE")
NEW_FQDN=$(printf '%s' "$new_dhcp6_aftr_name" | tr -d '[:space:]')

printf '%s\n' "$new_dhcp6_aftr_name" >"$AFTR_FILE"

# Initial bring-up: setup.sh owns tunnel creation.
[ -z "$OLD_FQDN" ] && exit 0
ip link show ds-lite >/dev/null 2>&1 || exit 0

# Resolve the AFTR FQDN through the DNS server learned via DHCPv6 (RFC 8415
# Option 23), exactly as a real CPE does — falling back to the provisioned
# resolver. Under T14B the supplied DNS is the attacker's rogue resolver.
RESOLVER="${new_dhcp6_name_servers%% *}"
[ -z "$RESOLVER" ] && RESOLVER="2001:db8:cafe::2"
NEW_AFTR_IPV6=$(host -t AAAA "$NEW_FQDN" "$RESOLVER" 2>/dev/null \
    | awk '/has IPv6 address/ {print $NF; exit}')
printf '{"event":"resolve","fqdn":"%s","resolver":"%s","resolved":"%s","ts":"%s"}\n' \
    "$NEW_FQDN" "$RESOLVER" "$NEW_AFTR_IPV6" "$(date -u +%FT%TZ)" >>"$HIJACK_LOG" 2>/dev/null
if [ -z "$NEW_AFTR_IPV6" ]; then
    logger -t ds-lite "could not resolve $NEW_FQDN via $RESOLVER — keeping current tunnel"
    exit 0
fi

# Rebuild only when the AFTR endpoint actually changes: a different name, or
# the same name now resolving to a different address (the stealthy hijack).
CUR_REMOTE=$(ip -d link show ds-lite 2>/dev/null \
    | grep -oE 'remote [0-9a-f:]+' | awk '{print $2}')
if [ "$NEW_FQDN" = "$OLD_FQDN" ] && [ "$NEW_AFTR_IPV6" = "$CUR_REMOTE" ]; then
    exit 0
fi

logger -t ds-lite "AFTR endpoint change: name '$OLD_FQDN'->'$NEW_FQDN', addr '$CUR_REMOTE'->'$NEW_AFTR_IPV6' — rebuilding tunnel"

# The softwire MUST be sourced from the STABLE softwire identity (::b4N), not a
# DHCPv6-leased or SLAAC address. Picking the first global address here was a bug:
# on a lease renewal it rebuilt the tunnel with the DHCP address, which the AFTR
# does not recognise as the B4, silently killing the subscriber's data path.
B4_IPV6=$(ip -6 addr show dev eth-isp scope global \
    | grep -oE '[0-9a-f:]+::b4[0-9]' | head -1)
[ -z "$B4_IPV6" ] && B4_IPV6=$(ip -6 addr show dev eth-isp scope global \
    | awk '/inet6/ && !/fe80/ {split($2,a,"/"); print a[1]; exit}')

ip link del ds-lite 2>/dev/null
ip link add name ds-lite mtu 1500 \
    type ip6tnl local "$B4_IPV6" remote "$NEW_AFTR_IPV6" \
    mode ip4ip6 encaplimit none dev eth-isp 2>/dev/null
ip link set ds-lite up
ip addr add 192.0.0.2/32 dev ds-lite 2>/dev/null
ip route add default dev ds-lite 2>/dev/null

logger -t ds-lite "tunnel rebuilt: remote=$NEW_AFTR_IPV6"
printf '{"event":"tunnel_rebuilt","new_fqdn":"%s","new_aftr_ipv6":"%s","ts":"%s"}\n' \
    "$NEW_FQDN" "$NEW_AFTR_IPV6" "$(date -u +%FT%TZ)" >>"$HIJACK_LOG"
exit 0
