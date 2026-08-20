#!/bin/bash
# dhclient6 exit hook for DS-Lite (RFC 6334) -- PINNED variant.
# Adds AFTR-name pinning: the B4 rejects any DHCPv6-supplied AFTR FQDN that is
# not under its provisioned ISP domain. The pin is a PUBLIC domain string set
# out-of-band at provisioning (/etc/ds-lite/aftr-pin), so nothing secret is
# bootstrapped -- unlike signed-DHCPv6, which needs a per-server key the B4 has
# no way to obtain at first contact. This closes the rogue-NAME hijack (T9).

AFTR_FILE="/var/run/ds-lite-aftr-name"
HIJACK_LOG="/var/log/ds-lite-hijack.log"

printf '{"event":"hook_fired","reason":"%s","aftr_name":"%s","name_servers":"%s","ts":"%s"}\n' \
    "$reason" "$new_dhcp6_aftr_name" "$new_dhcp6_name_servers" "$(date -u +%FT%TZ)" >>"$HIJACK_LOG" 2>/dev/null

[ -z "$new_dhcp6_aftr_name" ] && exit 0

OLD_FQDN=""
[ -f "$AFTR_FILE" ] && OLD_FQDN=$(tr -d '[:space:]' <"$AFTR_FILE")
NEW_FQDN=$(printf '%s' "$new_dhcp6_aftr_name" | tr -d '[:space:]')

# ── AFTR-name pinning (T9 defense) ───────────────────────────────────
# Reject any AFTR FQDN not under the provisioned ISP domain. The pin is
# public (a domain name), set out-of-band, so no secret key is required.
PIN_FILE="/etc/ds-lite/aftr-pin"
if [ -f "$PIN_FILE" ]; then
    PIN=$(tr -d '[:space:]' <"$PIN_FILE" | sed 's/\.$//')
    CHK=$(printf '%s' "$NEW_FQDN" | sed 's/\.$//')
    case ".$CHK" in
        *".$PIN") : ;;   # under the pinned domain: accept
        *)
            logger -t ds-lite "AFTR name '$NEW_FQDN' outside pinned domain '$PIN' -- REJECTED (T9 pin)"
            printf '{"event":"pin_reject","fqdn":"%s","pin":"%s","ts":"%s"}\n' \
                "$NEW_FQDN" "$PIN" "$(date -u +%FT%TZ)" >>"$HIJACK_LOG" 2>/dev/null
            exit 0        # keep the current (legit) AFTR, do not adopt or rebuild
            ;;
    esac
fi

printf '%s\n' "$new_dhcp6_aftr_name" >"$AFTR_FILE"

[ -z "$OLD_FQDN" ] && exit 0
ip link show ds-lite >/dev/null 2>&1 || exit 0

# Resolver pinning (T9b defense): resolve the AFTR name through the provisioned
# resolver, not the DHCPv6-supplied one (Option 23), so a rogue resolver cannot
# redirect the legit name. The pinned resolver is public config, no secret key.
RPIN_FILE="/etc/ds-lite/aftr-resolver"
if [ -f "$RPIN_FILE" ]; then
    RESOLVER=$(tr -d '[:space:]' <"$RPIN_FILE")
else
    RESOLVER="${new_dhcp6_name_servers%% *}"
    [ -z "$RESOLVER" ] && RESOLVER="2001:db8:cafe::2"
fi
NEW_AFTR_IPV6=$(host -t AAAA "$NEW_FQDN" "$RESOLVER" 2>/dev/null \
    | awk '/has IPv6 address/ {print $NF; exit}')
printf '{"event":"resolve","fqdn":"%s","resolver":"%s","resolved":"%s","ts":"%s"}\n' \
    "$NEW_FQDN" "$RESOLVER" "$NEW_AFTR_IPV6" "$(date -u +%FT%TZ)" >>"$HIJACK_LOG" 2>/dev/null
if [ -z "$NEW_AFTR_IPV6" ]; then
    logger -t ds-lite "could not resolve $NEW_FQDN via $RESOLVER -- keeping current tunnel"
    exit 0
fi

CUR_REMOTE=$(ip -d link show ds-lite 2>/dev/null \
    | grep -oE 'remote [0-9a-f:]+' | awk '{print $2}')
if [ "$NEW_FQDN" = "$OLD_FQDN" ] && [ "$NEW_AFTR_IPV6" = "$CUR_REMOTE" ]; then
    exit 0
fi

logger -t ds-lite "AFTR endpoint change: name '$OLD_FQDN'->'$NEW_FQDN', addr '$CUR_REMOTE'->'$NEW_AFTR_IPV6' -- rebuilding tunnel"

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
