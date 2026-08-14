#!/bin/bash
# aps_two_ip.sh — empirically separate the Affected-Population Scope levels
# Shared-IPv4 and AFTR-Wide by running the AFTR with TWO public IPv4 addresses.
#
# Added for the R2 revision (reviewer request: "run the testbed with >=2 public
# IPv4 addresses per AFTR to empirically separate APS Shared-IPv4 vs AFTR-Wide").
#
# Design. The default build SNATs every subscriber to one shared address
# (192.0.2.1), so the two APS levels coincide in measurement. This script:
#   1. measures each subscriber's egress public IPv4 in the default 1-address
#      mode (both share 192.0.2.1 -> a per-address abuse consequence such as
#      TS1 reputation blocklisting would hit both: Shared-IPv4 cohort = 2);
#   2. reconfigures the AFTR with a second public address and partitions the
#      subscribers (B4-1 -> 192.0.2.1, B4-2 -> 192.0.2.2), then re-measures:
#      the two subscribers now egress on different addresses, so the
#      Shared-IPv4 consequence reaches only the co-address subscriber and is
#      strictly smaller than AFTR-Wide;
#   3. runs an AFTR-hosted attack (T11 MIB disclosure) as the AFTR-Wide
#      contrast: it discloses BOTH subscribers' bindings regardless of which
#      public address they egress on, so its reach is unchanged by the split.
#   4. restores the single-address default.
#
# Run:  docker exec ds-lite-lab bash /testbed/scripts/aps_two_ip.sh
set -u
nse() { ip netns exec "$@"; }
SRV=198.51.100.2
C1=10.0.1.100; C2=10.0.2.100
T=/testbed/attack_tools
NFT_DEFAULT=/testbed/aftr/nftables.conf
# Two-address ruleset ships alongside the default at /testbed/aftr/; fall back to
# a /tmp copy if the script is run against an older image via `docker cp`.
NFT_2IP=/testbed/aftr/nftables_2ip.conf
[ -f "$NFT_2IP" ] || NFT_2IP=/tmp/nftables_2ip.conf

hr() { printf '%s\n' "----------------------------------------------------------------"; }

# egress_ip <client_ns> <client_inner_ip> -> public IPv4 the AFTR SNATs it to
egress_ip() {
    nse aftr conntrack -F >/dev/null 2>&1
    nse "$1" curl -s -o /dev/null --max-time 5 "http://$SRV/" >/dev/null 2>&1
    sleep 0.4
    nse aftr conntrack -L 2>/dev/null | grep "src=$2 " | grep -oE 'dst=192\.0\.2\.[0-9]+' \
        | tail -1 | cut -d= -f2
}

echo "================================================================"
echo "  APS separation experiment — one vs two public IPv4 on the AFTR"
echo "================================================================"
echo

hr
echo "STAGE 1 — default single-address mode (all subscribers share 192.0.2.1)"
hr
nse aftr nft -f "$NFT_DEFAULT" 2>/dev/null
nse aftr ip addr del 192.0.2.2/24 dev eth-wan 2>/dev/null
a1=$(egress_ip client1 "$C1"); a2=$(egress_ip client2 "$C2")
echo "  subscriber B4-1 (client $C1) egress public IPv4 = ${a1:-<none>}"
echo "  subscriber B4-2 (client $C2) egress public IPv4 = ${a2:-<none>}"
if [ "$a1" = "$a2" ] && [ -n "$a1" ]; then
    echo "  => both subscribers share $a1: a reputation block on $a1 denies BOTH"
    echo "     (Shared-IPv4 cohort = every subscriber behind the AFTR here = AFTR-Wide)"
    S1=OK; else S1=FAIL; fi
echo

hr
echo "STAGE 2 — two-address mode (B4-1 -> 192.0.2.1, B4-2 -> 192.0.2.2)"
hr
nse aftr ip addr add 192.0.2.2/24 dev eth-wan 2>/dev/null
nse aftr nft -f "$NFT_2IP" 2>/dev/null
nse aftr conntrack -F >/dev/null 2>&1
b1=$(egress_ip client1 "$C1"); b2=$(egress_ip client2 "$C2")
echo "  subscriber B4-1 (client $C1) egress public IPv4 = ${b1:-<none>}"
echo "  subscriber B4-2 (client $C2) egress public IPv4 = ${b2:-<none>}"
if [ -n "$b1" ] && [ -n "$b2" ] && [ "$b1" != "$b2" ]; then
    echo "  => subscribers egress on DIFFERENT addresses: a reputation block on $b1"
    echo "     denies only B4-1; B4-2 on $b2 is unaffected"
    echo "     (Shared-IPv4 cohort is strictly SMALLER than AFTR-Wide)"
    S2=OK; else S2=FAIL; fi
echo

hr
echo "STAGE 3 — AFTR-Wide contrast: MIB disclosure (T11) under the two-address split"
hr
# Warm one binding for each subscriber so both appear in the AFTR NAT table.
nse client1 curl -s -o /dev/null --max-time 5 "http://$SRV/" >/dev/null 2>&1
nse client2 curl -s -o /dev/null --max-time 5 "http://$SRV/" >/dev/null 2>&1
sleep 0.5
walk=$(nse mgmt sh -c "timeout 20 python3 $T/infra/snmp_attack.py read --target 10.99.0.1 --oids all 2>&1")
g1=$(echo "$walk" | grep -c "$C1"); g2=$(echo "$walk" | grep -c "$C2")
echo "  MIB walk disclosed B4-1 subscriber ($C1) bindings: $([ "${g1:-0}" -gt 0 ] && echo YES || echo no)"
echo "  MIB walk disclosed B4-2 subscriber ($C2) bindings: $([ "${g2:-0}" -gt 0 ] && echo YES || echo no)"
if [ "${g1:-0}" -gt 0 ] && [ "${g2:-0}" -gt 0 ]; then
    echo "  => the AFTR-hosted attack reaches BOTH subscribers despite the address split"
    echo "     (AFTR-Wide reach is independent of the public-IPv4 partition)"
    S3=OK; else S3=FAIL; fi
echo

hr
echo "RESTORE — single-address default"
hr
nse aftr nft -f "$NFT_DEFAULT" 2>/dev/null
nse aftr ip addr del 192.0.2.2/24 dev eth-wan 2>/dev/null
nse aftr conntrack -F >/dev/null 2>&1
r1=$(egress_ip client1 "$C1"); r2=$(egress_ip client2 "$C2")
echo "  restored egress: B4-1 -> ${r1:-<none>}, B4-2 -> ${r2:-<none>}"
echo

echo "================================================================"
echo "  RESULT  stage1(shared)=$S1  stage2(separated)=$S2  stage3(AFTR-wide)=$S3"
echo "  1-address: B4-1=$a1 B4-2=$a2   |   2-address: B4-1=$b1 B4-2=$b2"
echo "  T11 under split: B4-1 disclosed=$([ "${g1:-0}" -gt 0 ] && echo yes || echo no),"\
     "B4-2 disclosed=$([ "${g2:-0}" -gt 0 ] && echo yes || echo no)"
echo "================================================================"
