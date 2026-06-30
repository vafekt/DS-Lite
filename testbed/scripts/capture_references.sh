#!/bin/bash
# capture_references.sh — generate the project's REFERENCE packet captures, stored
# INSIDE the testbed (testbed/reference_captures/) so they ship with the project
# and are easy to find + compare against, and are not in the volatile ./pcaps
# runtime folder. Run from the host:  bash testbed/scripts/capture_references.sh
#
# Produces three groups:
#   baseline/   normal testbed traffic, every communication type (no attack)
#   attacks/Tn/ each attack run cleanly (the attack SUCCEEDS) — via the runner
#   defenses/   each defence OFF (attack succeeds) vs ON (attack blocked)
set -u
C="${CONTAINER_NAME:-ds-lite-lab}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REF="$ROOT/testbed/reference_captures"
T=/testbed/attack_tools
CP=2001:db8:cafe; AFTR=$CP::10; VB4=$CP::b41; B42=$CP::b42; ATK6=$CP::13a
GW1=10.0.1.1; SRV=198.51.100.2
dx(){ docker exec "$C" "$@"; }
nse(){ docker exec "$C" ip netns exec "$@"; }
AP="$ROOT/testbed/defenses/article_defenses.sh"
say(){ printf '  %s\n' "$*"; }
hdr(){ printf '\n== %s ==\n' "$*"; }

# tcpdump helper: start a capture in a netns, detached so it survives this call.
cap_start(){ # <ns> <iface> <filter> <outfile-in-container>
  dx ip netns exec "$1" rm -f "$4" 2>/dev/null
  # -U (packet-buffered) writes each packet to the file immediately. Without it
  # tcpdump buffers ~4 KB, so a low-volume capture (a handful of packets) is
  # still unflushed when cap_pull cats the file, yielding an EMPTY pcap.
  docker exec -d "$C" ip netns exec "$1" timeout "${CAP_SECS:-12}" tcpdump -U -i "$2" -n -w "$4" "$3" >/dev/null 2>&1
  sleep 0.8; }
cap_pull(){ # <outfile-in-container> <dest-on-host>
  sleep "${CAP_DRAIN:-3}"; mkdir -p "$(dirname "$2")"
  dx cat "$1" > "$2" 2>/dev/null; }

prov_attacker(){ nse attacker ip link show eth-isp >/dev/null 2>&1 || dx sh -c '
  ip netns add attacker 2>/dev/null
  ip link add eth-isp-atk type veth peer name atk-br 2>/dev/null
  ip link set eth-isp-atk netns attacker 2>/dev/null
  ip netns exec attacker ip link set eth-isp-atk name eth-isp 2>/dev/null
  ip link set atk-br master br-isp 2>/dev/null; ip link set atk-br up 2>/dev/null
  ip netns exec attacker ip link set lo up 2>/dev/null
  ip netns exec attacker ip link set eth-isp up 2>/dev/null
  ip netns exec attacker ip -6 addr add '"$ATK6"'/64 dev eth-isp 2>/dev/null'; }

# lab_restore — FULL clean baseline between captures, so no attack's state or
# config overlaps into the next. Stronger than the runner's reset_state: it also
# restarts the PCP server+proxies (clears the in-memory pool from T7), restarts
# the SNMP agent (resets the alarm threshold a T14 SET left at max), restores the
# stock DHCPv6 + B4 resolver, and removes any leftover defence state.
lab_restore(){
  # kill every attack tool + any defence daemon/scaffolding
  dx pkill -9 -f 'nat_exhaustion|nat_hold|tunnel_spoof|reputation_poisoning|pcp_attack|fragment_attack|dhcpv6_hijack|dns_cache_poison|dns_offpath_poison|t5_softwire_inject|t10_peer_crosssub|dns_0x20_forwarder|dns_sink|trabelsi_guard|feistel_b4|snmpv3_client|dhcpv6auth.py|conntrack -E' 2>/dev/null
  # PCP: restart server + proxies clean (no defence env, fresh pool)
  nse aftr pkill -9 -f pcp_server.py 2>/dev/null
  nse b4-1 pkill -9 -f pcp_proxy.py 2>/dev/null; nse b4-2 pkill -9 -f pcp_proxy.py 2>/dev/null; sleep 0.4
  dx ip netns exec aftr env PCP_POOL_SIZE=1024 python3 /testbed/aftr/pcp_server.py >/dev/null 2>&1 &
  dx ip netns exec b4-1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.1.1 --b4-ip6 $VB4 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  dx ip netns exec b4-2 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.2.1 --b4-ip6 $B42 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  # SNMP: restart agent (resets the alarm threshold to default 60)
  nse aftr pkill -9 -f snmp_agent.py 2>/dev/null; sleep 0.3
  dx ip netns exec aftr python3 -u /testbed/aftr/snmp_agent.py --host 10.99.0.1 --port 161 --community public >/dev/null 2>&1 &
  # DHCPv6: stock dhcpd6 + B4 dhclients/resolver
  dx pkill -9 -f 'dhcpv6auth.py server' 2>/dev/null; dx pkill -9 -f 'dhcpd -6' 2>/dev/null; sleep 0.2
  dx ip netns exec dhcpv6server /usr/sbin/dhcpd -6 -cf /etc/dhcp/dhcpd6.conf -lf /var/lib/dhcp/dhcpd6.leases -pf /var/run/dhcpd6.pid eth-isp >/dev/null 2>&1 &
  # remove any defence state (savi bridge, ESP xfrm, feistel nft, rp_filter, conntrack timeouts)
  dx nft delete table bridge savi 2>/dev/null
  nse aftr ip xfrm state flush 2>/dev/null; nse aftr ip xfrm policy flush 2>/dev/null
  nse b4-1 ip xfrm state flush 2>/dev/null; nse b4-2 ip xfrm state flush 2>/dev/null
  nse b4-1 nft delete table ip feistel 2>/dev/null; nse b4-2 nft delete table ip feistel 2>/dev/null
  nse aftr sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_syn_recv=60 net.netfilter.nf_conntrack_tcp_timeout_syn_sent=60 net.netfilter.nf_conntrack_udp_timeout=30 >/dev/null 2>&1
  # clear residual attack state: conntrack, PCP-DNAT, NDP, AFTR-name, softwire, T11 silent-upstream
  nse aftr conntrack -F >/dev/null 2>&1
  nse aftr nft flush chain ip nat pcp_dnat 2>/dev/null
  nse aftr ip -6 neigh flush dev eth-isp 2>/dev/null
  nse b4-1 sh -c "echo 'aftr.dslite.example.com.' > /run/ds-lite-aftr-name" 2>/dev/null
  nse b4-2 sh -c "echo 'aftr.dslite.example.com.' > /run/ds-lite-aftr-name" 2>/dev/null
  nse dns-server pkill -9 -f dns_sink 2>/dev/null
  nse dns-server ip -6 addr del $CP::5/64 dev eth-isp 2>/dev/null
  # heal the softwire local endpoints (a DHCPv6 hijack can flush ::b4N)
  nse b4-1 ip -6 addr add $VB4/64 dev eth-isp 2>/dev/null
  nse b4-2 ip -6 addr add $B42/64 dev eth-isp 2>/dev/null
  nse b4-1 ip -6 tunnel change ds-lite local $VB4 remote $AFTR 2>/dev/null
  nse b4-2 ip -6 tunnel change ds-lite local $B42 remote $AFTR 2>/dev/null
  sleep 1.5
}

mkdir -p "$REF"
prov_attacker
lab_restore   # start from a known-clean baseline

# ─────────────────────────────────────────────────────────────────────────
# 1. BASELINE — normal traffic, every communication type, NO attack
# ─────────────────────────────────────────────────────────────────────────
hdr "Baseline (normal full-communication capture)"
B="$REF/baseline"; mkdir -p "$B"
# Clean stale artifacts from prior runs so the shipped dir holds only this
# run's output (README.md and NOTES are preserved / rewritten below).
find "$B" -maxdepth 1 -type f \( -name '*.pcap' -o -name '*.log' \) -delete 2>/dev/null
CAP_SECS=16
cap_start b4-1 eth-isp "" /tmp/base_b4_isp.pcap          # softwire + DHCPv6 + DNS + PCP + NDP
cap_start aftr eth-wan "" /tmp/base_aftr_wan.pcap         # NAT'd egress to the Internet
cap_start aftr eth-mgmt "" /tmp/base_mgmt.pcap 2>/dev/null # SNMP management plane
cap_start b4-1 eth-lan "" /tmp/base_lan.pcap              # subscriber LAN
sleep 0.5
say "triggering every communication type ..."
# (a) HTTP through the DS-Lite softwire + CGNAT
nse client1 sh -c "curl -s -o /dev/null --max-time 5 http://$SRV/" >/dev/null 2>&1
nse client2 sh -c "curl -s -o /dev/null --max-time 5 http://$SRV/" >/dev/null 2>&1
# (b) DNS resolution through the B4 resolver
nse client1 sh -c "dig +short server.dslite.example.com @$GW1" >/dev/null 2>&1
# (c) DHCPv6 renew (option 64 AFTR-Name exchange)
nse b4-1 dhclient -6 -1 -nw -cf /etc/dhcp/dhclient6-b4-1.conf -lf /var/lib/dhcp/dhclient6-b4-1.leases -pf /tmp/dh.pid eth-isp >/dev/null 2>&1
# (d) PCP MAP (port mapping request to the AFTR)
nse client1 sh -c "timeout 5 python3 $T/infra/pcp_attack.py map --proxy-ip $GW1 --proto 17 --internal-port 8080" >/dev/null 2>&1
# (e) SNMP GET on the management plane
nse mgmt snmpget -v2c -c public -t1 10.99.0.1 1.3.6.1.2.1.240.1.2.2.0 >/dev/null 2>&1
# (f) ICMPv6 ping across the carrier
nse client1 sh -c "ping -c 3 $SRV" >/dev/null 2>&1
CAP_DRAIN=6
cap_pull /tmp/base_b4_isp.pcap  "$B/baseline_b4-1_eth-isp.pcap"
cap_pull /tmp/base_aftr_wan.pcap "$B/baseline_aftr_eth-wan.pcap"
cap_pull /tmp/base_mgmt.pcap    "$B/baseline_aftr_mgmt.pcap"
cap_pull /tmp/base_lan.pcap     "$B/baseline_client1_eth-lan.pcap"
for f in "$B"/*.pcap; do
  c=$(command -v tcpdump >/dev/null 2>&1 && tcpdump -nr "$f" 2>/dev/null | wc -l || echo "?")
  say "$(basename "$f"): ${c} pkts ($(wc -c < "$f" 2>/dev/null) bytes)"
done
cat > "$B/NOTES.txt" <<EOF
Baseline reference capture — normal DS-Lite operation, NO attack running.
Communication types exercised: HTTP through the 4-in-6 softwire + CGNAT, DNS via
the B4 resolver, DHCPv6 (option-64 AFTR-Name), PCP MAP, SNMP GET (mgmt plane),
ICMPv6 ping. Capture points:
  baseline_b4-1_eth-isp.pcap  carrier side of B4-1 (softwire/DHCPv6/DNS/PCP/NDP)
  baseline_aftr_eth-wan.pcap  AFTR public side (CGNAT egress as the shared IPv4)
  baseline_aftr_mgmt.pcap     AFTR management plane (SNMP)
  baseline_client1_eth-lan.pcap  subscriber LAN behind B4-1
EOF

# ─────────────────────────────────────────────────────────────────────────
# 2. ATTACKS — each attack run cleanly via the runner (attack SUCCEEDS)
# ─────────────────────────────────────────────────────────────────────────
hdr "Attacks (clean per-attack captures)"
for n in $(seq 1 15); do
  ID="T$n"
  lab_restore                       # clean baseline BEFORE each attack (no overlap)
  say "running $ID ..."
  outdir=$(dx bash /testbed/scripts/run_attack_live.sh "$ID" 2>&1 | grep -oE 'pcaps/runs/[0-9TZ]+_'"$ID" | head -1)
  [ -z "$outdir" ] && { say "  $ID: no output dir"; continue; }
  dest="$REF/attacks/$ID"; mkdir -p "$dest"
  # drop stale pcaps/logs from prior (differently-named) capture runs so the
  # dir holds only this run's runner pcaps + RESULT.txt (README.md preserved)
  find "$dest" -maxdepth 1 -type f \( -name '*.pcap' -o -name '*.log' -o -name 'RESULT.txt' -o -name 'config.txt' \) -delete 2>/dev/null
  dx sh -c "cp /testbed/$outdir/*.pcap /testbed/$outdir/RESULT.txt /testbed/$outdir/config.txt /tmp/ 2>/dev/null; true"
  for f in $(dx sh -c "ls /testbed/$outdir/*.pcap 2>/dev/null"); do
    bn=$(basename "$f"); dx cat "$f" > "$dest/$bn" 2>/dev/null
  done
  dx cat "/testbed/$outdir/RESULT.txt" > "$dest/RESULT.txt" 2>/dev/null
  # Auto-generate a README that matches the actual files (so the docs never
  # drift from the captures). The full narration + verdict live in RESULT.txt.
  {
    aname=$(grep -oE 'live attack  '"$ID"'  —  .*' "$dest/RESULT.txt" | sed 's/.*—  //')
    verdict=$(grep -E '^\s*verdict:' "$dest/RESULT.txt" | sed 's/^\s*//')
    echo "# $ID — ${aname:-$ID}"
    echo
    echo "Reference packet captures for $ID, regenerated from the testbed by"
    echo "\`testbed/scripts/capture_references.sh\` (one capture point per file)."
    echo "The step-by-step narration, measured signal, and verdict are in"
    echo "[\`RESULT.txt\`](RESULT.txt)."
    echo
    echo "## Capture points"
    echo
    echo "| file | packets |"
    echo "|---|---|"
    for f in "$dest"/*.pcap; do
      [ -f "$f" ] || continue
      pc=$(command -v tcpdump >/dev/null 2>&1 && tcpdump -nr "$f" 2>/dev/null | wc -l || echo "?")
      echo "| \`$(basename "$f")\` | $pc |"
    done
    echo
    echo "## Verdict"
    echo
    echo "\`\`\`"
    grep -E '^\s*(reference|this run|verdict):' "$dest/RESULT.txt" | sed 's/^\s*//'
    echo "\`\`\`"
  } > "$dest/README.md"
  say "  $ID -> $(ls "$dest"/*.pcap 2>/dev/null | wc -l) pcap(s)"
done

# ─────────────────────────────────────────────────────────────────────────
# 3. DEFENCES — capture each attack's key point with the defence OFF vs ON
# ─────────────────────────────────────────────────────────────────────────
hdr "Defences (off vs on captures)"
restart_pcp(){ nse aftr pkill -9 -f pcp_server.py 2>/dev/null
  nse b4-1 pkill -9 -f pcp_proxy.py 2>/dev/null; nse b4-2 pkill -9 -f pcp_proxy.py 2>/dev/null; sleep 0.6
  dx ip netns exec aftr env PCP_POOL_SIZE="${2:-1024}" $1 python3 /testbed/aftr/pcp_server.py >/dev/null 2>&1 &
  dx ip netns exec b4-1 env $1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.1.1 --b4-ip6 $VB4 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  dx ip netns exec b4-2 env $1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.2.1 --b4-ip6 $B42 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  sleep 2; }
defcap(){ # <DEF> <ns> <iface> <filter> <attack-cmd> ; captures off+on, restoring around each
  local def="$1" ns="$2" if="$3" flt="$4" cmd="$5" d="$REF/defenses/$1"; mkdir -p "$d"
  find "$d" -maxdepth 1 -type f -name '*.pcap' -delete 2>/dev/null   # drop stale pcaps
  CAP_SECS=14
  lab_restore                                  # clean baseline before the OFF case
  bash "$AP" "$def" off >/dev/null 2>&1; sleep 1
  cap_start "$ns" "$if" "$flt" /tmp/doff.pcap; eval "$cmd"; cap_pull /tmp/doff.pcap "$d/${def}_OFF_${ns}_${if}.pcap"
  lab_restore                                  # restore, then apply the defence for the ON case
  bash "$AP" "$def" on  >/dev/null 2>&1; sleep 1
  cap_start "$ns" "$if" "$flt" /tmp/don.pcap;  eval "$cmd"; cap_pull /tmp/don.pcap  "$d/${def}_ON_${ns}_${if}.pcap"
  bash "$AP" "$def" off >/dev/null 2>&1
  lab_restore                                  # RESTORE after the defence (no overlap into the next)
  say "$def: OFF $(dx tcpdump -nr /tmp/doff.pcap 2>/dev/null|wc -l) pkts | ON $(dx tcpdump -nr /tmp/don.pcap 2>/dev/null|wc -l) pkts"; }

# SAVI (T3): spoofed softwire from attacker -> count packets reaching the AFTR
defcap SAVI aftr eth-isp "ip6 src $VB4 and ip6 dst $AFTR and ip6 proto 4" \
  "nse attacker sh -c \"timeout 6 python3 $T/tunnel/tunnel_spoof.py spoof --interface eth-isp --src-ip6 $ATK6 --victim-b4-ip6 $VB4 --aftr-ip6 $AFTR --inner-src-ip4 10.0.1.77 --inner-dst-ip4 $SRV --proto udp --focused --dst-port 9999 --count 8 --batch 1 --interval 0.2 >/dev/null 2>&1\""

# ESP_AEAD (T4): victim softwire — cleartext inner HTTP vs ESP ciphertext
defcap ESP_AEAD b4-1 eth-isp "ip6 proto 4 or esp" \
  "nse client1 sh -c \"for i in 1 2 3 4 5; do curl -s -o /dev/null --max-time 3 http://$SRV/; done >/dev/null 2>&1\""

# SNMP_USM (T14): mgmt-plane SNMP — v2c SET accepted vs USM-only (v2c dropped)
defcap SNMP_USM aftr eth-mgmt "udp port 161" \
  "nse mgmt sh -c \"timeout 6 python3 $T/infra/snmp_attack.py set --target 10.99.0.1 --oid alarmConnectNumber --value 2147483647 >/dev/null 2>&1\""

# PCP_OWNERSHIP (T8): PCP THIRD_PARTY naming a different subscriber — accepted vs NOT_AUTHORIZED
defcap PCP_OWNERSHIP aftr eth-isp "udp port 5351" \
  "nse client1 sh -c \"timeout 6 python3 $T/infra/pcp_attack.py thirdparty --proxy-ip $GW1 --target-internal 10.0.2.100 >/dev/null 2>&1\""

# DHCPV6_AUTH and SNMP_USM and PCP_* and NAT_LOG and TRABELSI and FEISTEL_IPID and
# DNS_0X20 have their authoritative off/on EVIDENCE in
# results/defense_verification/VERIFY_ALL.txt (real measured numbers). The two
# captures above are representative packet-level off/on artefacts; the PCP/SNMP/
# DHCPv6/DNS defences act at the application layer (result codes / signatures),
# best read from VERIFY_ALL.txt rather than raw packet counts.
cat > "$REF/defenses/NOTES.txt" <<EOF
Defence captures: <DEF>_OFF_*.pcap (attack succeeds) vs <DEF>_ON_*.pcap (blocked).
SAVI: OFF shows spoofed softwire (src $VB4) reaching the AFTR; ON shows zero
(the carrier-bridge binding drops the spoof at the access port).
ESP_AEAD: OFF shows cleartext inner IPv4/HTTP on the softwire; ON shows only ESP
ciphertext (no readable inner packets).
The full off/on result table for ALL 11 defences (with measured numbers, incl.
the application-layer PCP/SNMP/DHCPv6/DNS controls) is in
results/defense_verification/VERIFY_ALL.txt and is reproducible via
testbed/defenses/verify_all.sh.
EOF
restart_pcp "" >/dev/null 2>&1

hdr "DONE — reference captures under testbed/reference_captures/"
say "baseline: $(ls "$REF"/baseline/*.pcap 2>/dev/null | wc -l) pcaps"
say "attacks:  $(ls -d "$REF"/attacks/T* 2>/dev/null | wc -l) attacks"
say "defences: $(ls -d "$REF"/defenses/*/ 2>/dev/null | wc -l) captured"
