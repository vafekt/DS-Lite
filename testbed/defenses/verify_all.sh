#!/bin/bash
# verify_all.sh — honest, single-pass off/on verification of EVERY article/RFC
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

# ── T1 TRABELSI (NAT state exhaustion) — via runner ─────────────────────────
hdr "T1  TRABELSI  (NAT/conntrack state exhaustion)"
bash "$AP" TRABELSI off >/dev/null 2>&1
# do_T1's two-phase RUN_LINE ends with the SIEGE victim code: "... client1=<code> ..."
o=$(dx bash /testbed/scripts/run_attack_live.sh T1 2>&1 | grep -oE 'client1=[0-9]+' | tail -1)
bash "$AP" TRABELSI on >/dev/null 2>&1
n=$(dx bash /testbed/scripts/run_attack_live.sh T1 2>&1 | grep -oE 'client1=[0-9]+' | tail -1)
bash "$AP" TRABELSI off >/dev/null 2>&1
{ echo "$o"|grep -q 000 && echo "$n"|grep -q 200; } && ok TRABELSI "OFF $o | ON $n" || no TRABELSI "OFF $o | ON $n"

# ── T4 ESP_AEAD (softwire interception) ─────────────────────────────────────
hdr "T4  ESP_AEAD  (unencrypted-tunnel interception)"
t4(){ dx ip netns exec b4-1 rm -f /tmp/v.pcap 2>/dev/null
  dx ip netns exec b4-1 timeout 8 tcpdump -i eth-isp -n "ip6 proto 4" -w /tmp/v.pcap >/dev/null 2>&1 &
  sleep 0.6; nse client1 sh -c "for i in 1 2 3 4 5; do curl -s -o /dev/null --max-time 3 http://$SRV/; done" >/dev/null 2>&1; sleep 8
  nse b4-1 tcpdump -nr /tmp/v.pcap -A 2>/dev/null | grep -caiE 'GET /|HTTP/1'; }
bash "$AP" ESP_AEAD off >/dev/null 2>&1; o=$(t4)
bash "$AP" ESP_AEAD on  >/dev/null 2>&1; n=$(t4)
bash "$AP" ESP_AEAD off >/dev/null 2>&1
{ [ "${o:-0}" -gt 0 ] && [ "${n:-0}" -eq 0 ]; } && ok ESP_AEAD "OFF $o cleartext markers | ON $n" || no ESP_AEAD "OFF $o | ON $n"

# ── T3/T5/T6 SAVI (forged softwire source) ──────────────────────────────────
# SAVI per-port source validation drops any carrier packet whose source the
# sending port does not own. All three spoofing attacks forge the victim B4
# source (T3 takeover, T5 downstream injection, T6 reassembly collision), so
# this one check covers the family. SAVI is the reliable T6 defence.
hdr "T3/T5/T6  SAVI  (forged softwire source)"
t3(){ dx ip netns exec aftr rm -f /tmp/t.pcap 2>/dev/null
  dx ip netns exec aftr timeout 8 tcpdump -i eth-isp -n "ip6 src $VB4 and ip6 dst $AFTR and ip6 proto 4" -w /tmp/t.pcap >/dev/null 2>&1 &
  sleep 0.5; nse attacker sh -c "timeout 6 python3 $T/tunnel/tunnel_spoof.py spoof --interface eth-isp --src-ip6 $ATK6 --victim-b4-ip6 $VB4 --aftr-ip6 $AFTR --inner-src-ip4 10.0.1.77 --inner-dst-ip4 $SRV --proto udp --focused --dst-port 9999 --count 8 --batch 1 --interval 0.2" >/dev/null 2>&1; sleep 8
  nse aftr tcpdump -nr /tmp/t.pcap 2>/dev/null | wc -l; }
bash "$AP" SAVI off >/dev/null 2>&1; o=$(t3)
bash "$AP" SAVI on  >/dev/null 2>&1; n=$(t3)
bash "$AP" SAVI off >/dev/null 2>&1
{ [ "${o:-0}" -gt 0 ] && [ "${n:-0}" -eq 0 ]; } && ok SAVI "OFF $o forged reach provider | ON $n (closes T3/T5/T6)" || no SAVI "OFF $o | ON $n"

# ── T6 FEISTEL_IPID (secondary control: unpredictable identifiers) ──────────
hdr "T6  FEISTEL_IPID  (secondary: defeats identifier prediction)"
# Secondary, article-grounded control. The reliable T6 defence is SAVI (above).
# This one defeats only the PREDICTION the classic band attack relies on: a
# sequential counter is predictable, the keyed permutation is not. It does not
# fully stop an on-path attacker that observes and races the live identifier.
# Verified by the module self-test (the algorithm property, auditable).
st=$(dx python3 /testbed/defenses/ipid_feistel.py 2>&1 | grep -oE 'sequential-prediction hits over 2000 ids = [0-9]+')
echo "$st" | grep -qE '= (0|1|2)$' && ok FEISTEL_IPID "$st (counter would be 2000; prediction defeated, secondary to SAVI)" || no FEISTEL_IPID "$st"

# ── T8/T10 PCP_OWNERSHIP (cross-subscriber PCP) ─────────────────────────────
hdr "T8/T10  PCP_OWNERSHIP  (THIRD_PARTY / PEER cross-subscriber)"
t8(){ nse aftr nft flush chain ip nat pcp_dnat 2>/dev/null
  nse client1 sh -c "timeout 8 python3 $T/infra/pcp_attack.py thirdparty --proxy-ip $GW1 --target-internal 10.0.2.100" >/dev/null 2>&1
  nse aftr nft list chain ip nat pcp_dnat 2>/dev/null | grep -c 10.0.2.100; }
restart_pcp "" ; o=$(t8)
restart_pcp "T10_THIRD_PARTY_OWNERSHIP_CHECK=1"; n=$(t8)
restart_pcp ""
{ [ "${o:-0}" -gt 0 ] && [ "${n:-0}" -eq 0 ]; } && ok PCP_OWNERSHIP "OFF $o cross-sub DNAT | ON $n" || no PCP_OWNERSHIP "OFF $o | ON $n"

# ── T7 PCP_QUOTA (port-pool exhaustion, cross-subscriber) ───────────────────
hdr "T7  PCP_QUOTA  (per-subscriber pool exhaustion)"
# The AFTR PCP pool is SHARED across B4s (pcp_server.py). A small pool that the
# flood actually FILLS is needed (a 400-pool is not drained inside the timeout);
# then b4-1's flood starves b4-2 (OFF), and the per-B4 quota leaves room (ON).
t7(){ nse client1 sh -c "timeout 12 python3 $T/infra/pcp_attack.py exhaust --proxy-ip 10.0.1.1 --proto 17 --count 120" >/dev/null 2>&1
  nse client2 sh -c "timeout 8 python3 $T/infra/pcp_attack.py map --proxy-ip 10.0.2.1 --proto 17 --internal-port 9090 2>&1" | grep -qiE 'Mapping created' && echo OK || echo REFUSED; }
restart_pcp "" 60; o=$(t7)
restart_pcp "T_PCP_QUOTA=20" 60; n=$(t7)
restart_pcp "" 1024
{ [ "$o" = REFUSED ] && [ "$n" = OK ]; } && ok PCP_QUOTA "OFF b4-2 $o | ON b4-2 $n" || no PCP_QUOTA "OFF b4-2 $o | ON b4-2 $n"

# ── T9 PCP_AUTH (ANNOUNCE epoch-reset storm) ────────────────────────────────
hdr "T9  PCP_AUTH  (forged ANNOUNCE epoch reset)"
# restart the b4-1 proxy with a captured log so we can count renewal storms it
# actually emitted (the proxy log is the reliable signal; pcap counts race).
restart_pcp_log(){ # $1 env
  nse aftr pkill -9 -f pcp_server.py 2>/dev/null
  nse b4-1 pkill -9 -f pcp_proxy.py 2>/dev/null; nse b4-2 pkill -9 -f pcp_proxy.py 2>/dev/null; sleep 0.6
  dx ip netns exec aftr env PCP_POOL_SIZE=1024 $1 python3 /testbed/aftr/pcp_server.py >/dev/null 2>&1 &
  dx ip netns exec b4-1 sh -c "$1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.1.1 --b4-ip6 $VB4 --aftr-ip6 $AFTR --passthrough-third-party > /tmp/proxy9.log 2>&1" &
  dx ip netns exec b4-2 env $1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.2.1 --b4-ip6 $B42 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  sleep 2; }
t9(){ nse client1 sh -c "timeout 8 python3 $T/infra/pcp_attack.py exhaust --proxy-ip $GW1 --count 30" >/dev/null 2>&1
  sleep 0.5; nse attacker sh -c "timeout 6 python3 $T/infra/pcp_attack.py announce --interface eth-isp --aftr-ip6 $AFTR --count 8" >/dev/null 2>&1; sleep 3
  # grep -c exits 1 on zero matches; capture just the integer (no `|| echo` double-fire)
  local c; c=$(dx sh -c "grep -c 'renewal storm sent' /tmp/proxy9.log 2>/dev/null; true" | head -1 | tr -dc '0-9'); echo "${c:-0}"; }
restart_pcp_log "";           o=$(t9)
restart_pcp_log "T_PCP_AUTH=1"; n=$(t9)
restart_pcp ""
{ [ "${o:-0}" -gt 0 ] && [ "${n:-0}" -eq 0 ]; } && ok PCP_AUTH "OFF $o storms | ON $n storms" || no PCP_AUTH "OFF $o | ON $n"

# ── T2 NAT_LOG (shared-IP attribution) ──────────────────────────────────────
hdr "T2  NAT_LOG  (shared-IPv4 reputation attribution)"
LOG=/var/log/aftr-bindings.log
t2(){ nse client1 sh -c "timeout 6 python3 $T/dns/reputation_poisoning.py --mode scan --target $SRV --count 200" >/dev/null 2>&1; }
cnt(){ dx sh -c "[ -f $LOG ] && wc -l < $LOG | tr -dc 0-9 || echo 0"; }
bash "$AP" NAT_LOG off >/dev/null 2>&1; dx sh -c "rm -f $LOG"; t2; o=$(cnt)
bash "$AP" NAT_LOG on  >/dev/null 2>&1; sleep 0.5; t2; sleep 1
n=$(cnt); bash "$AP" NAT_LOG off >/dev/null 2>&1; dx sh -c "rm -f $LOG"
{ [ "${o:-0}" -eq 0 ] && [ "${n:-0}" -gt 0 ]; } && ok NAT_LOG "OFF $o records | ON $n records" || no NAT_LOG "OFF $o | ON $n"

# ── T14/T15 SNMP_USM (management-plane) ─────────────────────────────────────
hdr "T14/T15  SNMP_USM  (SNMP write / disclosure)"
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

# ── T12/T13 DHCPV6_AUTH (rogue AFTR) ────────────────────────────────────────
hdr "T12/T13  DHCPV6_AUTH  (rogue DHCPv6 AFTR-Name)"
dx test -f /testbed/defenses/keys/dhcpv6_ed25519.sec || dx python3 /testbed/defenses/dhcpv6auth.py keygen --out /testbed/defenses/keys >/dev/null 2>&1
dx pkill -9 -f 'dhcpd -6' 2>/dev/null
# the B4 dhclient holds the client port 546; the verifying client cannot bind
# until it is stopped (otherwise the SOLICIT/ADVERTISE never reaches our client).
nse b4-1 pkill -9 -f 'dhclient.*b4-1' 2>/dev/null; dx pkill -9 -f 'dhclient6-b4-1' 2>/dev/null
dx ip netns exec attacker python3 $T/infra/dhcpv6_hijack.py dhcp --interface eth-isp --attack-id T12 --attacker-ip6 $ATK6 --fake-aftr-fqdn aftr-evil.attacker.example. --fake-aftr-ip6 $ATK6 >/dev/null 2>&1 &
sleep 1.5
o=$(nse b4-1 python3 /testbed/defenses/dhcpv6auth.py client --iface eth-isp --key /testbed/defenses/keys --insecure --wait 4 2>&1 | grep -oE 'AFTR=[^ ]+' | head -1)
dx ip netns exec dhcpv6server python3 /testbed/defenses/dhcpv6auth.py server --iface eth-isp --key /testbed/defenses/keys --aftr aftr.dslite.example.com. --dns $CP::2 >/dev/null 2>&1 &
sleep 0.5
n=$(nse b4-1 python3 /testbed/defenses/dhcpv6auth.py client --iface eth-isp --key /testbed/defenses/keys --wait 4 2>&1 | grep -oE 'AFTR=[^ ]+' | head -1)
dx pkill -9 -f 'dhcpv6_hijack.py' 2>/dev/null; dx pkill -9 -f 'dhcpv6auth.py server' 2>/dev/null
{ echo "$o"|grep -qi evil && echo "$n"|grep -qi 'aftr.dslite'; } && ok DHCPV6_AUTH "OFF $o | ON $n" || no DHCPV6_AUTH "OFF $o | ON $n"

# ── T11 DNS_0X20 (off-path AFTR-FQDN poisoning) — via runner ────────────────
hdr "T11  DNS_0X20  (off-path DNS poisoning)"
# clean any leftover off-path resolver scaffolding from earlier in this run
nse b4-1 pkill -9 -f dns_0x20_forwarder 2>/dev/null
nse dns-server pkill -9 -f dns_sink 2>/dev/null
nse dns-server ip -6 addr del $CP::5/64 dev eth-isp 2>/dev/null
nse b4-1 sysctl -qw net.core.rmem_max=33554432 2>/dev/null
bash "$AP" DNS_0X20 off >/dev/null 2>&1
o=$(dx bash /testbed/scripts/run_attack_live.sh T11 2>&1 | grep -oE 'resolved to [0-9a-f:]+|resolved to <none>' | tail -1)
bash "$AP" DNS_0X20 on >/dev/null 2>&1
n=$(dx bash /testbed/scripts/run_attack_live.sh T11 2>&1 | grep -oE 'resolved to [0-9a-f:]+|resolved to <none>' | tail -1)
bash "$AP" DNS_0X20 off >/dev/null 2>&1
{ echo "$o"|grep -qiE '::13a|cafe:0:' && ! echo "$n"|grep -qiE '::13a|cafe:0:'; } && ok DNS_0X20 "OFF $o | ON $n" || no DNS_0X20 "OFF $o | ON $n"

# ── summary ─────────────────────────────────────────────────────────────────
printf '\n================ %d PASS, %d FAIL ================\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
