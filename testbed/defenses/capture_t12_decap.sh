#!/bin/bash
# capture_t12_decap.sh — per-defense OFF/ON evidence for the two mitigations that
# post-date the original capture set: SAVI vs T12 (softwire identity
# multiplication / shared-pool drain) and DECAP_BIND vs T11 (softwire decap
# relay). Mirrors capture_defenses.sh conventions. Artifacts are written INSIDE
# the container under the bind-mounted /testbed/pcaps/defcap/ so they surface on
# the host; copy them into reference_captures/defenses/ from the host.
# Run from the host:  bash testbed/defenses/capture_t12_decap.sh
set -u
C="${CONTAINER_NAME:-ds-lite-lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"
AP="$HERE/article_defenses.sh"
T=/testbed/attack_tools
CP=2001:db8:cafe; AFTR=$CP::10; ATK6=$CP::13a; SRV=198.51.100.2; SHARED=192.0.2.1
dx(){ docker exec "$C" "$@"; }
nse(){ docker exec "$C" ip netns exec "$@"; }
dxsh(){ docker exec "$C" sh -c "$1"; }
OUT=/testbed/pcaps/defcap
mk(){ dx mkdir -p "$OUT/$1"; }
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
prov_attacker; hub_bridge
nse aftr sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done' 2>/dev/null  # default build, uRPF off

# ── SAVI vs T12 (softwire identity multiplication) ──────────────────────────
# T12 forges MANY outer softwire identities from cafe:dead::/64 (a DIFFERENT /64
# than the carrier prefix) to drain the shared 64,512-port pool. Proper SAVI
# (2000::/3 scope) drops every forged identity at the carrier bridge, so none
# reach the AFTR and the pool never fills.
echo "SAVI_T12"; mk SAVI_T12
t12cap(){ # $1 = OFF|ON
  nse aftr conntrack -F >/dev/null 2>&1
  nse aftr sh -c "timeout 12 tcpdump -U -ni eth-isp -c 500 -w '$OUT/SAVI_T12/SAVI_T12_$1_aftr_eth-isp.pcap' 'ip6 src net 2001:db8:cafe:dead::/64 and ip6 proto 4' >/dev/null 2>&1 &"
  sleep 0.8
  nse attacker sh -c "timeout 12 python3 $T/nat/nat_exhaustion.py eth-isp --tunnel --src-ip6-prefix ${CP}:dead::/64 --fixed-dport 80 --proto tcp --dst-ip4 $SRV --aftr-ip6 $AFTR --inner-src-prefix 10.90.0.0/16 --threads 8 --batch 256 >/dev/null 2>&1" &
  sleep 9
  local pool c1 c2
  pool=$(nse aftr conntrack -L 2>/dev/null | grep -c "dst=$SRV.*dport=80")
  c1=$(nse client1 curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://$SRV/ 2>/dev/null)
  c2=$(nse client2 curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://$SRV/ 2>/dev/null)
  nse attacker pkill -9 -f nat_exhaustion 2>/dev/null; stopcap
  local reached; reached=$(nse aftr sh -c "tcpdump -nr '$OUT/SAVI_T12/SAVI_T12_$1_aftr_eth-isp.pcap' 2>/dev/null | wc -l")
  dxsh "printf 'SAVI %s vs T12 (softwire identity multiplication)\nforged softwire packets (cafe:dead::/64) reaching the AFTR: %s\nshared-pool bindings (->:80): %s\nco-resident client1 HTTP: %s\nco-resident client2 HTTP: %s\n' '$1' '$reached' '$pool' '$c1' '$c2' > $OUT/SAVI_T12/SAVI_T12_$1.result.txt"; }
bash "$AP" SAVI off >/dev/null 2>&1; t12cap OFF
bash "$AP" SAVI on  >/dev/null 2>&1; t12cap ON
bash "$AP" SAVI off >/dev/null 2>&1
nse aftr conntrack -F >/dev/null 2>&1

# ── DECAP_BIND vs T11 (softwire decap relay) ────────────────────────────────
# An UNPROVISIONED carrier host builds a softwire to the AFTR and relays IPv4 to
# the Internet, laundered as the shared public IPv4. DECAP_BIND drops it by
# binding the decapsulated packet to a provisioned softwire; a legitimate
# subscriber (client1) is unaffected.
echo "DECAP_BIND"; mk DECAP_BIND
nse attacker ip link del atkrelay 2>/dev/null
nse attacker ip link add atkrelay type ip6tnl local $ATK6 remote $AFTR mode ip4ip6 encaplimit none 2>/dev/null
nse attacker ip link set atkrelay up 2>/dev/null
nse attacker ip addr add 10.66.66.66/32 dev atkrelay 2>/dev/null
nse attacker ip route add 198.51.100.0/24 dev atkrelay 2>/dev/null
decapcap(){ # $1 = tag, $2 = source-ns
  nse aftr conntrack -F >/dev/null 2>&1
  nse server sh -c "timeout 8 tcpdump -U -ni eth0 -w '$OUT/DECAP_BIND/DECAP_BIND_$1_server_eth0.pcap' 'icmp and src $SHARED' >/dev/null 2>&1 &"
  sleep 1; nse "$2" ping -c 3 -i 0.3 -W1 $SRV >/dev/null 2>&1; sleep 2
  stopcap
  local relayed; relayed=$(nse server sh -c "tcpdump -nr '$OUT/DECAP_BIND/DECAP_BIND_$1_server_eth0.pcap' 2>/dev/null | grep -c 'echo request'")
  dxsh "printf 'DECAP_BIND %s (source %s): echo-requests relayed to the Internet as shared IPv4 %s: %s\n' '$1' '$2' '$SHARED' '$relayed' > $OUT/DECAP_BIND/DECAP_BIND_$1.result.txt"; }
bash "$AP" DECAP_BIND off >/dev/null 2>&1; decapcap OFF attacker
bash "$AP" DECAP_BIND on  >/dev/null 2>&1; decapcap ON attacker; decapcap ON-legit client1
bash "$AP" DECAP_BIND off >/dev/null 2>&1
nse attacker ip link del atkrelay 2>/dev/null

echo "DONE — evidence in pcaps/defcap/{SAVI_T12,DECAP_BIND}/"
