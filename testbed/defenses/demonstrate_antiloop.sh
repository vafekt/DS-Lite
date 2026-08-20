#!/bin/bash
# demonstrate_antiloop.sh - RFC 6324 anti-loop rule demonstration.
#
# The conformant AFTR forward policy already blocks inter-softwire routing
# (policy drop, only Internet-bound NEW connections accepted), so an RFC 6324
# loop cannot complete on the shipped build. This shows the DECAP-BIND anti-loop
# rule INDEPENDENTLY drops the packet that would seed such a loop: a decapsulated
# datagram whose inner destination is a co-resident's private (overlapping)
# address. We inject it on a provisioned softwire (forging the B4 outer source,
# inner source inside that B4's prefix so the inner-source bind passes) and read
# the anti-loop rule's drop counter.
#   CONTAINER_NAME=ds-lite-lab bash testbed/defenses/demonstrate_antiloop.sh
set -u
C="${CONTAINER_NAME:-ds-lite-lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"; AP="$HERE/article_defenses.sh"
CP=2001:db8:cafe; AFTR=$CP::10; VB4=$CP::b41; ATK6=$CP::13a; T=/testbed/attack_tools
LOOPDST=10.0.2.1   # co-resident (behind B4-2) private address, in the overlap range
dx(){ docker exec "$C" "$@"; }
nse(){ docker exec "$C" ip netns exec "$@"; }
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
loopctr(){ nse aftr nft list chain ip decap_bind ingress 2>/dev/null | grep 'ds-lite-b4-1.*10\.0\.0\.0/16' | grep -oE 'packets [0-9]+' | awk '{print $2}'; }
inject(){ nse attacker sh -c "timeout 5 python3 $T/tunnel/tunnel_spoof.py spoof --interface eth-isp --src-ip6 $ATK6 --victim-b4-ip6 $VB4 --aftr-ip6 $AFTR --inner-src-ip4 10.0.1.77 --inner-dst-ip4 $LOOPDST --proto udp --focused --dst-port 9999 --count 10 --batch 1 --interval 0.15" >/dev/null 2>&1; }

prov_attacker; hub_bridge
nse aftr sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done' 2>/dev/null
bash "$AP" DECAP_BIND on >/dev/null 2>&1   # default overlap is 10.0.0.0/16 (the subscriber space)
b=$(loopctr); inject; sleep 1; a=$(loopctr)
echo "== RFC 6324 anti-loop rule =="
echo "  injected 10 private-destined ($LOOPDST) decapsulated packets on a provisioned softwire"
echo "  anti-loop rule drops: before=$b after=$a  ->  dropped $((a-b)) at decapsulation"
echo "  (the conformant forward policy also blocks the inter-softwire routing a loop needs)"
bash "$AP" DECAP_BIND off >/dev/null 2>&1
