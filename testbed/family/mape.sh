#!/bin/bash
# MAP-E (RFC 7597) BR forward-path validation harness, Linux-native (ip6tnl+nft).
# MAP-E's CE->IPv4+port-set mapping is ALGORITHMIC (derivable from the CE IPv6),
# validated at the BR against the algorithm, NOT a provisioned roster.
# MAP rule (simplified): CE 2001:db8:1a0e::10X -> 198.51.100.1 ports [X*4096..X*4096+4095].
# Tests which (outer-src, inner-sport) the BR relays out (egress on WAN).
set +e
PFX=2001:db8:1a0e
BRMAC=02:00:0e:00:00:10

echo "########## teardown + build ##########"
for ns in mapbr mapsnd mapsrv; do ip netns del $ns 2>/dev/null; done
ip link del br-mape 2>/dev/null; sleep 0.3
for ns in mapbr mapsnd mapsrv; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
ip link add br-mape type bridge; ip link set br-mape up
echo 0 > /sys/class/net/br-mape/bridge/multicast_snooping 2>/dev/null
# BR and sender on the MAP bridge (explicit args; IPv6/MAC contain colons)
attach(){ ns=$1; ip6=$2; mac=$3
  ip link add ${ns}-i type veth peer name ${ns}-b; ip link set ${ns}-i netns $ns
  ip link set ${ns}-b master br-mape; ip link set ${ns}-b up
  ip netns exec $ns ip link set ${ns}-i name eth-map
  ip netns exec $ns ip link set eth-map address $mac
  ip netns exec $ns ip link set eth-map up
  ip netns exec $ns ip -6 addr add ${ip6}/64 dev eth-map
  ip netns exec $ns sysctl -qw net.ipv6.conf.eth-map.accept_dad=0 net.ipv6.conf.all.forwarding=1
}
attach mapbr  ${PFX}::10  $BRMAC
attach mapsnd ${PFX}::150 02:00:0e:00:01:50
# WAN + server
ip link add mw-a type veth peer name mw-s; ip link set mw-a netns mapbr; ip link set mw-s netns mapsrv
ip netns exec mapbr ip link set mw-a name eth-wan up; ip netns exec mapbr ip addr add 203.0.113.1/24 dev eth-wan
ip netns exec mapsrv ip link set mw-s name eth0 up; ip netns exec mapsrv ip addr add 203.0.113.9/24 dev eth0; ip netns exec mapsrv ip route add default via 203.0.113.1
# BR: catch-all decap (mode any) + forward
ip netns exec mapbr sh -c "modprobe ip6_tunnel 2>/dev/null; ip link add mapbr0 type ip6tnl local ${PFX}::10 mode any encaplimit none; ip link set mapbr0 up; sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1"

echo "########## BR ALGORITHMIC validation (mark = outer-src low byte = X ; inner sport in [X*4096..]) ##########"
# Validate BEFORE decap at the IPv6 layer: inner TCP sport is at byte 60 (IPv6 40 + IPv4 20),
# i.e. bit offset 480. Accept only (outer src ::10X) whose inner sport is in X's algorithmic
# port-set [X*4096..]; drop every other 4in6. This is MAP-E's algorithmic check (no roster):
# ::103 is a valid-but-unassigned MAP address -> accepted (the weakness); ::150 (X=0x50) has
# no in-range port-set -> dropped; wrong sport for the source -> dropped.
ip netns exec mapbr nft -f - <<'NFT'
flush ruleset
table ip6 mapmon {
  chain in { type filter hook prerouting priority raw; policy accept
    ip6 saddr 2001:db8:1a0e::101 @nh,480,16 4096-8191   counter return
    ip6 saddr 2001:db8:1a0e::102 @nh,480,16 8192-12287  counter return
    ip6 saddr 2001:db8:1a0e::103 @nh,480,16 12288-16383 counter return
    ip6 nexthdr 4 counter drop comment "map-e algorithmic reject"
  }
}
NFT

# decapsulated inner src (198.51.100.1) has no reverse route on the BR; disable rp_filter so it forwards
ip netns exec mapbr sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter; for d in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $d 2>/dev/null; done'

echo "########## server ##########"
printf 'import socketserver\nclass H(socketserver.BaseRequestHandler):\n def handle(self):\n  try:\n   self.request.recv(1024); self.request.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length:2\\r\\n\\r\\nok")\n  except Exception: pass\nclass S(socketserver.ThreadingTCPServer):\n allow_reuse_address=True; daemon_threads=True\nS(("203.0.113.9",80),H).serve_forever()\n' > /tmp/mapsrv.py
ip netns exec mapsrv setsid python3 /tmp/mapsrv.py </dev/null >/tmp/mapsrv.log 2>&1 &
sleep 1

echo "########## TEST: which (outer-src, inner-sport) does the MAP-E BR relay out? ##########"
snap(){ ip netns exec mapbr nft list chain ip6 mapmon in 2>/dev/null | awk '
  /counter/{ p=0; for(i=1;i<=NF;i++) if($i=="packets") p=$(i+1); if(/return/)A+=p; if(/drop/)D+=p }
  END{ print (A+0)" "(D+0) }'; }
run(){ label="$1"; src6="$2"; sport="$3"
  read A0 D0 <<<"$(snap)"
  ip netns exec mapsnd python3 - "$src6" "$sport" <<'PY'
import sys
from scapy.all import Ether,IPv6,IP,TCP,sendp
src6,sport=sys.argv[1],int(sys.argv[2])
pkts=[Ether(dst="02:00:0e:00:00:10")/IPv6(src=src6,dst="2001:db8:1a0e::10",nh=4)/IP(src="198.51.100.1",dst="203.0.113.9")/TCP(sport=sport+i,dport=80,flags="S") for i in range(10)]
sendp(pkts,iface="eth-map",verbose=0)
PY
  sleep 0.7
  read A1 D1 <<<"$(snap)"
  acc=$((A1-A0)); drp=$((D1-D0))
  v=DROPPED; [ "$acc" -gt 0 ] && v="ACCEPTED->relayed"
  printf "   %-42s outer=%-22s sport=%-6s -> accepted=%s dropped=%s  [%s]\n" "$label" "$src6" "$sport" "$acc" "$drp" "$v"
}
run "legit CE1 (assigned, correct port-set)"      "${PFX}::101" 5000
run "ATTACK valid-but-UNASSIGNED MAP addr (::103)" "${PFX}::103" 13000
run "ATTACK invalid MAP index (::150, X=0x50)"     "${PFX}::150" 5000
run "ATTACK spoof CE1 with WRONG port-set"         "${PFX}::101" 13000
echo "########## MAP-E DONE (egressed>0 = BR relayed it; =0 = dropped) ##########"
