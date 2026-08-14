#!/bin/bash
# MAP-E (RFC 7597) emulation, parallel to DS-Lite and lw4o6, Linux-native
# (ip6tnl + nftables), same software-build honesty bar as the DS-Lite AFTR.
#
# MAP-E vs lw4o6: the CE->IPv4+port-set mapping is ALGORITHMIC (derivable from
# the CE's IPv6), and the BR validates the decapsulated source against that
# algorithm rather than a provisioned table. There is NO per-CE provisioning
# roster and NO catch-all that accepts arbitrary inner packets: the BR accepts
# any source whose (source-derived port-set) contains the inner source port.
#
# MAP rule used here (simplified, security-relevant part):
#   CE IPv6 2001:db8:1a0e::10X  ->  shared 198.51.100.1, ports [X*4096 .. X*4096+4095]
#   valid MAP index X in 1..15 (X*4096 < 65536); X>=16 -> no valid port-set -> drop
set +e
PFX=2001:db8:1a0e
SHARED4=198.51.100.1
SRV4=203.0.113.9

echo "########## teardown ##########"
for ns in mapbr mapce1 mapce2 mapcl1 mapcl2 mapsrv mapatk; do ip netns del $ns 2>/dev/null; done
ip link del br-mape 2>/dev/null; sleep 0.3

echo "########## namespaces + MAP bridge ##########"
for ns in mapbr mapce1 mapce2 mapcl1 mapcl2 mapsrv mapatk; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
ip link add br-mape type bridge; ip link set br-mape up
echo 0 > /sys/class/net/br-mape/bridge/multicast_snooping 2>/dev/null
isp_attach(){ ns=$1; ip6=$2; mac=$3
  ip link add ${ns}-i type veth peer name ${ns}-b
  ip link set ${ns}-i netns $ns; ip link set ${ns}-b master br-mape; ip link set ${ns}-b up
  ip netns exec $ns ip link set ${ns}-i name eth-map address $mac; ip netns exec $ns ip link set eth-map up
  ip netns exec $ns ip -6 addr add ${ip6}/64 dev eth-map
  ip netns exec $ns sysctl -qw net.ipv6.conf.eth-map.accept_dad=0 net.ipv6.conf.eth-map.dad_transmits=0 net.ipv6.conf.all.forwarding=1
}
isp_attach mapbr  ${PFX}::10  02:00:0e:00:00:10
isp_attach mapce1 ${PFX}::101 02:00:0e:00:01:01
isp_attach mapce2 ${PFX}::102 02:00:0e:00:01:02
isp_attach mapatk ${PFX}::150 02:00:0e:00:01:50
sleep 1

echo "########## LAN + WAN + server ##########"
ip link add ml1-b type veth peer name ml1-c; ip link set ml1-b netns mapce1; ip link set ml1-c netns mapcl1
ip netns exec mapce1 ip link set ml1-b name eth-lan up; ip netns exec mapce1 ip addr add 10.0.1.1/24 dev eth-lan
ip netns exec mapcl1 ip link set ml1-c name eth0 up; ip netns exec mapcl1 ip addr add 10.0.1.50/24 dev eth0; ip netns exec mapcl1 ip route add default via 10.0.1.1
ip link add ml2-b type veth peer name ml2-c; ip link set ml2-b netns mapce2; ip link set ml2-c netns mapcl2
ip netns exec mapce2 ip link set ml2-b name eth-lan up; ip netns exec mapce2 ip addr add 10.0.2.1/24 dev eth-lan
ip netns exec mapcl2 ip link set ml2-c name eth0 up; ip netns exec mapcl2 ip addr add 10.0.2.50/24 dev eth0; ip netns exec mapcl2 ip route add default via 10.0.2.1
ip link add mw-a type veth peer name mw-s; ip link set mw-a netns mapbr; ip link set mw-s netns mapsrv
ip netns exec mapbr ip link set mw-a name eth-wan up; ip netns exec mapbr ip addr add 203.0.113.1/24 dev eth-wan
ip netns exec mapsrv ip link set mw-s name eth0 up; ip netns exec mapsrv ip addr add ${SRV4}/24 dev eth0; ip netns exec mapsrv ip route add default via 203.0.113.1

echo "########## softwires: CE encapsulators + BR CATCH-ALL (algorithmic, no roster) ##########"
ip netns exec mapce1 sh -c "ip -6 route add ${PFX}::10/128 dev eth-map; ip link add sw type ip6tnl local ${PFX}::101 remote ${PFX}::10 mode any encaplimit none; ip link set sw up; ip route add ${SRV4}/32 dev sw; ip route add ${SHARED4}/32 dev lo"
ip netns exec mapce2 sh -c "ip -6 route add ${PFX}::10/128 dev eth-map; ip link add sw type ip6tnl local ${PFX}::102 remote ${PFX}::10 mode any encaplimit none; ip link set sw up; ip route add ${SRV4}/32 dev sw; ip route add ${SHARED4}/32 dev lo"
# BR: catch-all decapsulator (accepts ANY MAP-domain source, then validates algorithmically).
ip netns exec mapbr sh -c "modprobe ip6_tunnel 2>/dev/null; ip link add mapbr0 type ip6tnl local ${PFX}::10 mode any encaplimit none; ip link set mapbr0 up; sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1"

echo "########## edge NAT at CE into ALGORITHMIC port-set (X*4096) ##########"
# CE1 X=1 -> 4096-8191 ; CE2 X=2 -> 8192-12287
ip netns exec mapce1 nft -f - <<'NFT'
flush ruleset
table ip nat { chain post { type nat hook postrouting priority srcnat; policy accept
  meta l4proto { tcp, udp } oif "sw" snat to 198.51.100.1:4096-8191
  oif "sw" snat to 198.51.100.1 } }
NFT
ip netns exec mapce2 nft -f - <<'NFT'
flush ruleset
table ip nat { chain post { type nat hook postrouting priority srcnat; policy accept
  meta l4proto { tcp, udp } oif "sw" snat to 198.51.100.1:8192-12287
  oif "sw" snat to 198.51.100.1 } }
NFT

echo "########## BR ALGORITHMIC validation (mark=outer-src low byte=X; inner sport in [X*4096..]) ##########"
# Stage 1: copy the outer IPv6 source's low byte (the MAP index X) into the mark before decap.
# Stage 2: after decap, accept only if inner sport is in that X's algorithmic port-set.
ip netns exec mapbr nft -f - <<'NFT'
flush ruleset
table ip6 mapmon {
  chain in { type filter hook prerouting priority raw; policy accept
    ip6 nexthdr 4 meta mark set @nh,184,8
    ip6 nexthdr 4 counter comment "all-4in6"
  }
}
table ip mapbr {
  chain val { type filter hook forward priority filter; policy accept
    # valid MAP CEs: mark X in 1..3 (assigned 1,2 ; 3 = valid-but-unassigned), port-set X*4096..X*4096+4095
    iifname "mapbr0" meta mark 1 ip saddr 198.51.100.1 meta l4proto {tcp,udp} th sport 4096-8191   accept
    iifname "mapbr0" meta mark 2 ip saddr 198.51.100.1 meta l4proto {tcp,udp} th sport 8192-12287  accept
    iifname "mapbr0" meta mark 3 ip saddr 198.51.100.1 meta l4proto {tcp,udp} th sport 12288-16383 accept
    iifname "mapbr0" meta l4proto {icmp} accept
    iifname "mapbr0" counter drop
  }
  chain ret { type filter hook prerouting priority mangle; policy accept
    iifname "eth-wan" ip daddr 198.51.100.1 th dport 4096-8191   meta mark set 1
    iifname "eth-wan" ip daddr 198.51.100.1 th dport 8192-12287  meta mark set 2
  }
}
NFT
ip netns exec mapbr sh -c "ip rule add fwmark 1 lookup 1; ip rule add fwmark 2 lookup 2; ip route add 198.51.100.1/32 dev mapbr0 table 1; ip route add 198.51.100.1/32 dev mapbr0 table 2; ip route add 198.51.100.1/32 dev mapbr0"

echo "########## server + baseline ##########"
cat > /tmp/mapsrv.py <<'PY'
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        try: self.request.recv(1024); self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nok")
        except Exception: pass
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address=True; request_queue_size=128; daemon_threads=True
S((\"203.0.113.9\",80),H).serve_forever()
PY
sed -i 's/\\"/"/g' /tmp/mapsrv.py
ip netns exec mapsrv pkill -f mapsrv.py 2>/dev/null; sleep 0.3
ip netns exec mapsrv setsid python3 /tmp/mapsrv.py </dev/null >/tmp/mapsrv.log 2>&1 &
sleep 1
ip netns exec mapce1 ping6 -c2 -W1 ${PFX}::10 >/dev/null 2>&1; ip netns exec mapce2 ping6 -c2 -W1 ${PFX}::10 >/dev/null 2>&1
ip netns exec mapbr ping6 -c1 -W1 ${PFX}::101 >/dev/null 2>&1; ip netns exec mapbr ping6 -c1 -W1 ${PFX}::102 >/dev/null 2>&1; sleep 0.5
echo "-- mapcl1 -> server (edge NAT to 4096-8191, algorithmic-validated at BR):"
ip netns exec mapcl1 timeout 6 curl -s -o /dev/null -w "   HTTP=%{http_code}\n" http://203.0.113.9/ 2>&1 || echo "   curl-fail"
echo "-- BR drop counter pre-attack (expect 0):"
ip netns exec mapbr nft list chain ip mapbr val 2>/dev/null | grep "counter.*drop" | sed 's/^/   /'
echo "########## MAP-E SETUP DONE ##########"
