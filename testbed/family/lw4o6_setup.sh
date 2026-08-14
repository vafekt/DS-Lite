#!/bin/bash
# Lightweight 4over6 (RFC 7596) emulation, parallel to the DS-Lite testbed.
# Purpose: reproduce T1 (flood), T11 (unprovisioned relay), T12 (identity
# forgery) against a CONFORMANT lw4o6 stack, to show the RFC 7596 §5.1
# binding (which DS-Lite omits) blocks T11/T12 by design.
#
# lw4o6 vs DS-Lite differences realized here:
#   - NAT is at the EDGE lwB4, into an ASSIGNED port-set on a shared IPv4.
#   - lwAFTR has a BINDING per provisioned lwB4 (point-to-point softwire,
#     NO catch-all tunnel) and validates the inner source addr+port.
# Fresh "lw*" namespaces + a separate bridge; does NOT touch DS-Lite state.
set +e
PFX=2001:db8:1a06
SHARED4=198.51.100.1
SRV4=203.0.113.9

echo "########## STAGE 1: teardown any prior lw run ##########"
for ns in lwaftr lwb41 lwb42 lwcl1 lwcl2 lwsrv lwatk; do ip netns del $ns 2>/dev/null; done
ip link del br-lwisp 2>/dev/null
sleep 0.3

echo "########## STAGE 2: namespaces + ISP bridge ##########"
for ns in lwaftr lwb41 lwb42 lwcl1 lwcl2 lwsrv lwatk; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
ip link add br-lwisp type bridge; ip link set br-lwisp up
echo 0 > /sys/class/net/br-lwisp/bridge/multicast_snooping 2>/dev/null

# helper: attach a netns to the ISP bridge with a given IPv6
isp_attach(){ ns=$1; ip6=$2; mac=$3
  ip link add ${ns}-i type veth peer name ${ns}-b
  ip link set ${ns}-i netns $ns; ip link set ${ns}-b master br-lwisp; ip link set ${ns}-b up
  ip netns exec $ns ip link set ${ns}-i name eth-isp address $mac
  ip netns exec $ns ip link set eth-isp up
  ip netns exec $ns ip -6 addr add ${ip6}/64 dev eth-isp
}
isp_attach lwaftr ${PFX}::10  02:00:00:00:00:10
isp_attach lwb41  ${PFX}::101 02:00:00:00:01:01
isp_attach lwb42  ${PFX}::102 02:00:00:00:01:02
isp_attach lwatk  ${PFX}::150 02:00:00:00:01:50
# disable DAD for determinism
for ns in lwaftr lwb41 lwb42 lwatk; do ip netns exec $ns sysctl -qw net.ipv6.conf.eth-isp.accept_dad=0 net.ipv6.conf.eth-isp.dad_transmits=0; done
sleep 1

echo "########## STAGE 3: LAN links (client behind each lwB4) + WAN + server ##########"
# lwb41 <-> lwcl1
ip link add lan1-b type veth peer name lan1-c
ip link set lan1-b netns lwb41; ip link set lan1-c netns lwcl1
ip netns exec lwb41 ip link set lan1-b name eth-lan up; ip netns exec lwb41 ip addr add 10.0.1.1/24 dev eth-lan
ip netns exec lwcl1 ip link set lan1-c name eth0 up;    ip netns exec lwcl1 ip addr add 10.0.1.50/24 dev eth0
ip netns exec lwcl1 ip route add default via 10.0.1.1
# lwb42 <-> lwcl2
ip link add lan2-b type veth peer name lan2-c
ip link set lan2-b netns lwb42; ip link set lan2-c netns lwcl2
ip netns exec lwb42 ip link set lan2-b name eth-lan up; ip netns exec lwb42 ip addr add 10.0.2.1/24 dev eth-lan
ip netns exec lwcl2 ip link set lan2-c name eth0 up;    ip netns exec lwcl2 ip addr add 10.0.2.50/24 dev eth0
ip netns exec lwcl2 ip route add default via 10.0.2.1
# lwaftr <-> lwsrv (WAN)
ip link add wan-a type veth peer name wan-s
ip link set wan-a netns lwaftr; ip link set wan-s netns lwsrv
ip netns exec lwaftr ip link set wan-a name eth-wan up; ip netns exec lwaftr ip addr add 203.0.113.1/24 dev eth-wan
ip netns exec lwsrv  ip link set wan-s name eth0 up;    ip netns exec lwsrv  ip addr add ${SRV4}/24 dev eth0
ip netns exec lwsrv  ip route add default via 203.0.113.1

echo "########## STAGE 4: softwires (ip6tnl) — per-binding, NO catch-all ##########"
# lwB4-1 encapsulator
ip netns exec lwb41 sh -c "modprobe ip6_tunnel 2>/dev/null; ip -6 route add ${PFX}::10/128 dev eth-isp;
  ip link add sw type ip6tnl local ${PFX}::101 remote ${PFX}::10 mode any encaplimit none; ip link set sw up;
  ip route add ${SRV4}/32 dev sw; ip route add ${SHARED4}/32 dev lo"
ip netns exec lwb42 sh -c "ip -6 route add ${PFX}::10/128 dev eth-isp;
  ip link add sw type ip6tnl local ${PFX}::102 remote ${PFX}::10 mode any encaplimit none; ip link set sw up;
  ip route add ${SRV4}/32 dev sw; ip route add ${SHARED4}/32 dev lo"
# lwAFTR: ONE point-to-point tunnel PER PROVISIONED lwB4 (the binding); NO catch-all remote-any tunnel
ip netns exec lwaftr sh -c "modprobe ip6_tunnel 2>/dev/null;
  ip -6 route add ${PFX}::101/128 dev eth-isp; ip -6 route add ${PFX}::102/128 dev eth-isp;
  ip link add tnl-b41 type ip6tnl local ${PFX}::10 remote ${PFX}::101 mode any encaplimit none; ip link set tnl-b41 up;
  ip link add tnl-b42 type ip6tnl local ${PFX}::10 remote ${PFX}::102 mode any encaplimit none; ip link set tnl-b42 up"

echo "########## STAGE 5: EDGE NAT at lwB4 into assigned port-set (lw4o6 A+P) ##########"
ip netns exec lwb41 sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
ip netns exec lwb42 sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
# lwB4-1 -> shared 198.51.100.1 : 1024-2047 ; lwB4-2 -> 2048-3071
ip netns exec lwb41 nft -f - <<'NFT'
flush ruleset
table ip nat {
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    meta l4proto { tcp, udp } oif "sw" snat to 198.51.100.1:1024-2047
    oif "sw" snat to 198.51.100.1
  }
}
NFT
ip netns exec lwb42 nft -f - <<'NFT'
flush ruleset
table ip nat {
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    meta l4proto { tcp, udp } oif "sw" snat to 198.51.100.1:2048-3071
    oif "sw" snat to 198.51.100.1
  }
}
NFT

echo "########## STAGE 6: lwAFTR BINDING VALIDATION (RFC 7596 §5.1) + fwd + port-set return ##########"
# Forward: each tunnel already enforces its remote (outer src). Additionally
# validate inner source addr+port against that lwB4's binding; drop mismatch.
# Return: map shared IPv4 dport -> the owning lwB4's tunnel by port-set.
ip netns exec lwaftr sh -c 'sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1'
ip netns exec lwaftr nft -f - <<'NFT'
flush ruleset
# IPv6 ingress monitor: reliably count 4in6 packets ARRIVING at the lwAFTR
# (outer IPv6, nexthdr=4), before any decap, per attacker source. Proves the
# attack reached the concentrator even when it is dropped for lack of a binding.
table ip6 lwmon {
  chain ingress { type filter hook prerouting priority raw; policy accept;
    ip6 nexthdr 4 counter comment "all-4in6-in"
    ip6 saddr 2001:db8:1a06::150 ip6 nexthdr 4 counter comment "t11-unprov-in"
    ip6 saddr 2001:db8:1a06::200-2001:db8:1a06::231 ip6 nexthdr 4 counter comment "t12-forged-in"
  }
}
table ip lwaftr {
  chain fwdval { type filter hook forward priority filter; policy accept;
    # inner-source binding: packets arriving on tnl-b41 MUST have src 198.51.100.1 sport 1024-2047
    iifname "tnl-b41" ip saddr 198.51.100.1 meta l4proto {tcp,udp} th sport 1024-2047 accept
    iifname "tnl-b41" ip saddr 198.51.100.1 meta l4proto {icmp} accept
    iifname "tnl-b41" counter drop
    iifname "tnl-b42" ip saddr 198.51.100.1 meta l4proto {tcp,udp} th sport 2048-3071 accept
    iifname "tnl-b42" ip saddr 198.51.100.1 meta l4proto {icmp} accept
    iifname "tnl-b42" counter drop
  }
  # Return path: choose tunnel by dst port-set
  chain retmark { type filter hook prerouting priority mangle; policy accept;
    iifname "eth-wan" ip daddr 198.51.100.1 th dport 1024-2047 meta mark set 41
    iifname "eth-wan" ip daddr 198.51.100.1 th dport 2048-3071 meta mark set 42
  }
}
NFT
ip netns exec lwaftr sh -c '
  ip rule add fwmark 41 lookup 41; ip rule add fwmark 42 lookup 42;
  ip route add 198.51.100.1/32 dev tnl-b41 table 41;
  ip route add 198.51.100.1/32 dev tnl-b42 table 42;
  ip route add 198.51.100.1/32 dev tnl-b41'   # default owner for unmarked (baseline)

echo "########## STAGE 7: server listeners (robust, threaded, detached) ##########"
cat > /tmp/lwsrv.py <<'PY'
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(1024)
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nok")
        except Exception:
            pass
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    request_queue_size = 128
    daemon_threads = True
S(("203.0.113.9", 80), H).serve_forever()
PY
ip netns exec lwsrv pkill -f lwsrv.py 2>/dev/null; sleep 0.3
ip netns exec lwsrv setsid python3 /tmp/lwsrv.py </dev/null >/tmp/lwsrv.log 2>&1 &
sleep 1

echo "########## STAGE 8: NDP warmup + BASELINE connectivity through lw4o6 ##########"
# warm NDP between each lwB4 and the lwAFTR so the outer IPv6 next-hop resolves
ip netns exec lwb41 ping6 -c2 -W1 ${PFX}::10 >/dev/null 2>&1
ip netns exec lwb42 ping6 -c2 -W1 ${PFX}::10 >/dev/null 2>&1
ip netns exec lwaftr ping6 -c1 -W1 ${PFX}::101 >/dev/null 2>&1
ip netns exec lwaftr ping6 -c1 -W1 ${PFX}::102 >/dev/null 2>&1
sleep 0.5
echo "-- tunnel ifaces up? lwb41:"; ip netns exec lwb41 ip -br link show sw 2>/dev/null | sed 's/^/   /'
echo "-- lwcl1 ping server (through full lw4o6 path):"
ip netns exec lwcl1 ping -c2 -W2 203.0.113.9 >/dev/null 2>&1 && echo "   PING ok" || echo "   PING fail"
echo "-- lwcl1 -> server HTTP (NAT to :1024-2047, validated at lwAFTR):"
ip netns exec lwcl1 timeout 6 curl -s -o /dev/null -w "   HTTP=%{http_code}\n" http://203.0.113.9/ 2>&1 || echo "   curl-fail"
echo "-- conntrack at lwb41 (shows edge SNAT into port-set):"
ip netns exec lwb41 conntrack -L 2>/dev/null | grep -o "sport=[0-9]*.*dport=80" | head -2 | sed 's/^/   /' || echo "   (conntrack tool n/a)"
echo "-- binding drop counters (should be 0 pre-attack):"
ip netns exec lwaftr nft list chain ip lwaftr fwdval 2>/dev/null | grep -E "drop" | sed 's/^/   /'
echo "########## STAGE 1-8 DONE ##########"
