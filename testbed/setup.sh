#!/bin/bash
# DS-Lite Testbed Setup (RFC 6333 / RFC 6334)
#
# Topology:
#
#                     IPv6-only ISP Network         OAM / Management
#                     (br-isp, 2001:db8:cafe::/64)  (br-mgmt, 10.99.0.0/24)
#           ┌──────────┬──────────┬──────────┐     ┌────────┬─────────┐
#      DHCPv6-Server  B4-1      B4-2       AFTR    Mgmt    AFTR
#           eth-isp   eth-isp   eth-isp   eth-isp  eth-mgmt eth-mgmt
#                       |         |          eth-wan          (10.99.0.10) (10.99.0.1)
#                     eth-lan   eth-lan          |
#                       |         |          192.0.2.0/24
#                    Client1   Client2          |
#                  10.0.1.0/24  10.0.2.0/24    Server-Router
#                                              eth-aftr  eth-srv
#                                                         |
#                                                   198.51.100.0/24
#                                                         |
#                                                       Server
#
# RFC 5706 §3.1 — management plane (SNMP / syslog) lives on a dedicated
# OAM network (br-mgmt) reachable only from the mgmt netns.  AFTR's SNMP
# agent binds to 10.99.0.1:161 (not the data-plane interfaces); nftables
# rules drop UDP/161 arriving on eth-wan and eth-isp.
#
# Each B4 is a DS-Lite CPE with:
#   - An IPv4-only LAN interface to its client
#   - An IPv6-only ISP interface (SLAAC + DHCPv6)
#   - A DNS proxy (RFC 5625) for its IPv4 client
#   - A DS-Lite tunnel (IPv4-in-IPv6 via ip6tnl) to the AFTR
#
# AFTR performs NAT44/CGNAT on the IPv4 WAN side.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PCAP_DIR="${PCAP_DIR:-$SCRIPT_DIR/pcaps}"
mkdir -p "$PCAP_DIR"

# Note: PCP server and proxy use SO_RCVBUFFORCE in-process to raise their UDP
# receive buffers past net.core.rmem_max — that sysctl cannot be changed from
# a Linux container even with --privileged, so we cannot tune it here.

########################################################################
# 1. Namespaces
########################################################################
echo "=== Cleaning up previous lab state (if any) ==="
# Privileged containers share the host's netns mount table, so stale
# namespaces, bridges, and veth pairs can survive container restarts.
/testbed/teardown.sh 2>/dev/null || true
# Final sweep for stale nsfs mounts that teardown.sh couldn't remove
for ns in dhcpv6server dns-server b4-1 b4-2 aftr client1 client2 server-router server attacker mgmt; do
    if [ -e "/run/netns/$ns" ]; then
        umount "/run/netns/$ns" 2>/dev/null || true
        rm -f "/run/netns/$ns"
    fi
done

echo "=== Creating network namespaces ==="
for ns in dhcpv6server dns-server b4-1 b4-2 aftr client1 client2 server-router server mgmt; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
done

########################################################################
# 2. IPv6-only ISP bridge (shared L2: DHCPv6-Server, B4-1, B4-2, AFTR)
########################################################################
echo "=== Creating IPv6-only ISP bridge ==="
ip link del br-isp 2>/dev/null || true
ip link add br-isp type bridge
# ISP-side IPv6 link MTU. Default 1500 (the operational reality on most
# residential broadband access networks); set ISP_MTU=1540 to enable the
# RFC 6333 §5.3 recommended path that avoids fragmentation of the
# 1500-byte inner IPv4 packets (= 1540 bytes outer).
ip link set br-isp mtu "${ISP_MTU:-1500}"
ip link set br-isp up
# Disable multicast snooping so that DHCPv6 multicast/link-local
# packets are forwarded to all bridge ports (needed for T16 testing).
echo 0 > /sys/class/net/br-isp/bridge/multicast_snooping

# DHCPv6-Server <-> ISP bridge
ip link add eth-isp-dhcp6s type veth peer name dhcp6s-br
ip link set eth-isp-dhcp6s mtu "${ISP_MTU:-1500}" && ip link set dhcp6s-br mtu "${ISP_MTU:-1500}"
ip link set eth-isp-dhcp6s netns dhcpv6server
ip netns exec dhcpv6server ip link set eth-isp-dhcp6s name eth-isp
ip link set dhcp6s-br master br-isp
ip link set dhcp6s-br up

# DNS-Server <-> ISP bridge  (split out of dhcpv6server so that DNS
# queries from ANY netns — including dhcpv6server itself — traverse
# the ISP bridge and are visible in Wireshark)
ip link add eth-isp-dns type veth peer name dns-br
ip link set eth-isp-dns mtu "${ISP_MTU:-1500}" && ip link set dns-br mtu "${ISP_MTU:-1500}"
ip link set eth-isp-dns netns dns-server
ip netns exec dns-server ip link set eth-isp-dns name eth-isp
ip link set dns-br master br-isp
ip link set dns-br up

# B4-1 <-> ISP bridge
ip link add eth-isp-b41 type veth peer name b41-br
ip link set eth-isp-b41 mtu "${ISP_MTU:-1500}" && ip link set b41-br mtu "${ISP_MTU:-1500}"
ip link set eth-isp-b41 netns b4-1
ip netns exec b4-1 ip link set eth-isp-b41 name eth-isp
ip link set b41-br master br-isp
ip link set b41-br up
# Subscriber-to-subscriber L2 isolation (private/"protected" port). Real
# DS-Lite access networks isolate subscribers at L2 (per-subscriber VLAN,
# split-horizon on the DSLAM/OLT/BNG): a subscriber behind one B4 cannot see
# another B4's softwire traffic. `isolated on` blocks this B4 port from
# exchanging or being flooded frames with the OTHER isolated B4 port, while
# still reaching the non-isolated infrastructure ports (AFTR, DNS, DHCPv6)
# and the ISP-aggregation attacker port (left non-isolated so T6/T18 model a
# realistic P3 on-path vantage). This makes the cross-subscriber threat model
# honest: T21's PEER+THIRD_PARTY enumeration must work via the AFTR control
# plane, not by sniffing the victim's plaintext softwire. Toggle off to model
# a flat/hub access segment.
bridge link set dev b41-br isolated on

# B4-2 <-> ISP bridge
ip link add eth-isp-b42 type veth peer name b42-br
ip link set eth-isp-b42 mtu "${ISP_MTU:-1500}" && ip link set b42-br mtu "${ISP_MTU:-1500}"
ip link set eth-isp-b42 netns b4-2
ip netns exec b4-2 ip link set eth-isp-b42 name eth-isp
ip link set b42-br master br-isp
ip link set b42-br up
bridge link set dev b42-br isolated on   # subscriber L2 isolation (see b41-br note)

# AFTR <-> ISP bridge
ip link add eth-isp-aftr type veth peer name aftr-br
ip link set eth-isp-aftr mtu "${ISP_MTU:-1500}" && ip link set aftr-br mtu "${ISP_MTU:-1500}"
ip link set eth-isp-aftr netns aftr
ip netns exec aftr ip link set eth-isp-aftr name eth-isp
ip link set aftr-br master br-isp
ip link set aftr-br up

########################################################################
# 3. Other links (LANs, WAN, server network)
########################################################################
echo "=== Creating LAN, WAN, and server links ==="
# B4-1 <-> Client1 (IPv4 LAN)
ip link add eth-lan-b41 type veth peer name eth0-cl1
ip link set eth-lan-b41 netns b4-1
ip netns exec b4-1 ip link set eth-lan-b41 name eth-lan
ip link set eth0-cl1 netns client1
ip netns exec client1 ip link set eth0-cl1 name eth0

# B4-2 <-> Client2 (IPv4 LAN)
ip link add eth-lan-b42 type veth peer name eth0-cl2
ip link set eth-lan-b42 netns b4-2
ip netns exec b4-2 ip link set eth-lan-b42 name eth-lan
ip link set eth0-cl2 netns client2
ip netns exec client2 ip link set eth0-cl2 name eth0

# AFTR <-> Server-Router (IPv4 WAN)
ip link add eth-wan-aftr type veth peer name eth-aftr-sr
ip link set eth-wan-aftr netns aftr
ip netns exec aftr ip link set eth-wan-aftr name eth-wan
ip link set eth-aftr-sr netns server-router
ip netns exec server-router ip link set eth-aftr-sr name eth-aftr

# Server-Router <-> Server
ip link add eth-srv-sr type veth peer name eth0-srv
ip link set eth-srv-sr netns server-router
ip netns exec server-router ip link set eth-srv-sr name eth-srv
ip link set eth0-srv netns server
ip netns exec server ip link set eth0-srv name eth0

########################################################################
# 3b. OAM / Management network (RFC 5706 §3.1)
#     br-mgmt connects the AFTR's management interface (eth-mgmt) to a
#     dedicated mgmt host.  No subscriber, ISP-side, or Internet-side
#     attacker can reach this segment — it models the out-of-band
#     management VLAN used by real CGN/AFTR operators.
########################################################################
echo "=== Creating OAM management bridge ==="
ip link del br-mgmt 2>/dev/null || true
ip link add br-mgmt type bridge
ip link set br-mgmt up
echo 0 > /sys/class/net/br-mgmt/bridge/multicast_snooping

# AFTR <-> br-mgmt  (management interface)
ip link add eth-mgmt-aftr type veth peer name aftr-mgmt-br
ip link set eth-mgmt-aftr netns aftr
ip netns exec aftr ip link set eth-mgmt-aftr name eth-mgmt
ip link set aftr-mgmt-br master br-mgmt
ip link set aftr-mgmt-br up

# Mgmt station <-> br-mgmt
ip link add eth-mgmt-stn type veth peer name mgmt-stn-br
ip link set eth-mgmt-stn netns mgmt
ip netns exec mgmt ip link set eth-mgmt-stn name eth-mgmt
ip link set mgmt-stn-br master br-mgmt
ip link set mgmt-stn-br up

########################################################################
# 4. IP addressing
########################################################################
echo "=== Configuring IP addresses ==="

# --- DHCPv6 Server (static IPv6 on ISP) ---
ip netns exec dhcpv6server ip -6 addr add 2001:db8:cafe::1/64 dev eth-isp
ip netns exec dhcpv6server ip link set eth-isp up

# --- DNS Server (static IPv6 on ISP) — provides the AFTR-FQDN A/AAAA records ---
ip netns exec dns-server ip -6 addr add 2001:db8:cafe::2/64 dev eth-isp
ip netns exec dns-server ip link set eth-isp up

# --- AFTR (static IPv6 on ISP; IPv4 on WAN; OAM on mgmt) ---
ip netns exec aftr ip -6 addr add 2001:db8:cafe::10/64 dev eth-isp
ip netns exec aftr ip link set eth-isp up
ip netns exec aftr ip addr add 192.0.2.1/24 dev eth-wan
ip netns exec aftr ip link set eth-wan up
# RFC 5706 §3.1 management plane: dedicated OAM interface
ip netns exec aftr ip addr add 10.99.0.1/24 dev eth-mgmt
ip netns exec aftr ip link set eth-mgmt up

# --- Mgmt station (RFC 5706 OAM host) ---
ip netns exec mgmt ip addr add 10.99.0.10/24 dev eth-mgmt
ip netns exec mgmt ip link set eth-mgmt up

# --- B4-1 (SLAAC on ISP; IPv4 gateway on LAN) ---
ip netns exec b4-1 ip link set eth-isp up
ip netns exec b4-1 ip addr add 10.0.1.1/24 dev eth-lan
ip netns exec b4-1 ip link set eth-lan up

# --- B4-2 (SLAAC on ISP; IPv4 gateway on LAN) ---
ip netns exec b4-2 ip link set eth-isp up
ip netns exec b4-2 ip addr add 10.0.2.1/24 dev eth-lan
ip netns exec b4-2 ip link set eth-lan up

# --- Client1 (IPv4 only) ---
ip netns exec client1 ip addr add 10.0.1.100/24 dev eth0
ip netns exec client1 ip link set eth0 up
ip netns exec client1 ip route add default via 10.0.1.1
mkdir -p /etc/netns/client1
echo "nameserver 10.0.1.1" > /etc/netns/client1/resolv.conf

# --- Client2 (IPv4 only) ---
ip netns exec client2 ip addr add 10.0.2.100/24 dev eth0
ip netns exec client2 ip link set eth0 up
ip netns exec client2 ip route add default via 10.0.2.1
mkdir -p /etc/netns/client2
echo "nameserver 10.0.2.1" > /etc/netns/client2/resolv.conf

# --- Server-Router ---
ip netns exec server-router ip addr add 192.0.2.100/24 dev eth-aftr
ip netns exec server-router ip link set eth-aftr up
ip netns exec server-router ip addr add 198.51.100.1/24 dev eth-srv
ip netns exec server-router ip link set eth-srv up

# --- Server ---
ip netns exec server ip addr add 198.51.100.2/24 dev eth0
ip netns exec server ip link set eth0 up
ip netns exec server ip route add default via 198.51.100.1

########################################################################
# 5. Routing & forwarding
########################################################################
echo "=== Enabling forwarding and routes ==="
ip netns exec b4-1 sysctl -qw net.ipv4.ip_forward=1
ip netns exec b4-1 sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec b4-1 sysctl -qw net.ipv6.conf.eth-isp.accept_ra=2

ip netns exec b4-2 sysctl -qw net.ipv4.ip_forward=1
ip netns exec b4-2 sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec b4-2 sysctl -qw net.ipv6.conf.eth-isp.accept_ra=2

ip netns exec aftr sysctl -qw net.ipv4.ip_forward=1
ip netns exec aftr sysctl -qw net.ipv6.conf.all.forwarding=1
# RFC 2827 (BCP 38) / RFC 7039: ingress filtering of source addresses.
# Linux strict-mode RPF (rp_filter=1) requires the reverse route to match
# the inbound interface; loose mode (=2) only requires the source to be
# routable via *any* interface.
#
# DEFAULT (vulnerable) MODE: ingress filtering is DISABLED (rp_filter=0).
# This matches the paper's threat model, which explicitly assumes the AFTR
# deploys neither SAVI (RFC 7039) nor source-address uRPF on the softwire
# side. Strict mode silently drops every spoofed-inner-source packet that
# is decapsulated on the wildcard softwire (ds-lite-open): such sources
# reverse-route via the per-B4 tunnels or are unrouteable, so the reverse
# path never matches the wildcard inbound interface. That would defeat the
# spoofed-source NAT-exhaustion attacks (T1-ISP, T5) whose whole premise
# is the absence of ingress filtering. Legitimate subscriber traffic
# (10.0.1.0/24, 10.0.2.0/24) reverse-routes via its own softwire and is
# unaffected by the rp_filter setting either way.
#
# uRPF is a togglable DEFENSE: the hardened configuration re-enables it
# with `sysctl net.ipv4.conf.all.rp_filter=1` on the AFTR.
ip netns exec aftr sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec aftr sysctl -qw net.ipv4.conf.default.rp_filter=0
ip netns exec aftr ip route add 198.51.100.0/24 via 192.0.2.100

ip netns exec server-router sysctl -qw net.ipv4.ip_forward=1
ip netns exec server-router ip route add default via 192.0.2.1

########################################################################
# 6. Packet captures (start before services)
########################################################################
echo "=== Starting packet captures ==="
tcpdump -U -Z root -i br-isp  -w "$PCAP_DIR/isp-network.pcap" 2>/dev/null &
tcpdump -U -Z root -i br-mgmt -w "$PCAP_DIR/mgmt-network.pcap" 2>/dev/null &

ip netns exec dhcpv6server \
    tcpdump -U -Z root -i eth-isp -w "$PCAP_DIR/dhcpv6-server-isp.pcap" 2>/dev/null &

ip netns exec dns-server \
    tcpdump -U -Z root -i eth-isp -w "$PCAP_DIR/dns-server-isp.pcap" 2>/dev/null &

ip netns exec b4-1 \
    tcpdump -U -Z root -i eth-isp -w "$PCAP_DIR/b4-1-isp.pcap" 2>/dev/null &
ip netns exec b4-1 \
    tcpdump -U -Z root -i eth-lan -w "$PCAP_DIR/b4-1-lan.pcap" 2>/dev/null &

ip netns exec b4-2 \
    tcpdump -U -Z root -i eth-isp -w "$PCAP_DIR/b4-2-isp.pcap" 2>/dev/null &
ip netns exec b4-2 \
    tcpdump -U -Z root -i eth-lan -w "$PCAP_DIR/b4-2-lan.pcap" 2>/dev/null &

ip netns exec aftr \
    tcpdump -U -Z root -i eth-isp -w "$PCAP_DIR/aftr-isp.pcap" 2>/dev/null &
ip netns exec aftr \
    tcpdump -U -Z root -i eth-wan  -w "$PCAP_DIR/aftr-wan.pcap" 2>/dev/null &

ip netns exec server-router \
    tcpdump -U -Z root -i eth-aftr -w "$PCAP_DIR/server-router-aftr.pcap" 2>/dev/null &
ip netns exec server-router \
    tcpdump -U -Z root -i eth-srv  -w "$PCAP_DIR/server-router-srv.pcap" 2>/dev/null &

ip netns exec server \
    tcpdump -U -Z root -i eth0 -w "$PCAP_DIR/server.pcap" 2>/dev/null &

sleep 1

########################################################################
# 7. DHCPv6 server services: radvd + dhcpd6 + DNS
########################################################################
echo "=== Starting DHCPv6 server (radvd + dhcpd6) ==="
mkdir -p /var/lib/dhcp /etc/dhcp /var/run/radvd
touch /var/lib/dhcp/dhcpd6.leases

ip netns exec dhcpv6server \
    radvd -C "$SCRIPT_DIR/dhcpv6server/radvd.conf" \
          -p /var/run/radvd/radvd.pid -n -m stderr 2>/dev/null &
sleep 1

cp "$SCRIPT_DIR/dhcpv6server/dhcpd6.conf" /etc/dhcp/dhcpd6.conf
ip netns exec dhcpv6server \
    /usr/sbin/dhcpd -6 -cf /etc/dhcp/dhcpd6.conf \
    -lf /var/lib/dhcp/dhcpd6.leases -pf /var/run/dhcpd6.pid eth-isp >/dev/null 2>&1

echo "  radvd, dhcpd6 running in DHCPv6-Server namespace"

echo "=== Starting DNS server (separate netns, 2001:db8:cafe::2) ==="
# DNS lives in its own netns so a `dig` from ANY netns (including the
# DHCPv6 server's own shell) traverses the ISP bridge and is visible
# in Wireshark. Without this split, the DHCPv6-Server's local dnsmasq
# and the local resolv.conf would both terminate inside the same netns
# and the kernel would short-circuit the query to lo.
ip netns exec dns-server \
    dnsmasq -C "$SCRIPT_DIR/dhcpv6server/dnsmasq.conf" \
            --listen-address=2001:db8:cafe::2 \
            --bind-interfaces \
            --pid-file=/var/run/dnsmasq-dns-server.pid

echo "  dnsmasq running in DNS-Server namespace at 2001:db8:cafe::2"

# So a `dig` typed in the DHCPv6-Server terminal traverses the wire too.
mkdir -p /etc/netns/dhcpv6server
echo "nameserver 2001:db8:cafe::2" > /etc/netns/dhcpv6server/resolv.conf

########################################################################
# 8. B4-1: DHCPv6 client (option 64) + DNS proxy
########################################################################
echo "=== B4-1: Starting DHCPv6 client ==="
sleep 5
B4_1_SLAAC=$(ip netns exec b4-1 ip -6 addr show dev eth-isp scope global \
    | awk '/inet6/ && !/fe80/ {split($2,a,"/"); print a[1]; exit}')
if [ -n "$B4_1_SLAAC" ]; then
    echo "  B4-1 received SLAAC address: $B4_1_SLAAC"
else
    echo "  B4-1 no SLAAC – assigning static fallback"
    ip netns exec b4-1 ip -6 addr add 2001:db8:cafe::b41/64 dev eth-isp
    B4_1_SLAAC="2001:db8:cafe::b41"
fi
# DHCPv6 IA_NA installs the IPv6 address as /128 (host route only). Ensure
# the on-link ISP /64 prefix is reachable so the ip6tnl encapsulator can
# resolve the AFTR address. Idempotent.
ip netns exec b4-1 ip -6 route replace 2001:db8:cafe::/64 dev eth-isp 2>/dev/null || true

mkdir -p /etc/dhcp/dhclient-exit-hooks.d
cp "$SCRIPT_DIR/b4/dhclient6-exit-hook.sh" /etc/dhcp/dhclient-exit-hooks.d/ds-lite
chmod +x /etc/dhcp/dhclient-exit-hooks.d/ds-lite
cp "$SCRIPT_DIR/b4/dhclient6.conf" /etc/dhcp/dhclient6-b4-1.conf
rm -f /var/run/ds-lite-aftr-name
ip netns exec b4-1 \
    dhclient -6 -1 -nw -cf /etc/dhcp/dhclient6-b4-1.conf \
    -lf /var/lib/dhcp/dhclient6-b4-1.leases \
    -pf /var/run/dhclient6-b4-1.pid \
    eth-isp 2>/dev/null || true
sleep 3

B4_1_AFTR_FQDN=""
if [ -f /var/run/ds-lite-aftr-name ]; then
    B4_1_AFTR_FQDN=$(cat /var/run/ds-lite-aftr-name | tr -d '[:space:]')
    echo "  B4-1 received AFTR FQDN via DHCPv6 option 64: $B4_1_AFTR_FQDN"
fi
[ -z "$B4_1_AFTR_FQDN" ] && B4_1_AFTR_FQDN="aftr.dslite.example.com" \
    && echo "  B4-1 option 64 not received – using default: $B4_1_AFTR_FQDN"

echo "  B4-1: Resolving AFTR FQDN ($B4_1_AFTR_FQDN)"
AFTR_IPV6=$(ip netns exec b4-1 host -t AAAA "$B4_1_AFTR_FQDN" 2001:db8:cafe::2 2>/dev/null \
    | awk '/has IPv6 address/ {print $NF; exit}') || true
[ -z "$AFTR_IPV6" ] && AFTR_IPV6="2001:db8:cafe::10"
echo "  AFTR IPv6 address: $AFTR_IPV6"

# Anchor the tunnel local IPv6 to a permanent static address so
# the ds-lite ip6tnl does not break when the DHCPv6 IA_NA lease
# expires during long corpus runs. The DHCPv6 client still runs
# above for the AFTR-Name option (RFC 6334); only the address
# used as the tunnel local endpoint is forced to be permanent.
ip netns exec b4-1 ip -6 addr add 2001:db8:cafe::b41/64 dev eth-isp \
    valid_lft forever preferred_lft forever 2>/dev/null || true
B4_1_IPV6="2001:db8:cafe::b41"

echo "  B4-1: Starting DNS proxy (RFC 5625)"
ip netns exec b4-1 dnsmasq \
    --interface=eth-lan --except-interface=lo --bind-interfaces --no-resolv \
    --server=2001:db8:cafe::2 \
    --no-dhcp-interface=eth-lan \
    --address=/client1.dslite.example.com/10.0.1.100 \
    --proxy-dnssec \
    --log-queries --log-facility=/var/log/dnsmasq.log \
    --pid-file=/var/run/dnsmasq-b4-1.pid

########################################################################
# 9. B4-2: DHCPv6 client (option 64) + DNS proxy
########################################################################
echo "=== B4-2: Starting DHCPv6 client ==="
B4_2_SLAAC=$(ip netns exec b4-2 ip -6 addr show dev eth-isp scope global \
    | awk '/inet6/ && !/fe80/ {split($2,a,"/"); print a[1]; exit}')
if [ -n "$B4_2_SLAAC" ]; then
    echo "  B4-2 received SLAAC address: $B4_2_SLAAC"
else
    echo "  B4-2 no SLAAC – assigning static fallback"
    ip netns exec b4-2 ip -6 addr add 2001:db8:cafe::b42/64 dev eth-isp
    B4_2_SLAAC="2001:db8:cafe::b42"
fi
ip netns exec b4-2 ip -6 route replace 2001:db8:cafe::/64 dev eth-isp 2>/dev/null || true

cp "$SCRIPT_DIR/b4/dhclient6.conf" /etc/dhcp/dhclient6-b4-2.conf
rm -f /var/run/ds-lite-aftr-name
ip netns exec b4-2 \
    dhclient -6 -1 -nw -cf /etc/dhcp/dhclient6-b4-2.conf \
    -lf /var/lib/dhcp/dhclient6-b4-2.leases \
    -pf /var/run/dhclient6-b4-2.pid \
    eth-isp 2>/dev/null || true
sleep 3

B4_2_AFTR_FQDN=""
if [ -f /var/run/ds-lite-aftr-name ]; then
    B4_2_AFTR_FQDN=$(cat /var/run/ds-lite-aftr-name | tr -d '[:space:]')
    echo "  B4-2 received AFTR FQDN via DHCPv6 option 64: $B4_2_AFTR_FQDN"
fi
[ -z "$B4_2_AFTR_FQDN" ] && B4_2_AFTR_FQDN="aftr.dslite.example.com" \
    && echo "  B4-2 option 64 not received – using default: $B4_2_AFTR_FQDN"

echo "  B4-2: Resolving AFTR FQDN ($B4_2_AFTR_FQDN)"
AFTR_IPV6_2=$(ip netns exec b4-2 host -t AAAA "$B4_2_AFTR_FQDN" 2001:db8:cafe::2 2>/dev/null \
    | awk '/has IPv6 address/ {print $NF; exit}') || true
[ -z "$AFTR_IPV6_2" ] && AFTR_IPV6_2="2001:db8:cafe::10"

# Same anchoring as B4-1: persistent static address used for tunnel
# local; DHCPv6 client only consulted for AFTR-Name (RFC 6334).
ip netns exec b4-2 ip -6 addr add 2001:db8:cafe::b42/64 dev eth-isp \
    valid_lft forever preferred_lft forever 2>/dev/null || true
B4_2_IPV6="2001:db8:cafe::b42"

echo "  B4-2: Starting DNS proxy (RFC 5625)"
ip netns exec b4-2 dnsmasq \
    --interface=eth-lan --except-interface=lo --bind-interfaces --no-resolv \
    --server=2001:db8:cafe::2 \
    --no-dhcp-interface=eth-lan \
    --address=/client2.dslite.example.com/10.0.2.100 \
    --proxy-dnssec \
    --log-queries --log-facility=/var/log/dnsmasq.log \
    --pid-file=/var/run/dnsmasq-b4-2.pid

########################################################################
# 10. Create DS-Lite tunnels (IPv4-in-IPv6, RFC 6333)
########################################################################
echo "=== Creating DS-Lite tunnels (IPv4-in-IPv6) ==="
echo "  B4-1  local=$B4_1_IPV6  remote=$AFTR_IPV6"
echo "  B4-2  local=$B4_2_IPV6  remote=$AFTR_IPV6_2"
echo "  AFTR  local=$AFTR_IPV6"

# --- AFTR side: well-known tunnel address (RFC 6333 §5.7) ---
# 192.0.0.1 is the IANA-assigned AFTR tunnel address from 192.0.0.0/29.
# Assign to loopback (like a router-id) so all tunnel interfaces share it.
ip netns exec aftr ip addr add 192.0.0.1/32 dev lo

# --- AFTR side: wildcard tunnel first (catches any B4 by src IPv6) ---
# Must be created BEFORE the specific per-B4 tunnels so the kernel
# registers it as the fallback; specific tunnels take priority on match.
ip netns exec aftr ip link add name ds-lite-open mtu 1500 \
    type ip6tnl local "$AFTR_IPV6" \
    mode ip4ip6 encaplimit none dev eth-isp
ip netns exec aftr ip link set ds-lite-open up

# --- AFTR side: one named tunnel per known B4 (for per-pool NAT) ---
ip netns exec aftr ip link add name ds-lite-b4-1 mtu 1500 \
    type ip6tnl local "$AFTR_IPV6" remote "$B4_1_IPV6" \
    mode ip4ip6 encaplimit none dev eth-isp
ip netns exec aftr ip link set ds-lite-b4-1 up
ip netns exec aftr ip route add 10.0.1.0/24 dev ds-lite-b4-1

ip netns exec aftr ip link add name ds-lite-b4-2 mtu 1500 \
    type ip6tnl local "$AFTR_IPV6" remote "$B4_2_IPV6" \
    mode ip4ip6 encaplimit none dev eth-isp
ip netns exec aftr ip link set ds-lite-b4-2 up
ip netns exec aftr ip route add 10.0.2.0/24 dev ds-lite-b4-2

# --- B4-1 side (RFC 6333 §5.7: B4 well-known address 192.0.0.2) ---
ip netns exec b4-1 ip link add name ds-lite mtu 1500 \
    type ip6tnl local "$B4_1_IPV6" remote "$AFTR_IPV6" \
    mode ip4ip6 encaplimit none dev eth-isp
ip netns exec b4-1 ip link set ds-lite up
ip netns exec b4-1 ip addr add 192.0.0.2/32 dev ds-lite
ip netns exec b4-1 ip route add default dev ds-lite

# --- B4-2 side (RFC 6333 §5.7: all B4s use same 192.0.0.2) ---
ip netns exec b4-2 ip link add name ds-lite mtu 1500 \
    type ip6tnl local "$B4_2_IPV6" remote "$AFTR_IPV6_2" \
    mode ip4ip6 encaplimit none dev eth-isp
ip netns exec b4-2 ip link set ds-lite up
ip netns exec b4-2 ip addr add 192.0.0.2/32 dev ds-lite
ip netns exec b4-2 ip route add default dev ds-lite

# Tunnel pcap captures
ip netns exec b4-1 \
    tcpdump -U -Z root -i ds-lite -w "$PCAP_DIR/b4-1-tunnel.pcap" 2>/dev/null &
ip netns exec b4-2 \
    tcpdump -U -Z root -i ds-lite -w "$PCAP_DIR/b4-2-tunnel.pcap" 2>/dev/null &
ip netns exec aftr \
    tcpdump -U -Z root -i ds-lite-b4-1 -w "$PCAP_DIR/aftr-tunnel-b4-1.pcap" 2>/dev/null &
ip netns exec aftr \
    tcpdump -U -Z root -i ds-lite-b4-2 -w "$PCAP_DIR/aftr-tunnel-b4-2.pcap" 2>/dev/null &
ip netns exec aftr \
    tcpdump -U -Z root -i ds-lite-open -w "$PCAP_DIR/aftr-tunnel-open.pcap" 2>/dev/null &

########################################################################
# 11. AFTR NAT44 (CGNAT) – RFC 6333 Section 8
########################################################################
echo "=== Configuring AFTR NAT44 (RFC 6333 Section 8) ==="

# ── 8.2 NAT Conformance: conntrack timeouts (RFC 4787 / 5382 / 5508) ──
# Defaults are RFC-compliant; vulnerable mode overrides below.

# RFC 5382: TCP established ≥ 2 hours 24 minutes (= 8640s)
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_established=8640
# RFC 5382: TCP transitory (SYN_SENT, FIN_WAIT, etc.) ≥ 4 minutes
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_syn_sent=300
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_syn_recv=300
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_fin_wait=300
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_close_wait=300
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_last_ack=300
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_time_wait=300
# RFC 4787: UDP ≥ 2 minutes; recommended 5 minutes
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_udp_timeout=300
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_udp_timeout_stream=300
# RFC 5508 REQ-2: ICMP query timeout MUST NOT expire in < 60 s; set to 120 s
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_icmp_timeout=120
# Lab-only: relax the AFTR's TCP seqnum window check so the off-path RST
# injection demo (T20) can land. Many real-world CGN deployments run
# liberal mode for performance / interop; this models that class. Set to
# 0 for a strict deployment.
ip netns exec aftr sysctl -qw net.netfilter.nf_conntrack_tcp_be_liberal="${TCP_BE_LIBERAL:-1}"
# Max conntrack entries (sized for CGNAT) – system-wide parameter, set globally.
# 262,144 entries: matches the value reported in the paper; large enough to
# observe global-table-exhaustion attacks once subscriber multiplexing is
# configured via N_SUBSCRIBERS.
sysctl -qw net.netfilter.nf_conntrack_max="${CONNTRACK_MAX:-262144}" 2>/dev/null || true

echo "  Conntrack timeouts set (RFC 4787/5382/5508 conformance)"

# ── ALGs: all disabled per RFC 4787 REQ-10 / RFC 6333 §8.3 ──
# No nf_nat_* helpers are loaded. UDP-based ALGs SHOULD be off
# (RFC 4787 REQ-10) to avoid interfering with UNSAF traversal
# mechanisms; we extend this to TCP ALGs (FTP, SIP, etc.) for
# consistency. PCP (RFC 6887) replaces the need for ALG-based
# port forwarding.
echo "  ALGs: all disabled (RFC 4787 REQ-10)"

# ── Load the AFTR nftables ruleset (RFC 6056 / RFC 6888 conformant) ──
ip netns exec aftr nft -f "$SCRIPT_DIR/aftr/nftables.conf"
echo "  nftables loaded (shared SNAT pool 192.0.2.1, random ports 1024-65535,"
echo "  per-subscriber cap 2000; RFC 6056 §3.3.1 + RFC 6888 REQ-2/4)"

# ── RFC 6333 §6.6 per-softwire reply routing ────────────────────────
# The conntrack zone (nftables.conf) lets the SAME private IPv4 live
# behind multiple B4s as distinct entries. The de-NAT'd reply then has
# an overlapping private destination, so it must be sent to the CORRECT
# softwire. We policy-route it by the restored ct mark (= low 32 bits of
# the B4's softwire IPv6, host byte order — identical to the traceability
# map). The "home" overlap range 192.168.0.0/16 is routed per-softwire;
# the testbed's own non-overlapping subscriber /24s stay in the main
# table and the per-B4 table lookup falls through, so default flows and
# all 22 attacks are unaffected.
OVERLAP_RANGE="${DSLITE_OVERLAP_RANGE:-192.168.0.0/16}"
_mk_mark() { python3 -c "import ipaddress,sys;print(int.from_bytes(int(ipaddress.IPv6Address(sys.argv[1])).to_bytes(16,'big')[-4:],sys.byteorder))" "$1"; }
if [ -n "$B4_1_IPV6" ]; then
    M1=$(_mk_mark "$B4_1_IPV6")
    ip netns exec aftr ip route replace table 101 "$OVERLAP_RANGE" dev ds-lite-b4-1
    ip netns exec aftr ip rule del fwmark "$M1" table 101 2>/dev/null || true
    ip netns exec aftr ip rule add fwmark "$M1" table 101
fi
if [ -n "$B4_2_IPV6" ]; then
    M2=$(_mk_mark "$B4_2_IPV6")
    ip netns exec aftr ip route replace table 102 "$OVERLAP_RANGE" dev ds-lite-b4-2
    ip netns exec aftr ip rule del fwmark "$M2" table 102 2>/dev/null || true
    ip netns exec aftr ip rule add fwmark "$M2" table 102
fi
echo "  RFC 6333 §6.6 extended binding: per-softwire conntrack zones +"
echo "  per-B4 reply routing for overlapping private space ($OVERLAP_RANGE)"

########################################################################
# 12. PCP (Port Control Protocol) – RFC 6887 + draft-ietf-pcp-dslite-00
########################################################################
echo "=== Starting PCP services (RFC 6887 plain mode) ==="

# PCP server on AFTR: listens UDP6/5351, manages pcp_dnat nftables chain.
# Lab demo: cap the PCP pool so T15 exhaustion is reachable in a trial.
# Override with PCP_POOL_SIZE in the environment; unset for full RFC range.
ip netns exec aftr env PCP_POOL_SIZE="${PCP_POOL_SIZE:-1024}" \
    python3 "$SCRIPT_DIR/aftr/pcp_server.py" \
    > /var/log/pcp-server.log 2>&1 &
echo "  PCP server running on AFTR  UDP6/5351  pool=${PCP_POOL_SIZE:-1024} ports  log=/var/log/pcp-server.log"

sleep 1

# PCP proxy on B4-1: listens UDP4/5351 on LAN, forwards to AFTR over IPv6
ip netns exec b4-1 python3 "$SCRIPT_DIR/b4/pcp_proxy.py" \
    --lan-ip  10.0.1.1 \
    --b4-ip6  "$B4_1_IPV6" \
    --aftr-ip6 "$AFTR_IPV6" \
    --passthrough-third-party \
    > /var/log/pcp-proxy-b4-1.log 2>&1 &
echo "  PCP proxy running on B4-1   UDP4/5351  b4=$B4_1_IPV6"

# PCP proxy on B4-2: listens UDP4/5351 on LAN, forwards to AFTR over IPv6
ip netns exec b4-2 python3 "$SCRIPT_DIR/b4/pcp_proxy.py" \
    --lan-ip  10.0.2.1 \
    --b4-ip6  "$B4_2_IPV6" \
    --aftr-ip6 "$AFTR_IPV6_2" \
    --passthrough-third-party \
    > /var/log/pcp-proxy-b4-2.log 2>&1 &
echo "  PCP proxy running on B4-2   UDP4/5351  b4=$B4_2_IPV6"

########################################################################
# 13. Server HTTP + DNS test services
########################################################################
echo "=== Starting Server HTTP test service ==="
# Use a single-threaded Python HTTP server (TCPServer with allow_reuse_address).
# Single-threaded + bounded listen() backlog (default 5 in Python's TCPServer) means
# Slowloris can fill the backlog and block legitimate connections — T4b works correctly.
# socat/nc fork modes handle connections independently and cannot be backlog-saturated.
ip netns exec server python3 -c '
import http.server, socket, os

HTML = b"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DS-Lite Lab - Server</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; margin: 40px; }
    h1   { color: #58a6ff; }
    table{ border-collapse: collapse; margin-top: 16px; }
    th,td{ border: 1px solid #30363d; padding: 6px 14px; text-align: left; }
    th   { background: #161b22; color: #58a6ff; }
    .ok  { color: #3fb950; font-weight: bold; }
  </style>
</head>
<body>
  <h1>DS-Lite Lab &mdash; Public Server</h1>
  <p class="ok">&#10003; HTTP reachable through DS-Lite / CGNAT</p>
  <table>
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Server IP</td><td>198.51.100.2</td></tr>
    <tr><td>Server port</td><td>80</td></tr>
    <tr><td>AFTR public IPv4</td><td>192.0.2.1 (shared SNAT pool)</td></tr>
    <tr><td>RFC</td><td>6333 (DS-Lite), 6334 (DHCPv6 opt-64)</td></tr>
  </table>
</body>
</html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(HTML)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(HTML)
    def log_message(self, fmt, *args):
        pass  # suppress access log noise

srv = http.server.HTTPServer(("", 80), Handler)
srv.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# request_queue_size = 5 (default) → Slowloris fills this and blocks new connections
srv.serve_forever()
' >/dev/null 2>&1 &

# T2 echo service – always started so port_prediction.py works without manual setup.
# Listens on TCP/9999 and UDP/9999; echoes back "PORT <peer_port>" to the caller.
ip netns exec server socat \
    TCP-LISTEN:9999,fork,reuseaddr \
    SYSTEM:'echo PORT $SOCAT_PEERPORT' \
    >/dev/null 2>&1 &
ip netns exec server socat \
    UDP-RECVFROM:9999,fork,reuseaddr \
    SYSTEM:'echo PORT $SOCAT_PEERPORT' \
    >/dev/null 2>&1 &
echo "  T2 echo service running on server  TCP+UDP/9999"

# Long-lived TCP connection-sink on port 6666 — accepts and HOLDS every
# connection in ONE process (no fork-per-connection). The T1 SIEGE phase opens
# ~2000 simultaneous ESTABLISHED holds against it; a socat ...,fork sink crashes
# under that load (thousands of child procs) and silently breaks the SIEGE.
ip netns exec server python3 /testbed/server/conn_sink.py 6666 >/dev/null 2>&1 &
echo "  TCP connection-sink on server     TCP/6666  (single-proc hold)"

# DNS server in the server namespace (IPv4, 198.51.100.2:53)
# Authoritative for dslite.example.com – open resolver for amplification demo
ip netns exec server dnsmasq \
    -C "$SCRIPT_DIR/server/dnsmasq.conf" \
    --pid-file=/var/run/dnsmasq-server.pid
echo "  DNS server running on 198.51.100.2:53"

# Expose the server to the host browser via socat on port 8080 (container root ns).
# Each incoming connection forks a child that executes nc inside the server namespace.
# This path is direct (bypasses DS-Lite) and is only for visual browser access.
socat TCP-LISTEN:8080,fork,reuseaddr \
    EXEC:"ip netns exec server nc 127.0.0.1 80" 2>/dev/null &

########################################################################
# 13b. SNMP agent on AFTR (RFC 7870 DSLITE-MIB – T14/T15 target)
########################################################################
echo "=== Starting AFTR SNMP agent (RFC 7870 DSLITE-MIB) ==="
# RFC 5706 §3.1 — bind to OAM management interface only.  The data-plane
# interfaces (eth-wan, eth-isp) are additionally protected by the nftables
# rules below that drop udp/161 — defense in depth.
ip netns exec aftr python3 -u "$SCRIPT_DIR/aftr/snmp_agent.py" \
    --host 10.99.0.1 --port 161 --community public \
    > /var/log/snmp-agent.log 2>&1 &
echo "  SNMP agent running on AFTR  10.99.0.1:161 (OAM only)  community=public"
echo "  Exposes: dsliteTunnelTable, dsliteNATBindTable, alarm thresholds"
echo "  T14 test: python3 /testbed/attack_tools/infra/snmp_attack.py set --target 10.99.0.1 --oid alarmConnectNumber --value 2147483647"
echo "  T15 test: python3 /testbed/attack_tools/infra/snmp_attack.py read --target 10.99.0.1 --oids all"

# RFC 5706 defense-in-depth: drop SNMP arriving on data-plane interfaces
# even if a future misconfiguration binds the agent to 0.0.0.0.  Operators
# typically deploy this at the AFTR's edge ACL.
ip netns exec aftr nft add table inet mgmt_acl 2>/dev/null || true
ip netns exec aftr nft 'add chain inet mgmt_acl input { type filter hook input priority -100 ; policy accept ; }' 2>/dev/null || true
ip netns exec aftr nft add rule inet mgmt_acl input iifname "eth-wan" udp dport 161 drop 2>/dev/null || true
ip netns exec aftr nft add rule inet mgmt_acl input iifname "eth-isp" udp dport 161 drop 2>/dev/null || true

########################################################################
# 13c. RFC 6888 §4 subscriber-traceability logger on AFTR
#       (records subscriber identifier, internal/public address+port,
#        protocol, and timestamp for every NAT mapping created)
#       Uses RFC 7785 §3 subscriber-mask derivation for the identifier;
#       mask length is configurable via the SUBSCRIBER_MASK env var
#       (default /56, matching the RFC 7785 §3 informational default).
#       Destination logging follows RFC 6888 REQ-12 and is OFF unless
#       LOG_DESTINATIONS=1 is set.
########################################################################
echo "=== Starting AFTR traceability logger (RFC 6888 §4) ==="

# Provide the ct-mark → B4 IPv6 mapping the logger needs to attribute
# every NAT mapping to a specific CPE. The mark is what `meta mark set
# @nh,160,32` extracts on softwire ingress (the low 32 bits of the outer
# IPv6 source, stored in host byte order). Computing it from the live
# tunnel addresses keeps the mapping correct across SLAAC/DHCPv6 reboots
# instead of falling back to a stale hardcoded table.
CT_MARK_MAP_FILE="${CT_MARK_MAP_FILE:-/var/run/dslite-ct-mark-map.json}"
python3 - "$CT_MARK_MAP_FILE" "$B4_1_IPV6" "$B4_2_IPV6" <<'PY'
import ipaddress, json, sys
path, *pairs = sys.argv[1], *sys.argv[2:]
m = {}
for ipv6 in pairs:
    if not ipv6:
        continue
    addr = ipaddress.IPv6Address(ipv6)
    low32 = int(addr).to_bytes(16, "big")[-4:]
    mark = int.from_bytes(low32, sys.byteorder)
    m[str(mark)] = ipv6
with open(path, "w", encoding="utf-8") as fh:
    json.dump(m, fh)
PY

SUBSCRIBER_MASK="${SUBSCRIBER_MASK:-56}" \
LOG_DESTINATIONS="${LOG_DESTINATIONS:-0}" \
TRACEABILITY_LOG_PATH="${TRACEABILITY_LOG_PATH:-/var/log/dslite-aftr-traceability.log}" \
CT_MARK_MAP_FILE="$CT_MARK_MAP_FILE" \
PYTHONPATH="$SCRIPT_DIR/aftr:${PYTHONPATH:-}" \
    ip netns exec aftr python3 -u "$SCRIPT_DIR/aftr/traceability_logger.py" \
    >> /var/log/traceability-logger.stderr.log 2>&1 &
echo "  Traceability logger running on AFTR"
echo "    subscriber-mask: /${SUBSCRIBER_MASK:-56} (RFC 7785 §3)"
echo "    ct-mark map: $CT_MARK_MAP_FILE"
echo "    log path: ${TRACEABILITY_LOG_PATH:-/var/log/dslite-aftr-traceability.log}"
echo "    destination logging: ${LOG_DESTINATIONS:-0} (RFC 6888 REQ-12: off by default)"

echo ""
echo "DS-Lite testbed is ready."
echo "Pcap files being written to: $PCAP_DIR/"

########################################################################
# 14. Attacker namespace (optional, controlled by ATTACKER_PLACEMENT)
########################################################################
# ATTACKER_PLACEMENT values: "b4-1", "b4-2", "isp", "internet", "mgmt", or "" (none)
if [ -n "${ATTACKER_PLACEMENT:-}" ]; then
    echo ""
    echo "=== Setting up Attacker on: $ATTACKER_PLACEMENT ==="
    ip netns add attacker
    ip netns exec attacker ip link set lo up

    case "$ATTACKER_PLACEMENT" in
        b4-1)
            # IPv4-only attacker on B4-1's LAN (10.0.1.0/24)
            ip link add eth0-atk type veth peer name eth-atk-b41
            ip link set eth0-atk netns attacker
            ip netns exec attacker ip link set eth0-atk name eth0
            ip link set eth-atk-b41 netns b4-1

            # Create bridge on B4-1's LAN to connect both Client1 and Attacker.
            # stp_state 0 + forward_delay 0 = the bridge forwards immediately;
            # otherwise a new port sits in LISTENING/LEARNING for ~4s and the
            # attacker's first DHCP DISCOVER is dropped, leaving it with no lease.
            ip netns exec b4-1 ip link add br-lan type bridge stp_state 0 forward_delay 0
            ip netns exec b4-1 ip addr del 10.0.1.1/24 dev eth-lan
            ip netns exec b4-1 ip link set eth-lan master br-lan
            ip netns exec b4-1 ip link set eth-atk-b41 master br-lan
            ip netns exec b4-1 ip link set eth-atk-b41 up
            ip netns exec b4-1 ip addr add 10.0.1.1/24 dev br-lan
            ip netns exec b4-1 ip link set br-lan up

            # eth-lan is now a bridge port — restart pcap on br-lan so attacker
            # traffic (arriving on eth-atk-b41) is captured too.
            pkill -f "b4-1-lan.pcap" 2>/dev/null || true
            sleep 0.3
            ip netns exec b4-1 \
                tcpdump -U -Z root -i br-lan -w "$PCAP_DIR/b4-1-lan.pcap" 2>/dev/null &

            # Reconfigure dnsmasq to listen on br-lan instead of eth-lan
            kill $(cat /var/run/dnsmasq-b4-1.pid 2>/dev/null) 2>/dev/null || true
            sleep 0.5
            ip netns exec b4-1 dnsmasq \
                --interface=br-lan --except-interface=lo --bind-interfaces --no-resolv \
                --server=2001:db8:cafe::2 \
                --address=/client1.dslite.example.com/10.0.1.100 \
                --proxy-dnssec \
                --log-queries --log-facility=/var/log/dnsmasq.log \
                --dhcp-range=10.0.1.150,10.0.1.200,255.255.255.0,12h \
                --dhcp-option=3,10.0.1.1 \
                --dhcp-option=6,10.0.1.1 \
                --pid-file=/var/run/dnsmasq-b4-1.pid

            # Attacker gets IP via DHCP from B4-1. dnsmasq was just restarted on
            # br-lan and needs a moment to bind its DHCP socket; retry a few
            # times so the attacker reliably gets a 10.0.1.x lease (the LAN
            # attacks pass it as --src-ip4 $ATK_IP4, which is empty without one).
            ip netns exec attacker ip link set eth0 up
            sleep 1
            for _dhtry in 1 2 3 4 5; do
                timeout 8 ip netns exec attacker dhclient -1 \
                    -pf /var/run/dhclient-attacker.pid \
                    -lf /var/lib/dhcp/dhclient-attacker.leases eth0 2>/dev/null || true
                ip netns exec attacker ip -4 addr show eth0 | grep -q 'inet ' && break
                sleep 1
            done

            mkdir -p /etc/netns/attacker
            echo "nameserver 10.0.1.1" > /etc/netns/attacker/resolv.conf
            ;;

        b4-2)
            # IPv4-only attacker on B4-2's LAN (10.0.2.0/24)
            ip link add eth0-atk type veth peer name eth-atk-b42
            ip link set eth0-atk netns attacker
            ip netns exec attacker ip link set eth0-atk name eth0
            ip link set eth-atk-b42 netns b4-2

            # Create bridge on B4-2's LAN to connect both Client2 and Attacker.
            # stp_state 0 + forward_delay 0 = forward immediately (see b4-1 note).
            ip netns exec b4-2 ip link add br-lan type bridge stp_state 0 forward_delay 0
            ip netns exec b4-2 ip addr del 10.0.2.1/24 dev eth-lan
            ip netns exec b4-2 ip link set eth-lan master br-lan
            ip netns exec b4-2 ip link set eth-atk-b42 master br-lan
            ip netns exec b4-2 ip link set eth-atk-b42 up
            ip netns exec b4-2 ip addr add 10.0.2.1/24 dev br-lan
            ip netns exec b4-2 ip link set br-lan up

            # eth-lan is now a bridge port — restart pcap on br-lan.
            pkill -f "b4-2-lan.pcap" 2>/dev/null || true
            sleep 0.3
            ip netns exec b4-2 \
                tcpdump -U -Z root -i br-lan -w "$PCAP_DIR/b4-2-lan.pcap" 2>/dev/null &

            # Reconfigure dnsmasq to listen on br-lan instead of eth-lan
            kill $(cat /var/run/dnsmasq-b4-2.pid 2>/dev/null) 2>/dev/null || true
            ip netns exec b4-2 dnsmasq \
                --interface=br-lan --except-interface=lo --bind-interfaces --no-resolv \
                --server=2001:db8:cafe::2 \
                --dhcp-range=10.0.2.150,10.0.2.200,255.255.255.0,12h \
                --dhcp-option=3,10.0.2.1 \
                --dhcp-option=6,10.0.2.1 \
                --pid-file=/var/run/dnsmasq-b4-2.pid

            # Attacker gets IP via DHCP from B4-2 (retry; see b4-1 note).
            ip netns exec attacker ip link set eth0 up
            sleep 1
            for _dhtry in 1 2 3 4 5; do
                timeout 8 ip netns exec attacker dhclient -1 \
                    -pf /var/run/dhclient-attacker.pid \
                    -lf /var/lib/dhcp/dhclient-attacker.leases eth0 2>/dev/null || true
                ip netns exec attacker ip -4 addr show eth0 | grep -q 'inet ' && break
                sleep 1
            done

            mkdir -p /etc/netns/attacker
            echo "nameserver 10.0.2.1" > /etc/netns/attacker/resolv.conf
            ;;

        isp)
            # IPv6-only attacker on the ISP network (br-isp)
            ip link add eth-isp-atk type veth peer name atk-br
            ip link set eth-isp-atk mtu "${ISP_MTU:-1500}" && ip link set atk-br mtu "${ISP_MTU:-1500}"
            ip link set eth-isp-atk netns attacker
            ip netns exec attacker ip link set eth-isp-atk name eth-isp
            ip link set atk-br master br-isp
            ip link set atk-br up
            ip netns exec attacker ip link set eth-isp up
            # Attacker gets IPv6 via SLAAC from radvd + DHCPv6
            ip netns exec attacker sysctl -qw net.ipv6.conf.eth-isp.accept_ra=1
            # Static IPv6 for attacker on ISP segment — required for T14 (AFTR
            # Discovery Hijack): the testbed DNS resolves aftr-rogue.dslite.example.com
            # to this address so the victim B4's tunnel-rebuild hook can complete.
            ip netns exec attacker ip -6 addr add 2001:db8:cafe::13a/64 dev eth-isp 2>/dev/null || true
            # Hub mode: set bridge ageing_time=0 so all unicast is flooded to
            # every port (attacker sees all B4↔AFTR softwire traffic). Required
            # for T7 (unencrypted tunnel traffic interception) to work.
            ip link set br-isp type bridge ageing_time 0
            bridge link set dev atk-br learning off flood on 2>/dev/null || true
            ;;

        mgmt)
            # IPv4-only attacker on the OAM/management network (10.99.0.0/24)
            # Models an insider with management-plane access — the only
            # placement from which SNMP attacks (T14/T15) succeed when the
            # AFTR follows RFC 5706 §3.1 OAM segregation.
            ip link add eth-mgmt-atk type veth peer name atk-mgmt-br
            ip link set eth-mgmt-atk netns attacker
            ip netns exec attacker ip link set eth-mgmt-atk name eth0
            ip link set atk-mgmt-br master br-mgmt
            ip link set atk-mgmt-br up

            ip netns exec attacker ip link set eth0 up
            ip netns exec attacker ip addr add 10.99.0.50/24 dev eth0
            # No default route — mgmt network is intentionally isolated.
            ;;

        internet)
            # IPv4-only attacker on the public Internet (198.51.100.0/24)
            # The attacker sits on the same L2 segment as the server, behind
            # server-router.  This models an external host on the public Internet
            # that can reach AFTR's public IPs (192.0.2.1/2) via server-router.
            #
            # We convert the point-to-point server-router↔server link into a
            # bridge (br-srv) so the attacker can join the same L2 segment.

            # 1. Create bridge in server-router namespace
            ip netns exec server-router ip link add br-srv type bridge
            ip netns exec server-router ip link set br-srv up

            # 2. Move server-router's eth-srv into the bridge
            ip netns exec server-router ip addr del 198.51.100.1/24 dev eth-srv
            ip netns exec server-router ip link set eth-srv master br-srv
            ip netns exec server-router ip addr add 198.51.100.1/24 dev br-srv

            # 3. Create veth pair for attacker and attach to bridge
            ip link add eth0-atk type veth peer name eth-atk-srv
            ip link set eth0-atk netns attacker
            ip netns exec attacker ip link set eth0-atk name eth0
            ip link set eth-atk-srv netns server-router
            ip netns exec server-router ip link set eth-atk-srv master br-srv
            ip netns exec server-router ip link set eth-atk-srv up

            # 4. Configure attacker networking
            ip netns exec attacker ip link set eth0 up
            ip netns exec attacker ip addr add 198.51.100.50/24 dev eth0
            ip netns exec attacker ip route add default via 198.51.100.1

            mkdir -p /etc/netns/attacker
            echo "nameserver 198.51.100.2" > /etc/netns/attacker/resolv.conf
            ;;
    esac

    # Pcap on attacker interface.
    # `ip -o link show` prints veth names as "eth0@if27"; the "@if27" peer
    # suffix is NOT a valid tcpdump device name, so strip it (cut at '@') or
    # tcpdump fails with "No such device" and the capture silently never
    # starts. (The run.sh reposition path already strips it; this is the
    # initial-setup path.)
    ATK_IFACE=$(ip netns exec attacker ip -o link show \
        | awk -F': ' '/eth/ {print $2; exit}' | cut -d'@' -f1)
    if [ -n "$ATK_IFACE" ]; then
        ip netns exec attacker \
            tcpdump -U -Z root -i "$ATK_IFACE" -w "$PCAP_DIR/attacker.pcap" 2>/dev/null &
    fi

    echo "  Attacker namespace ready (placement: $ATTACKER_PLACEMENT)"
fi
########################################################################
# 14. Gotham-criteria extensions (F1 cgroups, F4 link-QoS, S1 scale-out)
#     Each is opt-in via env vars; defaults preserve baseline behaviour.
#     Paper §3.2 and §10.5 describe the integration.
########################################################################
SCRIPT_DIR_FINAL="$(cd "$(dirname "$0")" && pwd)"
PERF_DIR="$SCRIPT_DIR_FINAL/scripts/perf"
if [ -f "$PERF_DIR/setup_cgroups.sh" ]; then
    bash "$PERF_DIR/setup_cgroups.sh" || \
        echo "[setup] cgroups module skipped (non-fatal)"
fi
if [ -f "$PERF_DIR/setup_scale.sh" ]; then
    bash "$PERF_DIR/setup_scale.sh" || \
        echo "[setup] scale-out module skipped (non-fatal)"
fi
if [ -f "$PERF_DIR/setup_qos.sh" ]; then
    bash "$PERF_DIR/setup_qos.sh" || \
        echo "[setup] qos module skipped (non-fatal)"
fi

echo "=== Setup complete ==="
