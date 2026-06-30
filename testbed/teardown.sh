#!/bin/bash
echo "Tearing down DS-Lite testbed..."

# Kill all background processes that may be stale
pkill -9 tcpdump 2>/dev/null || true
pkill -9 dhcpd 2>/dev/null || true
pkill -9 radvd 2>/dev/null || true
pkill -9 dnsmasq 2>/dev/null || true
pkill -9 -f pcp_server 2>/dev/null || true
pkill -9 -f pcp_proxy 2>/dev/null || true
pkill -9 -f dns_proxy 2>/dev/null || true
pkill -9 -f http_server 2>/dev/null || true
pkill -9 -f monitor_nat 2>/dev/null || true
pkill -9 -f snmpd 2>/dev/null || true
sleep 1

# Remove stale PID files
rm -f /var/run/dhcpd6.pid /var/run/radvd.pid /var/run/radvd/radvd.pid 2>/dev/null

# Discover any scaled-out B4-N / clientN namespaces (Gotham S1 add-ons)
SCALED_B4S=$(ip netns list 2>/dev/null | awk '/^b4-[0-9]+/{print $1}' | sort -u)
SCALED_CLIENTS=$(ip netns list 2>/dev/null | awk '/^client[0-9]+/{print $1}' | sort -u)

# Kill processes in each namespace (base + scaled-out)
for ns in dhcpv6server dns-server aftr server-router server attacker mgmt $SCALED_B4S $SCALED_CLIENTS; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
done
sleep 1

# Delete namespaces (also removes veth endpoints)
for ns in dhcpv6server dns-server aftr server-router server attacker mgmt $SCALED_B4S $SCALED_CLIENTS; do
    ip netns del "$ns" 2>/dev/null || true
done

# Clean up bridge and stale veth pairs (privileged containers may leave
# orphaned links after namespace deletion due to shared mount table)
ip link del br-isp 2>/dev/null || true
ip link del br-mgmt 2>/dev/null || true
for dev in eth-isp-dhcp6s dhcp6s-br eth-isp-dns dns-br eth-isp-b41 b41-br eth-isp-b42 b42-br \
           eth-isp-aftr aftr-br eth-lan-b41 eth0-cl1 eth-lan-b42 eth0-cl2 \
           eth-wan-aftr eth-aftr-sr eth-srv-sr eth0-srv \
           eth-mgmt-aftr aftr-mgmt-br eth-mgmt-stn mgmt-stn-br eth-mgmt-atk atk-mgmt-br \
           eth0-atk eth-atk-b41 eth-atk-b42 eth-isp-atk atk-br eth-atk-srv; do
    ip link del "$dev" 2>/dev/null || true
done
# Scaled-out veth peers (Gotham S1)
for i in 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
    ip link del "eth-isp-b4${i}" 2>/dev/null || true
    ip link del "b4${i}-br"      2>/dev/null || true
    ip link del "eth-lan-b4${i}" 2>/dev/null || true
    ip link del "eth0-cl${i}"    2>/dev/null || true
done
nft flush ruleset 2>/dev/null || true

# Clean up per-netns resolv.conf
rm -rf /etc/netns/client1 /etc/netns/client2 /etc/netns/attacker 2>/dev/null || true
for i in 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
    rm -rf "/etc/netns/client${i}" 2>/dev/null || true
done

# Tear down Gotham F1 cgroup hierarchy
if [ -d /sys/fs/cgroup/dslite ]; then
    for cg in /sys/fs/cgroup/dslite/*/; do
        rmdir "$cg" 2>/dev/null || true
    done
    rmdir /sys/fs/cgroup/dslite 2>/dev/null || true
fi

# Restore system-wide conntrack_max (may have been lowered to 512 by vulnerable mode)
sysctl -qw net.netfilter.nf_conntrack_max=262144 2>/dev/null || true

echo "All namespaces and processes removed."
