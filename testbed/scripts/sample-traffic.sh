#!/bin/bash
# Generate one clean, visible exchange of every DS-Lite protocol so that
# Wireshark windows across the lab all show packets without the user
# having to fight caches, ping's per-invocation startup, or timing.
#
# Run from any terminal:
#   bash /testbed/scripts/sample-traffic.sh
#
# After this runs, every capture point should have fresh activity:
#   menu  1 (br-isp)              — DHCPv6, DNS, PCP, SNMP, ICMP-in-IPv6
#   menu  2 (AFTR eth-isp)        — same subset that hits the AFTR
#   menu  3 (AFTR eth-wan)        — SNMP + post-NAT ICMP
#   menu  4 (AFTR ds-lite-open)   — usually empty unless attacker is on ISP
#   menu  5 (B4-1 eth-isp)        — B4-1's view of the ISP segment
#   menu  6 (B4-1 LAN)            — client1↔B4-1 DNS + ICMP
#   menu  7 (B4-1 tunnel)         — decapsulated IPv4 at B4-1
#   menu  8 (B4-2 eth-isp)        — B4-2's view
#   menu  9 (B4-2 LAN)            — client2↔B4-2
#   menu 10 (B4-2 tunnel)         — decapsulated IPv4 at B4-2
#   menu 11 (Server eth0)         — public-IPv4 ICMP, SNMP, HTTP

set -u
banner() { echo; echo "════════ $* ════════"; }

# 1. Force a fresh DHCPv6 SOLICIT/ADVERTISE/REQUEST/REPLY (option 64).
#    HUP-renewal on dhclient triggers a wire-visible 4-message exchange.
banner "DHCPv6 (option 64 AFTR-Name)"
ip netns exec b4-1 dhclient -6 -1 -nw \
    -cf /etc/dhcp/dhclient6-b4-1.conf \
    -lf /var/lib/dhcp/dhclient6-b4-1.leases \
    -pf /var/run/dhclient6-b4-1.pid eth-isp 2>&1 | head -2
sleep 1

# 2. Forward A + reverse PTR. Use random forward names so the answer is
#    never cached at B4-1 dnsmasq → both directions guaranteed visible.
banner "DNS forward (A/AAAA) + reverse (PTR)"
NONCE=nonce-$(date +%s)
echo "[client1] dig A?    $NONCE.dslite.example.com    (in our zone → NXDOMAIN, but query+reply visible on br-isp)"
ip netns exec client1 dig +short +time=1 "$NONCE.dslite.example.com" || true
echo "[client1] dig -x 198.51.100.2   (reverse → PTR)"
ip netns exec client1 dig +short +time=1 -x 198.51.100.2
echo "[b4-1]    dig A?    server.dslite.example.com   (over IPv6 to ::2)"
ip netns exec b4-1 dig +short +time=1 server.dslite.example.com

# 3. Run ICMP via the softwire — pick -c 3 so the startup A query is
#    obvious on br-isp, and the per-reply PTRs are also visible.
banner "ICMP through softwire (3 packets)"
ip netns exec client1 ping -c 3 -i 0.5 -W 2 server.dslite.example.com 2>&1 | head -6

# 4. PCP MAP from B4-1's PCP proxy to AFTR's PCP server.
banner "PCP MAP request (B4-1 proxy → AFTR ::10)"
ip netns exec b4-1 python3 -c "
import socket, struct, os
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
hdr = struct.pack('!BBHI16s', 2, 1, 0, 120, b'\\x00'*16)
nonce = b'SampleTrafc!'   # 12 bytes, will be echoed back
pld = nonce + struct.pack('!B3sHH16s', 17, b'\\x00'*3, 12345, 0, b'\\x00'*16)
s.sendto(hdr+pld, ('10.0.1.1', 5351))
data, _ = s.recvfrom(1100)
print(f'  PCP reply: {len(data)} bytes, result={data[3]} (0=SUCCESS)')
print(f'  nonce echoed: {data[24:36]!r}')
"

# 5. SNMP get on the AFTR's DSLITE-MIB (visible on AFTR eth-wan).
banner "SNMP get from server-router → AFTR (DSLITE-MIB)"
ip netns exec server-router snmpget -v2c -c public 192.0.2.1 \
    1.3.6.1.2.1.240.1.3.1.1.0 2>&1 | head -3

# 6. HTTP through the softwire (visible on server eth0).
banner "HTTP request through CGNAT (client1 → server)"
ip netns exec client1 curl -sS -o /dev/null \
    -w 'HTTP %{http_code} %{size_download} bytes %{time_total}s\n' \
    --max-time 3 http://198.51.100.2/

echo
echo "Done. Each Wireshark window should now contain matching traffic."
echo "If a window is empty, the relevant netns wasn't on the packet path —"
echo "consult the cheat sheet to pick a different capture point."
