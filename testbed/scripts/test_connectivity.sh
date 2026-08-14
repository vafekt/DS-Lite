#!/bin/bash
PASS=0; FAIL=0

run_test() {
    local desc="$1"; shift
    echo -n "  $desc ... "
    if "$@" >/dev/null 2>&1; then
        echo "PASS"; ((PASS++))
    else
        echo "FAIL"; ((FAIL++))
    fi
}

echo "=== IPv6 ISP network ==="
run_test "DHCPv6-Server -> AFTR ping6"   ip netns exec dhcpv6server ping -6 -c 2 -W 2 2001:db8:cafe::10
run_test "B4-1 -> AFTR ping6"            ip netns exec b4-1 ping -6 -c 2 -W 2 2001:db8:cafe::10
run_test "B4-2 -> AFTR ping6"            ip netns exec b4-2 ping -6 -c 2 -W 2 2001:db8:cafe::10
run_test "B4-1 -> DHCPv6-Server ping6"   ip netns exec b4-1 ping -6 -c 2 -W 2 2001:db8:cafe::1
run_test "B4-2 -> DHCPv6-Server ping6"   ip netns exec b4-2 ping -6 -c 2 -W 2 2001:db8:cafe::1

echo "=== DHCPv6 / DNS ==="
# DNS server runs in its own netns at ::2 (split from dhcpv6server at ::1)
run_test "B4-1 DNS resolve AFTR FQDN"    ip netns exec b4-1 host -t AAAA aftr.dslite.example.com 2001:db8:cafe::2
run_test "B4-2 DNS resolve AFTR FQDN"    ip netns exec b4-2 host -t AAAA aftr.dslite.example.com 2001:db8:cafe::2

echo "=== DS-Lite tunnels ==="
run_test "B4-1 tunnel interface up"       ip netns exec b4-1 ip link show ds-lite
run_test "B4-2 tunnel interface up"       ip netns exec b4-2 ip link show ds-lite
run_test "AFTR tunnel to B4-1 up"         ip netns exec aftr ip link show ds-lite-b4-1
run_test "AFTR tunnel to B4-2 up"         ip netns exec aftr ip link show ds-lite-b4-2
# RFC 6333 §5.3 — tunnel inner MTU = 1500 (br-isp link widened to 1540 to absorb 40-byte IPv6 header)
run_test "B4-1 tunnel MTU (1500)" ip netns exec b4-1 sh -c 'ip link show ds-lite | grep -q "mtu 1500"'
run_test "B4-2 tunnel MTU (1500)" ip netns exec b4-2 sh -c 'ip link show ds-lite | grep -q "mtu 1500"'
run_test "AFTR well-known addr 192.0.0.1" ip netns exec aftr ip addr show lo

echo "=== Client1 (10.0.1.100) via B4-1 end-to-end ==="
run_test "Ping 192.0.2.1 (AFTR WAN)"     ip netns exec client1 ping -c 2 -W 3 192.0.2.1
run_test "Ping 198.51.100.2 (Server)"     ip netns exec client1 ping -c 2 -W 3 198.51.100.2
run_test "HTTP Server"                    ip netns exec client1 curl -sf --max-time 5 http://198.51.100.2/
run_test "DNS resolution via B4-1 proxy"  ip netns exec client1 host -t AAAA aftr.dslite.example.com 10.0.1.1

echo "=== Client2 (10.0.2.100) via B4-2 end-to-end ==="
run_test "Ping 192.0.2.1 (AFTR WAN)"     ip netns exec client2 ping -c 2 -W 3 192.0.2.1
run_test "Ping 198.51.100.2 (Server)"     ip netns exec client2 ping -c 2 -W 3 198.51.100.2
run_test "HTTP Server"                    ip netns exec client2 curl -sf --max-time 5 http://198.51.100.2/
run_test "DNS resolution via B4-2 proxy"  ip netns exec client2 host -t AAAA aftr.dslite.example.com 10.0.2.1

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
