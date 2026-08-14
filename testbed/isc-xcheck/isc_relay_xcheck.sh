#!/bin/bash
# ISC AFTR (reference DS-Lite) T11 relay egress cross-check.
# Topology (all inside one privileged container, three netns):
#
#   [b4 ns]                 [root ns: ISC aftr + tun0]              [wan ns]
#   unprovisioned B4        endpoint 2001::1 (routed to tun0)       external server
#   2001:0:0:5::2  --v_b4-- v_b4=2001:0:0:5::1                      203.0.113.9
#   inner 10.0.5.2          pool 198.18.200.111 --SNAT--> 203.0.113.1 (shared public)
#                           v_wan=203.0.113.1 --v_wan-- v_wanp
#
# The B4 source 2001:0:0:5::2 is inside acl6 2001::/48 but has NO static
# `nat` binding -> UNPROVISIONED. ISC aftr default use_autotunnel=1 serves it.
set -u
FORWARD=${FORWARD:-1}   # 1 = ISC-documented egress path; 0 = diagnosis contrast
EV=/work/isc_evidence_fwd${FORWARD}
echo "########## SCENARIO: ip_forward=$FORWARD ##########"
rm -rf "$EV"; mkdir -p "$EV"
LOG="$EV/run.log"; exec > >(tee "$LOG") 2>&1
AFTR=/build/aftr

echo "############ PHASE A: host/root-ns network setup ############"
# userspace NAT in aftr; kernel must forward and not reverse-path-drop the
# translated packet, and netfilter filter table must not interfere (README 3.1).
sysctl -w net.ipv4.ip_forward=$FORWARD
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
modprobe ip6_tunnel 2>/dev/null || true
iptables -F 2>/dev/null; iptables -t nat -F 2>/dev/null; ip6tables -F 2>/dev/null

# clean any residue from a prior run
pkill -f "$AFTR" 2>/dev/null; sleep 0.5
ip link del v_b4  2>/dev/null; ip link del v_wan 2>/dev/null
ip link del tun0  2>/dev/null
ip netns del b4   2>/dev/null; ip netns del wan 2>/dev/null
sleep 0.5
ip netns add b4; ip netns add wan

# B4 carrier link (IPv6)
ip link add v_b4 type veth peer name v_b4p
ip link set v_b4p netns b4
ip addr add 2001:0:0:5::1/64 dev v_b4; ip link set v_b4 up
ip netns exec b4 ip link set lo up
ip netns exec b4 ip addr add 2001:0:0:5::2/64 dev v_b4p
ip netns exec b4 ip link set v_b4p up
ip netns exec b4 ip -6 route add default via 2001:0:0:5::1

# WAN link (IPv4). 203.0.113.1 is the shared public address subscribers share.
ip link add v_wan type veth peer name v_wanp
ip link set v_wanp netns wan
ip addr add 203.0.113.1/24 dev v_wan; ip link set v_wan up
sysctl -w net.ipv4.conf.v_wan.rp_filter=0
ip netns exec wan ip link set lo up
ip netns exec wan ip addr add 203.0.113.9/24 dev v_wanp
ip netns exec wan ip link set v_wanp up
ip netns exec wan ip route add default via 203.0.113.1

echo "############ PHASE B: ISC aftr config + launch ############"
cat > "$EV/isc.conf" <<'CONF'
address endpoint 2001::1
address icmp 198.18.200.111
pool 198.18.200.111 tcp 5000-59999
pool 198.18.200.111 udp 5000-59999
acl6 2001::/48
CONF
# NOTE: no `nat 2001:0:0:5::2 ...` line -> the attacker B4 is UNPROVISIONED.

cat > "$EV/isc-script" <<'SCR'
#!/bin/sh
case "$1" in
start)
  ip link set tun0 up
  ip addr add 10.0.100.1 peer 10.0.100.2 dev tun0
  ip route add 10.0.0.0/8 dev tun0
  ip route add 198.18.0.0/15 dev tun0
  ip -6 route add 2001::/64 dev tun0
  sysctl -w net.ipv4.conf.tun0.rp_filter=0
  # egress: userspace-NAT pool address -> shared public (ISC shareone pattern)
  iptables -t nat -F
  iptables -t nat -A POSTROUTING -s 198.18.200.111 -j SNAT --to-source 203.0.113.1
  # return: inbound to shared public high ports -> pool
  iptables -t nat -A PREROUTING -p udp -d 203.0.113.1 --dport 5000:59999 -j DNAT --to-destination 198.18.200.111
  iptables -t nat -A PREROUTING -p tcp -d 203.0.113.1 --dport 5000:59999 -j DNAT --to-destination 198.18.200.111
  ;;
stop) ip link set tun0 down ;;
esac
exit 0
SCR
chmod +x "$EV/isc-script"

# launch aftr in foreground (-g). It makes stdin a control session and calls
# FIONREAD on it, so stdin must be a pipe held open (a redirected /dev/null
# aborts). The held-open FIFO doubles as the control channel for state dumps.
mkfifo "$EV/ctl"
exec 9<>"$EV/ctl"
"$AFTR" -g -c "$EV/isc.conf" -s "$EV/isc-script" <"$EV/ctl" >"$EV/aftr.log" 2>&1 &
AFTR_PID=$!
sleep 2
echo "aftr pid=$AFTR_PID; running? $(kill -0 $AFTR_PID 2>/dev/null && echo yes || echo NO)"
echo "--- tun0 + routes after start ---"; ip -br addr show tun0; ip route | grep -E 'tun0|198.18'; ip -6 route | grep tun0
echo "--- aftr.log head ---"; head -20 "$EV/aftr.log"

echo "############ PHASE C: unprovisioned softwire relay ############"
# B4 sets up a DS-Lite softwire to the AFTR with NO provisioning of any kind
# encaplimit none => plain IPv4-in-IPv6 (next-header 4), the RFC 6333 softwire
# form. Linux's default adds an RFC 2473 encap-limit dest-option the 2010 ISC
# decapsulator rejects as DR_BAD6; a conformant DS-Lite B4 does not add it.
ip netns exec b4 ip -6 tunnel add ds1 mode ipip6 remote 2001::1 local 2001:0:0:5::2 dev v_b4p encaplimit none
ip netns exec b4 ip link set ds1 up
ip netns exec b4 ip addr add 10.0.5.2/24 dev ds1
ip netns exec b4 ip route add 203.0.113.9/32 dev ds1
echo "--- b4 softwire ---"; ip netns exec b4 ip -br addr show ds1; ip netns exec b4 ip route get 203.0.113.9

# capture on the external server side and on tun0
ip netns exec wan tcpdump -n -i v_wanp -w "$EV/wan.pcap" udp 2>/dev/null &
TCPD_WAN=$!
tcpdump -n -i tun0 -w "$EV/tun0.pcap" 2>/dev/null &
TCPD_TUN=$!
# external server UDP listener
ip netns exec wan bash -c "timeout 8 nc -u -l -p 9999 > '$EV/server_rx.txt' 2>/dev/null" &
sleep 1

echo "--- FIRING RELAY: unprovisioned B4 -> AFTR -> external server ---"
for i in 1 2 3 4 5; do
  echo "RELAY-PKT-$i-from-unprovisioned-B4" | ip netns exec b4 nc -u -w1 -p 40000 203.0.113.9 9999
  sleep 0.3
done
sleep 2
kill $TCPD_WAN $TCPD_TUN 2>/dev/null; sleep 1

echo "############ PHASE D: evidence ############"
echo "=== [1] AFTR auto-created a tunnel for the UNPROVISIONED source? (aftr.log) ==="
grep -iE 'tunnel|2001:0:0:5|auto' "$EV/aftr.log" | head -20
echo "=== [2] decapsulated+translated packet on tun0 (inner path) ==="
tcpdump -nr "$EV/tun0.pcap" 2>/dev/null | head -20
echo "=== [3] EGRESS: did the external server RECEIVE the relayed flow? ==="
echo "--- wan.pcap (as seen by the external server; src should be 203.0.113.1 shared public) ---"
tcpdump -nr "$EV/wan.pcap" 2>/dev/null | head -20
echo "--- server application payload received ---"
cat "$EV/server_rx.txt" 2>/dev/null | head
echo "=== [4] aftr NAT/tunnel state (via control channel) ==="
echo "list tunnel"  >"$EV/ctl"; sleep 0.5
echo "list nat all" >"$EV/ctl"; sleep 0.5
sleep 1
grep -iE 'tunnel|nat|2001:0:0:5|198.18.200.111|10.0.5' "$EV/aftr.log" | tail -25

kill $AFTR_PID 2>/dev/null; exec 9>&-
echo "############ DONE ############"
