#!/bin/bash
# Attacks against the conformant lw4o6 stack (parallel to the DS-Lite T11/T12/T1).
# Shows RFC 7596 §5.1 binding + no-catch-all + fixed port-sets block the breaks.
set +e
PFX=2001:db8:1a06
AFTR_MAC=02:00:00:00:00:10

# Conformant lw4o6: NO catch-all decapsulator. Only per-binding tunnels.
ip netns exec lwaftr ip link set ip6tnl0 down 2>/dev/null

echo "############### T11: UNPROVISIONED softwire relay ###############"
echo "(attacker ::150 has NO binding; on DS-Lite the catch-all AFTR relays it out as the shared IPv4)"
# capture: ingress 4in6 at AFTR, and any egress as shared IPv4 on WAN
ip netns exec lwaftr sh -c 'timeout 5 tcpdump -i eth-isp -n -c 50 "ip6 proto 4 and src '"${PFX}"'::150" >/tmp/t11_in.txt 2>&1 &
                            timeout 5 tcpdump -i eth-wan -n -c 50 "ip src 198.51.100.1" >/tmp/t11_wan.txt 2>&1 &'
sleep 0.6
ip netns exec lwatk python3 - <<PY
from scapy.all import Ether,IPv6,IP,TCP,sendp
pkts=[Ether(dst="$AFTR_MAC")/IPv6(src="${PFX}::150",dst="${PFX}::10",nh=4)/IP(src="198.51.100.1",dst="203.0.113.9")/TCP(sport=5000+i,dport=80,flags="S") for i in range(20)]
sendp(pkts,iface="eth-isp",verbose=0); print("   sent 20 unprovisioned 4in6 relay attempts")
PY
sleep 4
echo "   [reached lwAFTR ingress]  nft counter of 4in6 from ::150 arriving at lwAFTR:"; ip netns exec lwaftr nft list chain ip6 lwmon ingress 2>/dev/null | grep "t11-unprov-in" | grep -oE "packets [0-9]+" | sed 's/^/     ingress_/'
echo "   [relayed to Internet?]    packets egressing WAN as shared 198.51.100.1:"; grep -c "198.51.100.1" /tmp/t11_wan.txt 2>/dev/null | sed 's/^/     egress_count=/'
echo "   ip6tnl0 (catch-all) RX packets (should be 0 = down/no decap):"; ip netns exec lwaftr sh -c 'x=$(cat /sys/class/net/ip6tnl0/statistics/rx_packets 2>/dev/null); echo "     ip6tnl0_rx=${x:-NA}"'

echo ""
echo "############### T12: identity forgery / shared-pool drain ###############"
echo "(a) forge MANY unprovisioned identities (::200..::231) -> no binding -> dropped"
ip netns exec lwaftr sh -c 'timeout 5 tcpdump -i eth-wan -n -c 100 "ip src 198.51.100.1" >/tmp/t12_wan.txt 2>&1 &'
sleep 0.5
ip netns exec lwatk python3 - <<PY
from scapy.all import Ether,IPv6,IP,TCP,sendp
pkts=[]
for j in range(32):                       # 32 forged softwire identities (::200..::21f)
  src=f"${PFX}::{0x200+j:x}"
  for i in range(30):                      # each tries 30 bindings
    pkts.append(Ether(dst="$AFTR_MAC")/IPv6(src=src,dst="${PFX}::10",nh=4)/IP(src="198.51.100.1",dst="203.0.113.9")/TCP(sport=10000+j*30+i,dport=80,flags="S"))
sendp(pkts,iface="eth-isp",verbose=0); print(f"   sent {len(pkts)} forged-identity packets across 32 fake softwires")
PY
sleep 4
echo "   [reached lwAFTR] nft counter of forged-identity 4in6 arriving:"; ip netns exec lwaftr nft list chain ip6 lwmon ingress 2>/dev/null | grep "t12-forged-in" | grep -oE "packets [0-9]+" | sed 's/^/     ingress_/'
echo "   packets egressing WAN as shared IPv4 from forged identities (expect NONE):"; grep -c "198.51.100.1" /tmp/t12_wan.txt 2>/dev/null | sed 's/^/     egress_count=/'
echo ""
echo "(b) forge a REAL binding (::101) but use inner ports OUTSIDE its set 1024-2047 -> binding validation drops"
ip netns exec lwaftr nft reset counters table ip lwaftr >/dev/null 2>&1
ip netns exec lwatk python3 - <<PY
from scapy.all import Ether,IPv6,IP,TCP,sendp
# spoof lwB4-1's identity, but source ports in 2048-3071 (lwB4-2's set) -> must be dropped by lwB4-1 binding
pkts=[Ether(dst="$AFTR_MAC")/IPv6(src="${PFX}::101",dst="${PFX}::10",nh=4)/IP(src="198.51.100.1",dst="203.0.113.9")/TCP(sport=2048+i,dport=80,flags="S") for i in range(40)]
sendp(pkts,iface="eth-isp",verbose=0); print("   sent 40 pkts spoofing ::101 with out-of-set source ports 2048-3087")
PY
sleep 2
echo "   lwAFTR binding-validation DROP counter on tnl-b41 (expect >0):"
ip netns exec lwaftr nft list chain ip lwaftr fwdval 2>/dev/null | grep "tnl-b41.*drop" | sed 's/^/     /'

echo ""
echo "############### T1: connection-flood isolation (STRUCTURAL, no flood needed) ###############"
echo "(lw4o6 confines each subscriber to a fixed disjoint port-set; one cannot consume another's)"
ip netns exec lwb41 nft list chain ip nat post 2>/dev/null | grep -oE "198.51.100.1:[0-9]+-[0-9]+" | head -1 | sed "s/^/   lwB4-1 port-set = /"
ip netns exec lwb42 nft list chain ip nat post 2>/dev/null | grep -oE "198.51.100.1:[0-9]+-[0-9]+" | head -1 | sed "s/^/   lwB4-2 port-set = /"
echo "   -> a flood from lwB4-1 exhausts only 1024 ports it already owns; lwB4-2's set is untouched by design."
echo "############### ATTACKS DONE ###############"
