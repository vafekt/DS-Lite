#!/bin/bash
# Independent cross-check of the T11/T12 isolation breaks on the Snabb lwAFTR,
# an independent RFC 7596 Lightweight-4over6 implementation (userspace, Lua/C),
# unrelated to the paper's nftables/ip6tnl emulation.
#
# Uses `snabb lwaftr check`, Snabb's own data-plane test harness: it runs input
# pcaps through the real lwAFTR data plane and writes the output pcaps. The
# binding config and the three test vectors are Snabb's own; they happen to
# model exactly the provisioned / unprovisioned / out-of-port-set cases.
#
# Usage: SNABB=/path/to/snabb/src/snabb  DATA=/path/to/lwaftr/tests/data  ./snabb_lw_xcheck.sh
set -u
SNABB=${SNABB:-/root/snabb/src/snabb}
DATA=${DATA:-/root/snabb/src/program/lwaftr/tests/data}
OUT=${OUT:-/tmp/snabb_lw_out}; mkdir -p "$OUT"
cd "$DATA" || exit 1

run() {  # name  v6-in-pcap
  local name=$1 v6in=$2
  timeout 30 "$SNABB" lwaftr check -r no_icmp.conf empty.pcap "$v6in" \
      "$OUT/$name-v4out.pcap" "$OUT/$name-v6out.pcap" "$OUT/$name-counters.lua" >/dev/null 2>&1
  local egress; egress=$(tcpdump -nr "$OUT/$name-v4out.pcap" 2>/dev/null | wc -l)
  local drop;   drop=$(grep -oE 'drop-no-source-softwire-ipv6-packets"\] = [0-9]+' "$OUT/$name-counters.lua" 2>/dev/null | grep -oE '[0-9]+$')
  printf '%-26s  egress-to-internet=%s  drop-no-source-softwire=%s\n' "$name" "${egress:-?}" "${drop:-0}"
}

echo "lwAFTR binding config: no_icmp.conf (provisions e.g. 178.79.150.233 psid 54192, b4 127:11:12:13:14:15:16:128)"
echo "--- real Snabb lwAFTR data plane, three cases ---"
run baseline_provisioned      tcp-fromb4-ipv6.pcap                 # provisioned softwire -> forwarded
run T11_unprovisioned         tcp-fromb4-ipv6-unbound.pcap         # source not in binding table -> dropped
run T12_out-of-portset        tcp-fromb4-ipv6-bound-port-unbound.pcap  # right IPv4, wrong port-set -> dropped
echo "Expected: baseline egress=1 drop=0 ; T11 egress=0 drop=1 ; T12 egress=0 drop=1"
