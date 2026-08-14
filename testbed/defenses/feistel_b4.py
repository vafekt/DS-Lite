#!/usr/bin/python3
# feistel_b4.py — in-path deployment of Gilad-Herzberg §8.3 at the B4 gateway,
# via NFQUEUE so the rewrite happens IN PLACE on the forward path (conntrack and
# stateful TCP are preserved, unlike a sniff/re-inject bump-in-the-wire).
#
# Gilad & Herzberg, "Fragmentation Considered Vulnerable" (ACM TISSEC 2013) §8.3
# deploy the IP-ID-rewriting pseudo-random PERMUTATION "at the firewall of a
# network ... when a packet leaves the network". In DS-Lite the B4 is that
# gateway. An nft rule sends the subscriber's outbound inner-IPv4 packets (the
# ones about to be encapsulated into the softwire) to this queue; we rewrite the
# IP-ID with the keyed Feistel permutation and accept, so the value the AFTR
# reassembles on is unpredictable and the attacker can no longer plant a
# colliding fragment under the victim's reassembly four-tuple.
#
# Fragments of one datagram carry the same original ID, so remap_fixed maps them
# all to the same new ID and reassembly is preserved.
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ipid_feistel import IpIdFeistel  # noqa: E402

from netfilterqueue import NetfilterQueue  # noqa: E402
from scapy.layers.inet import IP           # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", type=int, default=0)
    ap.add_argument("--key", default=os.environ.get("FEISTEL_KEY", "ds-lite-feistel-master"))
    a = ap.parse_args()
    fe = IpIdFeistel(master_key=a.key.encode())
    stats = {"n": 0}

    def cb(pkt):
        try:
            ip = IP(pkt.get_payload())
            old = ip.id
            new = fe.remap_fixed(ip.src, ip.dst, ip.proto, old)
            if new == old:
                new = (new + 1) & 0xFFFF
            ip.id = new
            del ip.chksum                 # force IP-header checksum recompute
            pkt.set_payload(bytes(ip))     # L4 checksum does not cover IP-ID
            stats["n"] += 1
            if stats["n"] % 25 == 0:
                print(f"[feistel-b4] rewrote {stats['n']} inner-IPv4 IP-IDs",
                      flush=True)
        except Exception as e:
            print(f"[feistel-b4] rewrite error: {e}", file=sys.stderr, flush=True)
        pkt.accept()

    nfq = NetfilterQueue()
    nfq.bind(a.queue, cb)
    print(f"[feistel-b4] NFQUEUE {a.queue}: rewriting inner-IPv4 IP-ID with the "
          f"Gilad-Herzberg Feistel PRP (in-path, conntrack preserved)", flush=True)
    try:
        nfq.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfq.unbind()


if __name__ == "__main__":
    main()
