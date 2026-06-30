#!/usr/bin/python
# DS-Lite AFTR SNMP Agent – partial RFC 7870 DSLITE-MIB simulator
#
# Implements the subset of the DSLITE-MIB defined in RFC 7870 that is
# exercised by the attack corpus: the alarm-threshold scalar subtree
# (`dsliteAFTRAlarmScalar`) and the alarm-notification objects. The
# softwire tunnel table (`dsliteTunnel`), per-B4 session table, and
# port-allocation algorithm objects are NOT implemented.
#
# IANA-assigned OID:     mib-2.240 (1.3.6.1.2.1.240)
# IANA tunnel type:      dsLite(17)
#
# MIB structure (three subtrees):
#
#   dsliteMIBObjects (240.1)
#   ├── dsliteTunnel (240.1.1)          – softwire tunnel management
#   │   ├── dsliteTunnelTable (240.1.1.1)
#   │   │   └── dsliteTunnelEntry indexed by:
#   │   │       addressType(1), startAddress(2), endAddress(3), ifIndex
#   │   │       Also: startAddPreLen(4)
#   │   └── (scalar) tunnelCount
#   │
#   ├── dsliteNAT (240.1.2)            – extended NAT binding table
#   │   ├── dsliteNATBindTable (240.1.2.1)
#   │   │   └── dsliteNATBindEntry indexed by 8 fields:
#   │   │       natv2PortMapInstanceIndex, protocol, externalRealm,
#   │   │       externalAddrType, externalAddr, externalPort,
#   │   │       ifIndex, tunnelStartAddress (B4 IPv6)
#   │   │   Exposes: internalRealm, internalAddrType, internalAddress,
#   │   │       internalPort, pool, mapBehavior, filterBehavior, pooling
#   │   └── dsliteNATBindCurrentCount (240.1.2.2.0)
#   │
#   └── dsliteInfo (240.1.3)           – statistics + alarm thresholds
#       ├── dsliteAFTRAlarmScalar (240.1.3.1)   — EXACT RFC 7870 §8 order:
#       │   ├── dsliteAFTRAlarmB4AddrType        (.1) – notify identity
#       │   ├── dsliteAFTRAlarmB4Addr            (.2) – notify identity
#       │   ├── dsliteAFTRAlarmProtocolType      (.3) – notify identity
#       │   ├── dsliteAFTRAlarmSpecificIPAddrType(.4) – notify identity
#       │   ├── dsliteAFTRAlarmSpecificIP        (.5) – notify identity
#       │   ├── dsliteAFTRAlarmConnectNumber     (.6) – r/w, Integer32(60..90), DEFVAL 60
#       │   ├── dsliteAFTRAlarmSessionNumber     (.7) – r/w, Integer32, DEFVAL -1
#       │   └── dsliteAFTRAlarmPortNumber        (.8) – r/w, Integer32, DEFVAL -1
#       │
#       └── dsliteStatisticsTable (240.1.3.2)
#           └── per-subscriber: discards, sends, receives,
#               currentIPv4Sessions, currentIPv6Sessions
#
#   dsliteNotifications (240.0)
#   ├── dsliteTunnelNumAlarm          (.1) – tunnel count exceeds threshold
#   ├── dsliteAFTRUserSessionNumAlarm (.2) – user sessions exceed threshold
#   └── dsliteAFTRPortUsageOfSpecificIpAlarm (.3) – NAT port usage threshold
#
# Writable OIDs (T14 targets), per RFC 7870 §8; SYNTAX range enforced on SET:
#   1.3.6.1.2.1.240.1.3.1.6  dsliteAFTRAlarmConnectNumber  Integer32(60..90)
#   1.3.6.1.2.1.240.1.3.1.7  dsliteAFTRAlarmSessionNumber  Integer32
#   1.3.6.1.2.1.240.1.3.1.8  dsliteAFTRAlarmPortNumber     Integer32
#
# Usage (run inside AFTR namespace):
#   python3 /testbed/aftr/snmp_agent.py [--community public] [--port 161]
import argparse
import os
import socket
import struct
import subprocess
import sys
import threading
import time

COMMUNITY = 'public'
PORT = 161

# Community enforcement (RFC 7870 §7 hardening). When off (default, the
# vulnerable baseline) the agent answers any community string. When
# T12_SNMP_COMMUNITY_ENFORCE=1 it silently drops requests whose community does
# not match COMMUNITY, so a probe with the well-known "public" gets no reply.
ENFORCE_COMMUNITY = os.environ.get("T12_SNMP_COMMUNITY_ENFORCE", "0") == "1"

# ── T14/T15 defence: SNMPv3 USM authNoPriv + engineID pinning ──────────────
# Mechanism from Lawrence & Traynor et al., "Under New Management: Practical
# Attacks on SNMPv3" (USENIX WOOT 2012): authenticate every request and pin the
# snmpEngineID instead of trusting unauthenticated discovery. When T_SNMP_USM=1
# the agent ONLY accepts SNMPv3 USM messages carrying a valid HMAC-SHA-96
# msgAuthenticationParameters for the configured user, within the engineTime
# window (anti-replay); SNMPv1/v2c (the T14/T15 attack) is dropped. The engine
# identity is fixed and pinned at the manager, so discovery cannot be abused to
# choose a key. authNoPriv (no AES in the lab); auth alone blocks SET and GET.
USM_MODE = os.environ.get("T_SNMP_USM", "0") == "1"
USM_USER = os.environ.get("SNMP_USM_USER", "oamuser").encode()
USM_PASS = os.environ.get("SNMP_SECRET", "S3cr3t-oam-2026")
# Authoritative engineID (RFC 3411 SnmpEngineID): enterprise-fmt, fixed/pinned.
USM_ENGINE_ID = (b"\x80\x00\x1f\x88\x80" + b"dslite-aftr1")
USM_BOOTS = 1
_USM_START = time.time()
if USM_MODE:
    sys.path.insert(0, "/testbed/defenses")
    import snmpv3_usm as _usm
    _USM_KEY = _usm.password_to_key_sha1(USM_PASS, USM_ENGINE_ID)


def _usm_engine_time():
    # Lab simplification: use the shared host wall clock as engineTime so the
    # pinned manager and agent agree without a discovery round-trip (the paper's
    # fix is to NOT trust discovery). The ±150s window still gives anti-replay.
    return int(time.time()) & 0x7FFFFFFF


def handle_usm_message(data):
    """SNMPv3 USM authNoPriv path. Returns authenticated response or None."""
    p = _usm.parse_usm_message(data)
    if not p or p.get("version") != 3:
        return None                       # drop v1/v2c (the attack)
    if (p["flags"] & _usm.MSG_FLAG_AUTH) == 0:
        return None                       # unauthenticated: pinned, no discovery
    if p["user"] != USM_USER:
        return None                       # unknown principal
    if p["engine_id"] != USM_ENGINE_ID:
        return None                       # engineID pinning
    if not _usm.verify_auth(data, p, _USM_KEY):
        print(f"[SNMP USM] auth FAIL user={p['user'].decode(errors='replace')}",
              file=sys.stderr)
        return None                       # bad HMAC: forged/no key
    if abs(_usm_engine_time() - p["engine_time"]) > 150:
        return None                       # outside timeliness window (replay)
    # unwrap scoped PDU: SEQUENCE { ctxEngineID, ctxName, PDU }
    try:
        st, sval, svoff, _ = _usm.rd_tlv(p["scoped_pdu"], 0)
        o = svoff
        t, _ceid, _, o = _usm.rd_tlv(p["scoped_pdu"], o)
        t, _cname, _, o = _usm.rd_tlv(p["scoped_pdu"], o)
        pdu_tag = p["scoped_pdu"][o]
        _, pdu_data, _, _ = _usm.rd_tlv(p["scoped_pdu"], o)
    except Exception:
        return None
    response_pdu = process_pdu(pdu_tag, pdu_data,
                               principal=f"usm-user={p['user'].decode()}")
    if response_pdu is None:
        return None
    scoped = _usm.build_scoped_pdu(USM_ENGINE_ID, response_pdu)
    return _usm.build_usm_message(p["msg_id"], USM_ENGINE_ID, USM_BOOTS,
                                  _usm_engine_time(), p["user"], _USM_KEY,
                                  scoped, reportable=False)

# ── OID definitions (RFC 7870, IANA mib-2.240) ──────────────────────────

OID_BASE = (1, 3, 6, 1, 2, 1, 240)

# dsliteTunnel subtree (.1.1)
OID_TUNNEL_TABLE  = OID_BASE + (1, 1, 1)      # dsliteTunnelTable (RFC 7870)
# NON-STANDARD vendor extension: RFC 7870 does not define a tunnel-count scalar
# (counts are meant to come from the tables / dsliteStatisticsTable). Kept here
# under an unused sub-OID for the lab's monitor_nat.sh convenience only.
OID_TUNNEL_COUNT  = OID_BASE + (1, 1, 2, 0)

# dsliteNAT subtree (.1.2)
OID_NAT_BIND_TABLE = OID_BASE + (1, 2, 1)     # dsliteNATBindTable (RFC 7870)
# NON-STANDARD vendor extension (see note above): current binding count scalar.
OID_NAT_BIND_COUNT = OID_BASE + (1, 2, 2, 0)

# dsliteInfo subtree (.1.3)
# dsliteAFTRAlarmScalar (.1.3.1) — EXACT RFC 7870 §8 column order:
OID_ALARM_B4_ADDR_TYPE = OID_BASE + (1, 3, 1, 1)  # dsliteAFTRAlarmB4AddrType   (notify)
OID_ALARM_B4_ADDR      = OID_BASE + (1, 3, 1, 2)  # dsliteAFTRAlarmB4Addr       (notify)
OID_ALARM_PROTO_TYPE   = OID_BASE + (1, 3, 1, 3)  # dsliteAFTRAlarmProtocolType (notify)
OID_ALARM_SPEC_IP_TYPE = OID_BASE + (1, 3, 1, 4)  # dsliteAFTRAlarmSpecificIPAddrType (notify)
OID_ALARM_SPECIFIC_IP  = OID_BASE + (1, 3, 1, 5)  # dsliteAFTRAlarmSpecificIP   (notify)
OID_ALARM_CONNECT_NUM  = OID_BASE + (1, 3, 1, 6)  # dsliteAFTRAlarmConnectNumber (r/w, Integer32 60..90, DEFVAL 60)
OID_ALARM_SESSION_NUM  = OID_BASE + (1, 3, 1, 7)  # dsliteAFTRAlarmSessionNumber (r/w, Integer32, DEFVAL -1)
OID_ALARM_PORT_NUM     = OID_BASE + (1, 3, 1, 8)  # dsliteAFTRAlarmPortNumber    (r/w, Integer32, DEFVAL -1)

# dsliteStatisticsTable (.1.3.2) — RFC 7870
OID_STATS_TABLE = OID_BASE + (1, 3, 2)

# dsliteNotifications (.0)
OID_NOTIF_TUNNEL_NUM   = OID_BASE + (0, 1)  # dsliteTunnelNumAlarm
OID_NOTIF_SESSION_NUM  = OID_BASE + (0, 2)  # dsliteAFTRUserSessionNumAlarm
OID_NOTIF_PORT_USAGE   = OID_BASE + (0, 3)  # dsliteAFTRPortUsageOfSpecificIpAlarm

# ── Mutable alarm thresholds (RFC 7870 §8 — T14 attack targets) ─────────
# RFC 7870 defines each object's SYNTAX exactly:
#   dsliteAFTRAlarmConnectNumber  Integer32 (60..90)  DEFVAL 60
#   dsliteAFTRAlarmSessionNumber  Integer32           DEFVAL -1
#   dsliteAFTRAlarmPortNumber     Integer32           DEFVAL -1
# A conformant agent MUST enforce the SYNTAX range on SET (see THRESHOLD_RANGE);
# a write outside it is rejected with wrongValue.
thresholds = {
    OID_ALARM_CONNECT_NUM: 60,
    OID_ALARM_SESSION_NUM: -1,
    OID_ALARM_PORT_NUM:    -1,
}
# (lo, hi) inclusive SYNTAX bounds per RFC 7870 §8.
THRESHOLD_RANGE = {
    OID_ALARM_CONNECT_NUM: (60, 90),            # Integer32 (60..90)
    OID_ALARM_SESSION_NUM: (-1, 0x7FFFFFFF),    # Integer32, -1 = disabled
    OID_ALARM_PORT_NUM:    (-1, 0x7FFFFFFF),    # Integer32, -1 = disabled
}
threshold_lock = threading.Lock()

# Alarm identity objects (accessible-for-notify; populated when an alarm fires)
alarm_identity = {
    OID_ALARM_B4_ADDR_TYPE: 2,          # InetAddressType ipv6(2)
    OID_ALARM_B4_ADDR:      '::',
    OID_ALARM_PROTO_TYPE:   0,          # tcp(0)
    OID_ALARM_SPEC_IP_TYPE: 1,          # InetAddressType ipv4(1)
    OID_ALARM_SPECIFIC_IP:  '0.0.0.0',
}
alarm_lock = threading.Lock()

# Statistics counters (per-subscriber aggregated)
statistics = {
    'discards': 0,
    'sends': 0,
    'receives': 0,
    'ipv4_sessions': 0,
    'ipv6_sessions': 0,
}
stats_lock = threading.Lock()


# ── BER/DER encoding helpers ─────────────────────────────────────────────

def ber_length(n):
    if n < 128:
        return bytes([n])
    elif n < 256:
        return bytes([0x81, n])
    else:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def ber_tlv(tag, value_bytes):
    return bytes([tag]) + ber_length(len(value_bytes)) + value_bytes


def encode_int(n):
    if n == 0:
        return ber_tlv(0x02, b'\x00')
    # Handle negative numbers (for -1 default thresholds)
    if n < 0:
        n = n & 0xFFFFFFFF  # treat as unsigned for BER encoding
    result = []
    while n:
        result.append(n & 0xFF)
        n >>= 8
    result.reverse()
    if result[0] & 0x80:
        result.insert(0, 0)
    return ber_tlv(0x02, bytes(result))


def encode_signed_int(n):
    """Encode a signed 32-bit integer for BER."""
    raw = struct.pack('!i', n)
    # Strip leading 0x00 or 0xFF bytes that are redundant
    # Keep at least one byte
    i = 0
    while i < len(raw) - 1:
        if raw[i] == 0x00 and not (raw[i+1] & 0x80):
            i += 1
        elif raw[i] == 0xFF and (raw[i+1] & 0x80):
            i += 1
        else:
            break
    return ber_tlv(0x02, raw[i:])


def encode_string(s):
    if isinstance(s, str):
        s = s.encode()
    return ber_tlv(0x04, s)


def encode_oid(oid_tuple):
    """Encode OID tuple to BER."""
    if len(oid_tuple) < 2:
        return ber_tlv(0x06, b'\x00')
    result = bytes([oid_tuple[0] * 40 + oid_tuple[1]])
    for val in oid_tuple[2:]:
        if val < 128:
            result += bytes([val])
        else:
            encoded = []
            encoded.append(val & 0x7F)
            val >>= 7
            while val:
                encoded.append((val & 0x7F) | 0x80)
                val >>= 7
            encoded.reverse()
            result += bytes(encoded)
    return ber_tlv(0x06, result)


def decode_oid(data, offset, length):
    """Decode BER OID bytes to tuple."""
    end = offset + length
    if offset >= end:
        return ()
    first = data[offset]
    result = [first // 40, first % 40]
    offset += 1
    val = 0
    while offset < end:
        b = data[offset]
        offset += 1
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            result.append(val)
            val = 0
    return tuple(result)


def decode_tlv(data, offset=0):
    """Decode BER TLV at offset. Returns (tag, value_bytes, next_offset)."""
    if offset >= len(data):
        return None, b'', offset
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        return tag, b'', offset
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        num_len_bytes = length_byte & 0x7F
        length = int.from_bytes(data[offset:offset+num_len_bytes], 'big')
        offset += num_len_bytes
    else:
        length = length_byte
    value = data[offset:offset+length]
    return tag, value, offset + length


# ── Live MIB data from kernel ────────────────────────────────────────────

def get_tunnel_entries():
    """Read active DS-Lite tunnels from the kernel.
    Returns list of dicts with RFC 7870 dsliteTunnelEntry fields:
      addressType(1)=ipv6(2), startAddress(2)=B4 IPv6,
      endAddress(3)=AFTR IPv6, startAddPreLen(4)
    """
    entries = []
    try:
        out = subprocess.check_output(
            ['ip', '-6', 'tunnel', 'show'],
            stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            if 'ip6tnl' not in line.lower() and 'ipip6' not in line.lower():
                continue
            parts = line.split()
            name = parts[0].rstrip(':')
            remote = '::'
            local = '::'
            for i, p in enumerate(parts):
                if p == 'remote' and i + 1 < len(parts):
                    remote = parts[i+1]
                if p == 'local' and i + 1 < len(parts):
                    local = parts[i+1]
            # In DS-Lite: startAddress = remote B4 IPv6, endAddress = local AFTR IPv6
            # For the wildcard tunnel (ds-lite-open), remote = ::
            entries.append({
                'name': name,
                'addressType': 2,         # ipv6(2)
                'startAddress': remote,   # B4 IPv6 (:: for wildcard)
                'endAddress': local,      # AFTR IPv6
                'startAddPreLen': 128,    # /128 — each B4 tunnel endpoint is a host route (RFC 7870 dsliteTunnelStartAddrPrefixLength)
                'encapsMethod': 17,       # dsLite(17) IANAtunnelType
                'ifIndex': len(entries) + 1,
            })
    except Exception:
        entries.append({
            'name': 'ds-lite-open',
            'addressType': 2,
            'startAddress': '::',
            'endAddress': '::',
            'startAddPreLen': 128,
            'encapsMethod': 17,
            'ifIndex': 1,
        })
    return entries


def get_nat_bind_count():
    """Get current conntrack entry count (= dsliteNATBindCurrentCount)."""
    try:
        out = subprocess.check_output(
            ['conntrack', '-C'],
            stderr=subprocess.DEVNULL, text=True
        )
        return int(out.strip())
    except Exception:
        return 0


def get_nat_bindings():
    """Read active NAT bindings from conntrack.
    Returns list of dicts modelling dsliteNATBindEntry fields:
      protocol, externalAddr, externalPort,
      internalAddr (B4 IPv6 tunnel src), internalPort,
      mapBehavior, filterBehavior, addressPooling
    """
    bindings = []
    try:
        out = subprocess.check_output(
            ['conntrack', '-L', '-o', 'extended'],
            stderr=subprocess.DEVNULL, text=True
        )
        # The DSLITE-MIB NAT-binding table models DS-Lite SUBSCRIBER sessions, not
        # the AFTR's own OAM-plane traffic. Exclude the management network
        # (10.99.0.0/24) so the table reflects real subscriber bindings and the
        # agent's own SNMP queries don't crowd out subscriber rows under the cap.
        sub_lines = [l for l in out.splitlines() if '10.99.0.' not in l]
        for line in sub_lines[:200]:
            fields = {}
            parts = line.split()
            if len(parts) < 2:
                continue
            # Protocol
            proto_name = parts[0]
            proto_num = int(parts[1]) if parts[1].isdigit() else 0
            # Parse key=value pairs
            for p in parts:
                if '=' in p:
                    k, v = p.split('=', 1)
                    # First occurrence = original direction
                    if k not in fields:
                        fields[k] = v

            # Find reply direction (second src/dst)
            reply_fields = {}
            seen_src = 0
            for p in parts:
                if '=' in p:
                    k, v = p.split('=', 1)
                    if k == 'src':
                        seen_src += 1
                        if seen_src == 2:
                            reply_fields['src'] = v
                    elif k == 'dst' and seen_src >= 2:
                        reply_fields['dst'] = v
                    elif k == 'sport' and seen_src >= 2:
                        reply_fields['sport'] = v
                    elif k == 'dport' and seen_src >= 2:
                        reply_fields['dport'] = v

            bindings.append({
                'protocol': proto_num,
                'protocolName': proto_name,
                'internalAddress': fields.get('src', '?'),
                'internalPort': int(fields.get('sport', 0)),
                'externalAddress': reply_fields.get('dst', fields.get('dst', '?')),
                'externalPort': int(reply_fields.get('dport', fields.get('dport', 0))),
                'destinationAddress': fields.get('dst', '?'),
                'destinationPort': int(fields.get('dport', 0)),
                # RFC 7870 NAT behavior fields
                'mapBehavior': 1,       # endpointIndependent(1)
                'filterBehavior': 3,    # addressAndPortDependent(3)
                'addressPooling': 2,    # paired(2)
                'raw': line[:240],
            })
    except Exception:
        pass
    return bindings


def get_statistics():
    """Read interface statistics for the DS-Lite tunnel.
    Maps to dsliteStatisticsTable Counter64 objects:
      discards, sends, receives, IPv4Sessions, IPv6Sessions
    """
    result = {
        'discards': 0,
        'sends': 0,
        'receives': 0,
        'ipv4Sessions': 0,
        'ipv6Sessions': 0,
    }
    try:
        # Read tunnel interface statistics
        out = subprocess.check_output(
            ['ip', '-s', 'link', 'show', 'ds-lite-open'],
            stderr=subprocess.DEVNULL, text=True
        )
        lines = out.splitlines()
        for i, line in enumerate(lines):
            parts = line.strip().split()
            if 'RX:' in line and i + 1 < len(lines):
                rx_parts = lines[i+1].strip().split()
                if rx_parts:
                    result['receives'] = int(rx_parts[1]) if len(rx_parts) > 1 else 0
                    result['discards'] = int(rx_parts[3]) if len(rx_parts) > 3 else 0
            if 'TX:' in line and i + 1 < len(lines):
                tx_parts = lines[i+1].strip().split()
                if tx_parts:
                    result['sends'] = int(tx_parts[1]) if len(tx_parts) > 1 else 0
    except Exception:
        pass

    # Session counts from conntrack
    try:
        out = subprocess.check_output(
            ['conntrack', '-C'],
            stderr=subprocess.DEVNULL, text=True
        )
        result['ipv4Sessions'] = int(out.strip())
    except Exception:
        pass

    # IPv6 tunnel count
    tunnels = get_tunnel_entries()
    result['ipv6Sessions'] = len(tunnels)

    return result


# ── MIB value lookup ──────────────────────────────────────────────────────

def get_mib_value(oid):
    """Return (type_tag, value_bytes) for a given OID, or (None, None) if not found."""

    # ── System MIB objects ────────────────────────────────────────────

    # sysDescr: 1.3.6.1.2.1.1.1.0
    if oid == (1, 3, 6, 1, 2, 1, 1, 1, 0):
        desc = b'DS-Lite AFTR - RFC 6333 / RFC 7870 DSLITE-MIB (mib-2.240)'
        return 0x04, desc

    # sysUpTime: 1.3.6.1.2.1.1.3.0
    if oid == (1, 3, 6, 1, 2, 1, 1, 3, 0):
        uptime = int(time.time() * 100) % (2**32)
        return 0x43, struct.pack('!I', uptime)  # TimeTicks

    # ── dsliteTunnel subtree (.1.1) ───────────────────────────────────

    # dsliteTunnelCount scalar
    if oid == OID_TUNNEL_COUNT:
        count = len(get_tunnel_entries())
        return 0x02, struct.pack('!I', count)

    # dsliteTunnelTable entries: .240.1.1.1.col.row
    if (len(oid) >= len(OID_TUNNEL_TABLE) + 2 and
            oid[:len(OID_TUNNEL_TABLE)] == OID_TUNNEL_TABLE):
        tunnels = get_tunnel_entries()
        col = oid[len(OID_TUNNEL_TABLE)]
        row = oid[len(OID_TUNNEL_TABLE) + 1] - 1
        if 0 <= row < len(tunnels):
            entry = tunnels[row]
            if col == 1:    # dsliteTunnelAddressType (ipv6=2)
                return 0x02, struct.pack('!I', entry['addressType'])
            elif col == 2:  # dsliteTunnelStartAddress (B4 IPv6)
                return 0x04, entry['startAddress'].encode()
            elif col == 3:  # dsliteTunnelEndAddress (AFTR IPv6)
                return 0x04, entry['endAddress'].encode()
            elif col == 4:  # dsliteTunnelStartAddPreLen
                return 0x02, struct.pack('!I', entry['startAddPreLen'])
            elif col == 5:  # tunnel name (ifDescr equivalent)
                return 0x04, entry['name'].encode()
            elif col == 6:  # tunnelIfEncapsMethod = dsLite(17)
                return 0x02, struct.pack('!I', entry['encapsMethod'])
        return None, None

    # ── dsliteNAT subtree (.1.2) ──────────────────────────────────────

    # dsliteNATBindCurrentCount scalar
    if oid == OID_NAT_BIND_COUNT:
        count = get_nat_bind_count()
        return 0x02, struct.pack('!I', count)

    # dsliteNATBindTable entries: .240.1.2.1.col.row
    if (len(oid) >= len(OID_NAT_BIND_TABLE) + 2 and
            oid[:len(OID_NAT_BIND_TABLE)] == OID_NAT_BIND_TABLE):
        bindings = get_nat_bindings()
        col = oid[len(OID_NAT_BIND_TABLE)]
        row = oid[len(OID_NAT_BIND_TABLE) + 1] - 1
        if 0 <= row < len(bindings):
            entry = bindings[row]
            if col == 1:    # protocol
                return 0x02, struct.pack('!I', entry['protocol'])
            elif col == 2:  # externalAddress
                return 0x04, entry['externalAddress'].encode()
            elif col == 3:  # externalPort
                return 0x02, struct.pack('!I', entry['externalPort'])
            elif col == 4:  # internalAddress (subscriber private IPv4)
                return 0x04, entry['internalAddress'].encode()
            elif col == 5:  # internalPort
                return 0x02, struct.pack('!I', entry['internalPort'])
            elif col == 6:  # destinationAddress (remote server)
                return 0x04, entry['destinationAddress'].encode()
            elif col == 7:  # destinationPort
                return 0x02, struct.pack('!I', entry['destinationPort'])
            elif col == 8:  # mapBehavior: endpointIndependent(1)
                return 0x02, struct.pack('!I', entry['mapBehavior'])
            elif col == 9:  # filterBehavior: addressAndPortDependent(3)
                return 0x02, struct.pack('!I', entry['filterBehavior'])
            elif col == 10: # addressPooling: paired(2)
                return 0x02, struct.pack('!I', entry['addressPooling'])
            elif col == 11: # raw conntrack line
                return 0x04, entry['raw'].encode()
        return None, None

    # ── dsliteInfo subtree (.1.3) ─────────────────────────────────────

    # dsliteAFTRAlarmScalar writable thresholds
    if oid in thresholds:
        with threshold_lock:
            val = thresholds[oid]
        if val < 0:
            return 0x02, struct.pack('!i', val)  # signed for -1
        return 0x02, struct.pack('!I', val)

    # Alarm identity objects (accessible-for-notify; readable here)
    if oid == OID_ALARM_B4_ADDR_TYPE:
        with alarm_lock:
            return 0x02, struct.pack('!I', alarm_identity[OID_ALARM_B4_ADDR_TYPE])
    if oid == OID_ALARM_B4_ADDR:
        with alarm_lock:
            return 0x04, alarm_identity[OID_ALARM_B4_ADDR].encode()
    if oid == OID_ALARM_PROTO_TYPE:
        with alarm_lock:
            return 0x02, struct.pack('!I', alarm_identity[OID_ALARM_PROTO_TYPE])
    if oid == OID_ALARM_SPEC_IP_TYPE:
        with alarm_lock:
            return 0x02, struct.pack('!I', alarm_identity[OID_ALARM_SPEC_IP_TYPE])
    if oid == OID_ALARM_SPECIFIC_IP:
        with alarm_lock:
            return 0x04, alarm_identity[OID_ALARM_SPECIFIC_IP].encode()

    # dsliteStatisticsTable: .240.1.3.2.col.0
    if (len(oid) >= len(OID_STATS_TABLE) + 1 and
            oid[:len(OID_STATS_TABLE)] == OID_STATS_TABLE):
        st = get_statistics()
        col = oid[len(OID_STATS_TABLE)]
        # RFC 7870 dsliteStatisticsTable columns 1..5 are SYNTAX Counter64.
        # ASN.1 tag for Counter64 is APPLICATION-6 = 0x46; value is a
        # big-endian unsigned integer (1..8 octets); we always emit 8.
        if col == 1:
            return 0x46, struct.pack('!Q', st['discards'])
        elif col == 2:
            return 0x46, struct.pack('!Q', st['sends'])
        elif col == 3:
            return 0x46, struct.pack('!Q', st['receives'])
        elif col == 4:
            return 0x46, struct.pack('!Q', st['ipv4Sessions'])
        elif col == 5:
            return 0x46, struct.pack('!Q', st['ipv6Sessions'])
        return None, None

    return None, None


# ── Alarm monitoring thread ──────────────────────────────────────────────

def alarm_monitor():
    """Background thread: check thresholds and log when exceeded.
    This simulates the three RFC 7870 SNMP notifications:
      dsliteTunnelNumAlarm, dsliteAFTRUserSessionNumAlarm,
      dsliteAFTRPortUsageOfSpecificIpAlarm
    """
    while True:
        time.sleep(10)
        try:
            with threshold_lock:
                connect_thresh = thresholds[OID_ALARM_CONNECT_NUM]
                session_thresh = thresholds[OID_ALARM_SESSION_NUM]
                port_thresh = thresholds[OID_ALARM_PORT_NUM]

            tunnel_count = len(get_tunnel_entries())
            bind_count = get_nat_bind_count()

            # dsliteTunnelNumAlarm
            if connect_thresh >= 0 and tunnel_count > connect_thresh:
                with alarm_lock:
                    alarm_identity[OID_ALARM_PROTO_TYPE] = 0
                print(f"[ALARM] dsliteTunnelNumAlarm: tunnels={tunnel_count} > "
                      f"threshold={connect_thresh}")

            # dsliteAFTRUserSessionNumAlarm
            if session_thresh >= 0 and bind_count > session_thresh:
                print(f"[ALARM] dsliteAFTRUserSessionNumAlarm: sessions={bind_count} > "
                      f"threshold={session_thresh}")

            # dsliteAFTRPortUsageOfSpecificIpAlarm
            if port_thresh >= 0:
                # Count unique SNAT ports per external IP
                bindings = get_nat_bindings()
                port_counts = {}
                for b in bindings:
                    ext_ip = b['externalAddress']
                    port_counts[ext_ip] = port_counts.get(ext_ip, 0) + 1
                for ip, count in port_counts.items():
                    if count > port_thresh:
                        with alarm_lock:
                            alarm_identity[OID_ALARM_SPECIFIC_IP] = ip
                        print(f"[ALARM] dsliteAFTRPortUsageOfSpecificIpAlarm: "
                              f"IP={ip} ports={count} > threshold={port_thresh}")

        except Exception as e:
            print(f"[ALARM] Monitor error: {e}", file=sys.stderr)


# ── SNMP PDU building helpers ────────────────────────────────────────────

def build_varbind(oid, value_tag, value_bytes):
    """Build an SNMP varbind (OID + value)."""
    oid_bytes = encode_oid(oid)
    val_tlv = ber_tlv(value_tag, value_bytes)
    return ber_tlv(0x30, oid_bytes + val_tlv)


def build_error_varbind(oid):
    """Build a varbind with noSuchObject."""
    oid_bytes = encode_oid(oid)
    null = ber_tlv(0x05, b'')
    return ber_tlv(0x30, oid_bytes + null)


def build_endofmibview_varbind(oid):
    """SNMPv2 endOfMibView exception (context tag 0x82): a walk ran off the end."""
    oid_bytes = encode_oid(oid)
    eom = ber_tlv(0x82, b'')
    return ber_tlv(0x30, oid_bytes + eom)


def enumerate_leaf_oids():
    """Lexicographically ordered list of every leaf OID the agent serves.

    Rebuilt per request because the tunnel and NAT-binding tables track live
    kernel state, so the walkable set grows and shrinks with the conntrack
    table. Sorting OID tuples yields the standard SNMP column-major table walk
    (.table.col.row ascending gives all rows of column 1, then column 2, ...).
    """
    oids = [
        (1, 3, 6, 1, 2, 1, 1, 1, 0),   # sysDescr.0
        (1, 3, 6, 1, 2, 1, 1, 3, 0),   # sysUpTime.0
    ]
    n_tun = len(get_tunnel_entries())
    for col in range(1, 7):                       # dsliteTunnelTable columns 1..6
        for row in range(1, n_tun + 1):
            oids.append(OID_TUNNEL_TABLE + (col, row))
    oids.append(OID_TUNNEL_COUNT)                 # .1.1.2.0
    n_bind = len(get_nat_bindings())
    for col in range(1, 12):                      # dsliteNATBindTable columns 1..11
        for row in range(1, n_bind + 1):
            oids.append(OID_NAT_BIND_TABLE + (col, row))
    oids.append(OID_NAT_BIND_COUNT)               # .1.2.2.0
    for o in (OID_ALARM_B4_ADDR_TYPE, OID_ALARM_B4_ADDR, OID_ALARM_PROTO_TYPE,
              OID_ALARM_SPEC_IP_TYPE, OID_ALARM_SPECIFIC_IP,
              OID_ALARM_CONNECT_NUM, OID_ALARM_SESSION_NUM, OID_ALARM_PORT_NUM):
        oids.append(o)
    for col in range(1, 6):                       # dsliteStatisticsTable columns 1..5
        oids.append(OID_STATS_TABLE + (col, 0))
    return sorted(set(oids))


def get_next_oid(oid):
    """GETNEXT: the first served OID strictly greater than `oid`, with its value.

    Returns (next_oid, type_tag, value_bytes), or (None, None, None) at end-of-MIB.
    """
    for cand in enumerate_leaf_oids():
        if cand > oid:
            vtype, vval = get_mib_value(cand)
            if vtype is not None:
                return cand, vtype, vval
    return None, None, None


# ── SNMP PDU handler ──────────────────────────────────────────────────────

def process_pdu(pdu_tag, pdu_data, principal="community=public"):
    """Process a request PDU (GET/GETNEXT/GETBULK/SET) and return the response
    PDU bytes (0xA2 GetResponse), independent of the SNMP message wrapper.
    Shared by the SNMPv2c path (handle_snmp_pdu) and the SNMPv3 USM path
    (handle_usm_message). `principal` is only used in the SET audit log."""
    try:
        # 0xA0=GetRequest, 0xA1=GetNextRequest, 0xA5=GetBulkRequest, 0xA3=SetRequest
        if pdu_tag not in (0xA0, 0xA1, 0xA5, 0xA3):
            return None

        pdu_offset = 0
        # Request ID
        tag, req_id_bytes, pdu_offset = decode_tlv(pdu_data, pdu_offset)
        req_id = int.from_bytes(req_id_bytes, 'big') if req_id_bytes else 0

        # Error status / non-repeaters
        tag, err_bytes, pdu_offset = decode_tlv(pdu_data, pdu_offset)
        # Error index / max-repetitions
        tag, erridx_bytes, pdu_offset = decode_tlv(pdu_data, pdu_offset)

        # Varbind list
        tag, vblist_bytes, _ = decode_tlv(pdu_data, pdu_offset)

        response_varbinds = b''
        error_status = 0
        error_index = 0

        # Parse each varbind
        vb_offset = 0
        vb_index = 0
        while vb_offset < len(vblist_bytes):
            tag, vb_data, vb_offset = decode_tlv(vblist_bytes, vb_offset)
            if tag != 0x30:
                break
            vb_offset2 = 0
            oid_tag, oid_bytes, vb_offset2 = decode_tlv(vb_data, vb_offset2)
            if oid_tag != 0x06:
                break
            oid = decode_oid(oid_bytes, 0, len(oid_bytes))
            val_tag, val_bytes, _ = decode_tlv(vb_data, vb_offset2)
            vb_index += 1

            if pdu_tag == 0xA3:  # SetRequest
                # Only the three read-write alarm thresholds are writable.
                if oid in thresholds:
                    try:
                        new_val = int.from_bytes(val_bytes, 'big', signed=False)
                        # Handle signed values (for -1)
                        if new_val > 0x7FFFFFFF:
                            new_val = new_val - 0x100000000
                        lo, hi = THRESHOLD_RANGE.get(oid, (-0x80000000, 0x7FFFFFFF))
                        if new_val < lo or new_val > hi:
                            # RFC 7870 SYNTAX range violation -> wrongValue(10).
                            oid_str = '.'.join(map(str, oid))
                            print(f"[SNMP SET] REJECTED {oid_str} = {new_val} "
                                  f"(out of RFC 7870 range {lo}..{hi}) ({principal})")
                            error_status = 10  # wrongValue
                            error_index = vb_index
                            response_varbinds += build_error_varbind(oid)
                        else:
                            with threshold_lock:
                                old_val = thresholds[oid]
                                thresholds[oid] = new_val
                            oid_str = '.'.join(map(str, oid))
                            print(f"[SNMP SET] {oid_str}  {old_val} → {new_val} "
                                  f"({principal})")
                            response_varbinds += build_varbind(oid, 0x02, val_bytes)
                    except Exception:
                        error_status = 17  # notWritable
                        error_index = vb_index
                        response_varbinds += build_error_varbind(oid)
                else:
                    error_status = 17  # notWritable
                    error_index = vb_index
                    response_varbinds += build_error_varbind(oid)
            elif pdu_tag == 0xA1:  # GetNextRequest (snmpwalk / snmpgetnext)
                next_oid, vtype, vval = get_next_oid(oid)
                if next_oid is not None:
                    response_varbinds += build_varbind(next_oid, vtype, vval)
                else:
                    response_varbinds += build_endofmibview_varbind(oid)

            elif pdu_tag == 0xA5:  # GetBulkRequest (snmpbulkwalk)
                # In a GETBULK PDU the error-index field carries max-repetitions;
                # walk forward from this varbind that many times. The common
                # bulk-walk case sends a single varbind, which this handles
                # exactly; multi-varbind bulk requests are expanded per varbind.
                max_rep = int.from_bytes(erridx_bytes, 'big') if erridx_bytes else 1
                cur = oid
                for _ in range(max(1, max_rep)):
                    next_oid, vtype, vval = get_next_oid(cur)
                    if next_oid is None:
                        response_varbinds += build_endofmibview_varbind(cur)
                        break
                    response_varbinds += build_varbind(next_oid, vtype, vval)
                    cur = next_oid

            else:  # 0xA0 GetRequest
                vtype, vvalue = get_mib_value(oid)
                if vtype is not None:
                    response_varbinds += build_varbind(oid, vtype, vvalue)
                else:
                    response_varbinds += build_error_varbind(oid)

        # Build response PDU (0xA2 = GetResponse)
        req_id_tlv = encode_int(req_id)
        err_tlv = encode_int(error_status)
        erridx_tlv = encode_int(error_index)
        vblist_tlv = ber_tlv(0x30, response_varbinds)
        pdu_body = req_id_tlv + err_tlv + erridx_tlv + vblist_tlv
        return ber_tlv(0xA2, pdu_body)

    except Exception as e:
        print(f"[SNMP] PDU error: {e}", file=sys.stderr)
        return None


def handle_snmp_pdu(data):
    """SNMPv1/v2c path: parse community message, return response bytes or None."""
    try:
        tag, outer, _ = decode_tlv(data, 0)
        if tag != 0x30:
            return None
        offset = 0
        tag, version_bytes, offset = decode_tlv(outer, offset)
        version = int.from_bytes(version_bytes, 'big') if version_bytes else 0
        tag, community_bytes, offset = decode_tlv(outer, offset)
        community = community_bytes.decode(errors='replace')
        if ENFORCE_COMMUNITY and community != COMMUNITY:
            return None   # wrong credential: drop silently (no information leak)
        pdu_tag, pdu_data, _ = decode_tlv(outer, offset)
        response_pdu = process_pdu(pdu_tag, pdu_data,
                                   principal=f"community={community}")
        if response_pdu is None:
            return None
        version_tlv = encode_int(version)
        community_tlv = encode_string(community)
        return ber_tlv(0x30, version_tlv + community_tlv + response_pdu)
    except Exception as e:
        print(f"[SNMP] Parse error: {e}", file=sys.stderr)
        return None


# ── server loop ───────────────────────────────────────────────────────────

def run_server(host, port, community):
    global COMMUNITY
    COMMUNITY = community

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    print(f"[SNMP] DS-Lite AFTR SNMP agent listening on {host}:{port}")
    print(f"[SNMP] Community: {community} (SNMPv2c – NOT RECOMMENDED per RFC 7870 §7)")
    print(f"[SNMP] MIB: DSLITE-MIB (IANA mib-2.240 = OID 1.3.6.1.2.1.240)")
    print(f"[SNMP] Tunnel encapsulation type: dsLite(17)")
    print(f"[SNMP]")
    print(f"[SNMP] Writable alarm thresholds (RFC 7870 §4 – T13 targets):")
    thresh_names = {
        OID_ALARM_CONNECT_NUM: 'dsliteAFTRAlarmConnectNumber',
        OID_ALARM_SESSION_NUM: 'dsliteAFTRAlarmSessionNumber',
        OID_ALARM_PORT_NUM:    'dsliteAFTRAlarmPortNumber',
    }
    for oid, val in thresholds.items():
        name = thresh_names.get(oid, '?')
        print(f"[SNMP]   {'.'.join(map(str, oid))} ({name}) = {val}")
    print(f"[SNMP]")
    print(f"[SNMP] Notifications monitored:")
    print(f"[SNMP]   dsliteTunnelNumAlarm (tunnel count > {thresholds[OID_ALARM_CONNECT_NUM]})")
    print(f"[SNMP]   dsliteAFTRUserSessionNumAlarm (sessions > {thresholds[OID_ALARM_SESSION_NUM]})")
    print(f"[SNMP]   dsliteAFTRPortUsageOfSpecificIpAlarm (ports > {thresholds[OID_ALARM_PORT_NUM]})")
    print()

    # Start alarm monitoring thread
    alarm_thread = threading.Thread(target=alarm_monitor, daemon=True)
    alarm_thread.start()

    if USM_MODE:
        print(f"[SNMP] USM authNoPriv ENFORCED (user={USM_USER.decode()}, "
              f"engineID pinned); SNMPv1/v2c dropped (Under New Management, WOOT'12)")
    while True:
        try:
            data, addr = s.recvfrom(65535)
            response = handle_usm_message(data) if USM_MODE else handle_snmp_pdu(data)
            if response:
                s.sendto(response, addr)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[SNMP] Error: {e}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(
        description='DS-Lite AFTR SNMP Agent – RFC 7870 DSLITE-MIB simulator\n'
                    'IANA OID: mib-2.240 (1.3.6.1.2.1.240)\n'
                    'Tunnel type: dsLite(17)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('--host', default='0.0.0.0',
                   help='Bind address (default: 0.0.0.0)')
    p.add_argument('--port', type=int, default=161,
                   help='UDP port (default: 161)')
    p.add_argument('--community', default='public',
                   help='SNMP community string (default: public)')
    args = p.parse_args()
    run_server(args.host, args.port, args.community)


if __name__ == '__main__':
    main()
