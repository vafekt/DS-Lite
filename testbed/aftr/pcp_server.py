#!/usr/bin/env python3
"""
pcp_server.py  –  PCP Server for DS-Lite AFTR
RFC 6887 (Port Control Protocol) + draft-ietf-pcp-dslite-00 (plain mode)
RFC 6908 §2.11: PCP server co-located in AFTR (recommended deployment)

Runs inside the AFTR network namespace.
Listens on UDP/5351 over IPv6 for MAP/PEER/ANNOUNCE requests from B4 PCP proxies.
Dynamically creates / removes nftables DNAT rules in the ip nat pcp_dnat chain.

Opcodes implemented (RFC 6887):
  ANNOUNCE (0) – server epoch advertisement; clients use for restart recovery
  MAP      (1) – create/refresh/delete explicit inbound port mappings
  PEER     (2) – learn/control external address+port for outbound flows

Options implemented:
  THIRD_PARTY     (1) – B4 proxy injects client IPv4 (draft-ietf-pcp-dslite-00 §2)
  PREFER_FAILURE  (2) – fail if suggested external port unavailable (RFC 6887 §13.2)
  FILTER          (3) – restrict remote peers that can reach a mapping (RFC 6887 §13.3)

Plain-mode flow (per draft-ietf-pcp-dslite-00 §2):
  Client → B4-proxy (IPv4) → AFTR PCP server (IPv6) → nftables DNAT rule
  B4 proxy sets:
    • PCP Client IP field = B4's DS-Lite tunnel IPv6 endpoint
    • THIRD_PARTY option  = client's IPv4 address

Port pool  (shared with CGNAT SNAT – mirrors real AFTR behavior)
  Range 1024-65534, matching the AFTR's nftables SNAT pool. Each
  PCP allocation also inserts a conntrack entry so that PCP port
  exhaustion (T8) consumes the same session table as regular
  SNAT traffic, matching real CGNAT/AFTR behavior where PCP and
  SNAT share a single port/session allocation table.
"""

import os
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from ipaddress import IPv6Address, ip_address, ip_network


# ── T8/T10 defence: PCP THIRD_PARTY ownership binding (env-gated) ────
# Mechanism from Müller & Rytilahti et al., "On Using Application-Layer
# Middlebox Protocols for Peeking Behind NAT Gateways" (NDSS 2020),
# §Potential Remediations: a PCP server must enforce access control so a
# client cannot create a forward to (or learn the mapping of) an address
# it does not own. When T10_THIRD_PARTY_OWNERSHIP_CHECK=1, MAP and PEER
# requests carrying a THIRD_PARTY option are rejected with NOT_AUTHORIZED
# unless the claimed internal IPv4 address falls inside the prefix
# delegated to the requesting B4. (This is the paper's ownership/access-
# control remediation, not an RFC default — stock PCP performs no such
# check, which is exactly the gap the paper exploits.)
_THIRD_PARTY_OWNERSHIP_CHECK = os.environ.get(
    "T10_THIRD_PARTY_OWNERSHIP_CHECK", "0") == "1"

# Static prefix delegation table for the testbed. Maps each B4's
# tunnel-local IPv6 address to the inner-IPv4 prefix authorised for
# THIRD_PARTY use by clients behind that B4.
_B4_PREFIX = {
    "2001:db8:cafe::b41": ip_network("10.0.1.0/24"),
    "2001:db8:cafe::b42": ip_network("10.0.2.0/24"),
}

def _third_party_owned(client_addr6: str, int_ip_str: str) -> bool:
    """Return True if the THIRD_PARTY-claimed address falls inside the
    requesting B4's authorised prefix, or if the ownership check is
    disabled. Return False to reject the request."""
    if not _THIRD_PARTY_OWNERSHIP_CHECK:
        return True
    prefix = _B4_PREFIX.get(client_addr6)
    if prefix is None:
        return False
    try:
        return ip_address(int_ip_str) in prefix
    except ValueError:
        return False

# ── PCP constants (RFC 6887) ─────────────────────────────────────────
PCP_VERSION = 2
PCP_PORT    = 5351

OP_ANNOUNCE = 0
OP_MAP      = 1
OP_PEER     = 2

SUCCESS                  = 0
UNSUPP_VERSION           = 1
MALFORMED_REQUEST        = 3
UNSUPP_OPCODE            = 4
NETWORK_FAILURE          = 7
NO_RESOURCES             = 8
CANNOT_PROVIDE_EXTERNAL  = 11

OPT_THIRD_PARTY          = 1
OPT_PREFER_FAILURE       = 2
OPT_FILTER               = 3
OPT_AUTH                 = 10   # testbed PCP authentication (shared-key HMAC tag)

NOT_AUTHORIZED           = 2

# ── PCP authentication (RFC 7652-style, env-gated) ───────────────────
# When T_PCP_AUTH=1 the AFTR requires every state-changing/disclosing opcode
# (MAP, PEER) to carry a valid OPT_AUTH option: an HMAC-SHA256 tag over the
# whole request up to the auth option, keyed by a secret shared with the
# legitimate B4 PCP proxies (PCP_AUTH_KEY). The attack tools speak unauthenticated
# PCP straight to the AFTR, so they are rejected with NOT_AUTHORIZED. This models
# the integrity protection of RFC 7652 (a forged or replayed request for a
# different action cannot carry a valid tag without the key).
import hmac as _hmac
import hashlib as _hashlib
_PCP_AUTH_REQUIRED = os.environ.get("T_PCP_AUTH", "0") == "1"
_PCP_AUTH_KEY = os.environ.get("PCP_AUTH_KEY", "ds-lite-pcp-shared-key-2026").encode()
_AUTH_TAG_LEN = 16

# ── Per-subscriber PCP mapping quota (T7, env-gated) ────────────────
# A LAN attacker reaches the AFTR through its own B4 proxy, which authenticates
# it, so PCP auth alone does not stop on-LAN pool exhaustion (T7). When
# T_PCP_QUOTA=N the AFTR caps the number of concurrent mappings per requesting
# B4 (RFC 6887 §16.5 / RFC 6888 REQ-4), so one subscriber cannot drain the shared
# pool and starve co-subscribers behind other B4s.
_PCP_QUOTA = int(os.environ.get("T_PCP_QUOTA", "0") or "0")

def _auth_ok(data: bytes, payload_size: int) -> bool:
    """True iff a valid OPT_AUTH tag is present over the request prefix."""
    base = HDR_REQ.size + payload_size
    i = base
    while i + OPT_HDR.size <= len(data):
        code, _, length = OPT_HDR.unpack_from(data, i)
        opt_start = i
        i += OPT_HDR.size
        opt_data = data[i:i + length]
        i += (length + 3) & ~3
        if code == OPT_AUTH:
            covered = data[:opt_start]
            expected = _hmac.new(_PCP_AUTH_KEY, covered, _hashlib.sha256).digest()[:_AUTH_TAG_LEN]
            return _hmac.compare_digest(opt_data[:_AUTH_TAG_LEN], expected)
    return False   # no auth option present

# ── Lab configuration ────────────────────────────────────────────────
EXT_IP         = "192.0.2.1"    # public IP for PCP DNAT mappings
MAX_LIFETIME   = 7200            # 2-hour cap (seconds)

# Port range matches the SNAT pool so PCP exhaustion (T8) directly
# competes with regular subscriber traffic (RFC 6056 §3.3.4 / RFC 6888).
# For lab demos, PCP_POOL_SIZE limits the effective pool so exhaustion is
# reachable in a short trial.  Real AFTRs use the full 1024-65534 range.
PORT_LOW  = int(os.environ.get("PCP_POOL_LOW",  "1024"))
PORT_HIGH = int(os.environ.get("PCP_POOL_HIGH", "65534"))
_pool_override = os.environ.get("PCP_POOL_SIZE")
if _pool_override:
    PORT_HIGH = PORT_LOW + int(_pool_override) - 1

NFT_TABLE      = "ip nat"
PCP_CHAIN      = "pcp_dnat"

# ── Struct formats ────────────────────────────────────────────────────
# Common request header (24 bytes)
#   version(1) | R|opcode(1) | reserved(2) | lifetime(4) | client_ip(16)
HDR_REQ  = struct.Struct(">BB H I 16s")

# Common response header (24 bytes)
#   version(1) | 1|opcode(1) | reserved(1) | result(1) | lifetime(4) | epoch(4) | reserved96(12)
HDR_RESP = struct.Struct(">BBBB I I 12s")

# MAP opcode payload (36 bytes)
#   nonce(12) | protocol(1) | reserved(3) | int_port(2) | ext_port(2) | ext_ip(16)
MAP_PLD  = struct.Struct(">12s B 3s H H 16s")

# PEER opcode payload (56 bytes)
#   nonce(12) | protocol(1) | reserved(3) | int_port(2) | ext_port(2) | ext_ip(16)
#   remote_port(2) | reserved(2) | remote_ip(16)
PEER_PLD = struct.Struct(">12s B 3s H H 16s H 2s 16s")

# Option header (4 bytes): code(1) | reserved(1) | length(2)
OPT_HDR  = struct.Struct(">BB H")

# FILTER option data: reserved(1) | prefix_len(1) | remote_port(2) | remote_ip(16)
FILTER_DATA = struct.Struct(">B B H 16s")

EPOCH_START = int(time.time())

# ── Mapping state ────────────────────────────────────────────────────
_lock      = threading.Lock()
_mappings  = {}    # (ext_ip, ext_port, proto) → {nonce, int_ip, int_port, expires, handle, filters: list}
_allocated = set() # (ext_ip, ext_port, proto)
_next_port = PORT_LOW
# PEER mappings track outbound flow knowledge (no nftables rule needed)
_peer_mappings = {}  # (client_ip6, proto, int_port, remote_ip, remote_port) → {nonce, ext_ip, ext_port, expires}
# Connected PCP clients for unsolicited ANNOUNCE on restart
_known_clients = set()  # (addr6, port) tuples


# ── nftables helpers ─────────────────────────────────────────────────

def _proto_str(proto: int) -> str:
    return {6: "tcp", 17: "udp"}.get(proto, "tcp")


def _nft_add(ext_ip: str, ext_port: int, proto: int,
             int_ip: str, int_port: int) -> str:
    """Add a DNAT rule to pcp_dnat; return the nft rule handle or '' on failure."""
    p = _proto_str(proto)
    cmd = (f'nft add rule {NFT_TABLE} {PCP_CHAIN} '
           f'iif "eth-wan" {p} dport {ext_port} '
           f'dnat to {int_ip}:{int_port}')
    r = subprocess.run(cmd, shell=True, capture_output=True)
    if r.returncode != 0:
        return ""
    # Retrieve handle of the most recently added rule
    out = subprocess.run(
        ["nft", "-a", "list", "chain"] + NFT_TABLE.split() + [PCP_CHAIN],
        capture_output=True, text=True,
    ).stdout
    handles = re.findall(r"# handle (\d+)", out)
    return handles[-1] if handles else ""


# ── Batched nft writer ────────────────────────────────────────────────
# Per-request fork+exec of `nft` is the dominant cost in MAP handling and
# limits exhaustion attacks (T7) to ~100 mappings per second. We coalesce
# pending adds and flush them in a single `nft -f -` invocation every 50ms,
# bringing throughput to thousands per second so the demo can actually
# exhaust the pool inside a trial window.

_nft_queue: "queue.Queue[tuple]" = queue.Queue()
_pending_handles: dict = {}            # (ext_ip, ext_port, proto) -> threading.Event
_handle_results: dict = {}             # (ext_ip, ext_port, proto) -> handle str

def _nft_enqueue(ext_ip: str, ext_port: int, proto: int,
                 int_ip: str, int_port: int) -> "threading.Event":
    """Queue an nft DNAT add; return an Event that fires when handle is known."""
    key = (ext_ip, ext_port, proto)
    ev = threading.Event()
    _pending_handles[key] = ev
    _nft_queue.put((key, _proto_str(proto), ext_port, int_ip, int_port))
    return ev


def _nft_batch_writer():
    """Background flush loop: drain queue, run `nft -f -`, parse handles."""
    while True:
        batch = []
        try:
            batch.append(_nft_queue.get(timeout=0.5))
        except queue.Empty:
            continue
        # Grab anything else that's queued without blocking
        try:
            while len(batch) < 256:
                batch.append(_nft_queue.get_nowait())
        except queue.Empty:
            pass

        rules = [
            f'add rule {NFT_TABLE} {PCP_CHAIN} '
            f'iif "eth-wan" {p} dport {ep} dnat to {ip}:{ipt}'
            for (_, p, ep, ip, ipt) in batch
        ]
        ruleset = "\n".join(rules) + "\n"
        subprocess.run(["nft", "-f", "-"], input=ruleset.encode(),
                       capture_output=True)

        # Parse handles back. They come back in order; we tag the last N
        # handles in the chain listing to our batch in the same order.
        out = subprocess.run(
            ["nft", "-a", "list", "chain"] + NFT_TABLE.split() + [PCP_CHAIN],
            capture_output=True, text=True,
        ).stdout
        handles = re.findall(r"# handle (\d+)", out)
        tail = handles[-len(batch):] if len(handles) >= len(batch) else handles
        for (key, *_), h in zip(batch, tail):
            _handle_results[key] = h
            ev = _pending_handles.pop(key, None)
            if ev is not None:
                ev.set()
        # Mark queue items done
        for _ in batch:
            _nft_queue.task_done()


def _nft_del(handle: str):
    if handle:
        subprocess.run(
            ["nft", "delete", "rule"] + NFT_TABLE.split()
            + [PCP_CHAIN, "handle", handle],
            capture_output=True,
        )


# ── Port budget enforcement (shared pool simulation) ────────────────
# Real AFTRs share a single port allocation table between PCP and SNAT.
# When PCP claims all ports, the CGNAT has none left for outbound traffic.
# We simulate this by inserting nftables DROP rules in the forward chain
# when the PCP pool is exhausted — matching what a real AFTR does when
# its per-subscriber port budget is fully consumed.

_snat_blocked = False
_POOL_SIZE = PORT_HIGH - PORT_LOW + 1
_BLOCK_COMMENT = "PCP-EXHAUST"

def _enforce_port_budget():
    """Block/unblock outbound SNAT based on PCP port pool usage."""
    global _snat_blocked
    used = len(_allocated)

    if used >= _POOL_SIZE and not _snat_blocked:
        # All ports claimed by PCP — block new outbound connections
        for iface in ("ds-lite-b4-1", "ds-lite-b4-2", "ds-lite-open"):
            # nft requires literal double-quotes around prefix/comment values
            subprocess.run(
                f'nft insert rule ip filter forward '
                f'iif \\"{iface}\\" oif \\"eth-wan\\" ct state new '
                f'log prefix \\"AFTR-PCP-EXHAUST: \\" '
                f'counter drop comment \\"{_BLOCK_COMMENT}\\"',
                shell=True, capture_output=True,
            )
        _snat_blocked = True
        print(f"[!] PCP EXHAUSTED ({used}/{_POOL_SIZE}) "
              f"— new outbound SNAT blocked (port budget depleted)")
        sys.stdout.flush()

    elif used < _POOL_SIZE and _snat_blocked:
        # Ports freed — remove block rules
        out = subprocess.run(
            ["nft", "-a", "list", "chain", "ip", "filter", "forward"],
            capture_output=True, text=True,
        ).stdout
        for line in out.split("\n"):
            if _BLOCK_COMMENT in line:
                m = re.search(r"# handle (\d+)", line)
                if m:
                    subprocess.run(
                        ["nft", "delete", "rule", "ip", "filter",
                         "forward", "handle", m.group(1)],
                        capture_output=True,
                    )
        _snat_blocked = False
        print(f"[+] PCP ports freed ({used}/{_POOL_SIZE}) "
              f"— outbound SNAT restored")


# ── Port allocation ──────────────────────────────────────────────────

def _alloc_port(proto: int) -> int:
    global _next_port
    for _ in range(PORT_HIGH - PORT_LOW + 1):
        p = _next_port
        _next_port = PORT_LOW if _next_port >= PORT_HIGH else _next_port + 1
        if (EXT_IP, p, proto) not in _allocated:
            return p
    return 0  # exhausted


# ── Address encoding helpers ─────────────────────────────────────────

def _v4mapped(ipv4_str: str) -> bytes:
    return b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(ipv4_str)


def _decode_pcp_ip(raw16: bytes) -> str:
    """Return a string IP from a 16-byte PCP address field (v4-mapped or v6)."""
    addr = IPv6Address(raw16)
    return str(addr.ipv4_mapped) if addr.ipv4_mapped else str(addr)


# ── Option parsing ───────────────────────────────────────────────────

def _parse_options(data: bytes) -> dict:
    """Return dict of option_code → option_data bytes."""
    opts, i = {}, 0
    while i + OPT_HDR.size <= len(data):
        code, _, length = OPT_HDR.unpack_from(data, i)
        i += OPT_HDR.size
        opts[code] = data[i:i + length]
        i += (length + 3) & ~3   # advance over padded option data
    return opts


# ── Epoch time ───────────────────────────────────────────────────────

def _epoch() -> int:
    return int(time.time()) - EPOCH_START


# ── Response builders ────────────────────────────────────────────────

def _resp_hdr(opcode: int, result: int, lifetime: int) -> bytes:
    return HDR_RESP.pack(PCP_VERSION, 0x80 | opcode, 0, result,
                         lifetime, _epoch(), b"\x00" * 12)


def _error(opcode: int, result: int) -> bytes:
    if opcode == OP_MAP:
        payload = MAP_PLD.pack(b"\x00"*12, 0, b"\x00"*3, 0, 0, b"\x00"*16)
    elif opcode == OP_PEER:
        payload = PEER_PLD.pack(b"\x00"*12, 0, b"\x00"*3, 0, 0,
                                b"\x00"*16, 0, b"\x00"*2, b"\x00"*16)
    else:
        payload = b""
    return _resp_hdr(opcode, result, 0) + payload


# ── MAP opcode handler ───────────────────────────────────────────────

def _handle_map(client_addr6: str, lifetime: int,
                map_raw: bytes, opts: dict) -> bytes:
    if len(map_raw) < MAP_PLD.size:
        return _error(OP_MAP, MALFORMED_REQUEST)

    nonce, proto, _, int_port, sug_ext_port, sug_ext_ip = MAP_PLD.unpack_from(map_raw)

    # In DS-Lite plain mode the B4 proxy adds THIRD_PARTY with the client IPv4
    if OPT_THIRD_PARTY in opts and len(opts[OPT_THIRD_PARTY]) == 16:
        int_ip = _decode_pcp_ip(opts[OPT_THIRD_PARTY])
        if not _third_party_owned(client_addr6, int_ip):
            return _error(OP_MAP, NOT_AUTHORIZED)
    else:
        # A direct PCP client speaking to the AFTR over IPv6 has no IPv4
        # address; we can't materialise a `ip nat` DNAT rule for it.
        # RFC 6887 §13.1 — clients in this position SHOULD include
        # THIRD_PARTY when their internal address is in a different
        # address family than the source.
        if ':' in client_addr6:
            return _error(OP_MAP, MALFORMED_REQUEST)
        int_ip = client_addr6   # direct IPv4 client (no proxy)

    # Protocol 0 = all; default to TCP for the nftables rule
    eff_proto = proto if proto in (6, 17) else 6

    with _lock:
        # Find existing mapping by (nonce + int_ip + int_port)
        existing = next(
            (k for k, m in _mappings.items()
             if m["nonce"] == nonce and m["int_ip"] == int_ip
             and m["int_port"] == int_port and k[2] == eff_proto),
            None,
        )

        if lifetime == 0:
            # Delete request
            if existing:
                _nft_del(_mappings[existing]["handle"])
                _enforce_port_budget()
                _allocated.discard(existing)
                del _mappings[existing]
                print(f"[-] PCP DELETE  {int_ip}:{int_port}"
                      f"  proto={_proto_str(eff_proto)}")
            pld = MAP_PLD.pack(nonce, proto, b"\x00"*3,
                               int_port, 0, b"\x00"*16)
            return _resp_hdr(OP_MAP, SUCCESS, 0) + pld

        if existing:
            # Refresh: extend lifetime
            new_lt = min(lifetime, MAX_LIFETIME)
            _mappings[existing]["expires"] = time.time() + new_lt
            ext_ip, ext_port, _ = existing
            pld = MAP_PLD.pack(nonce, proto, b"\x00"*3,
                               int_port, ext_port, _v4mapped(ext_ip))
            return _resp_hdr(OP_MAP, SUCCESS, new_lt) + pld

        # Per-subscriber quota (T7): cap concurrent mappings per requesting B4
        # so one subscriber cannot exhaust the shared pool.
        if _PCP_QUOTA > 0:
            in_use = sum(1 for m in _mappings.values() if m.get("b4") == client_addr6)
            if in_use >= _PCP_QUOTA:
                return _error(OP_MAP, NO_RESOURCES)

        # PREFER_FAILURE: if client suggests a specific port, fail if unavailable
        prefer_failure = OPT_PREFER_FAILURE in opts
        if prefer_failure and sug_ext_port > 0:
            if (EXT_IP, sug_ext_port, eff_proto) in _allocated:
                return _error(OP_MAP, CANNOT_PROVIDE_EXTERNAL)
            ext_port = sug_ext_port
        else:
            # New mapping: allocate a port
            ext_port = _alloc_port(eff_proto)
        if not ext_port:
            return _error(OP_MAP, NO_RESOURCES)

        # Enqueue the nft DNAT rule; batched writer flushes shortly.
        # We return SUCCESS to the client immediately because the port is
        # already reserved in _allocated; this matches real PCP servers
        # that ACK before the dataplane rule lands.
        ev = _nft_enqueue(EXT_IP, ext_port, eff_proto, int_ip, int_port)
        handle = ""
        if ev.wait(timeout=0.6):
            handle = _handle_results.pop((EXT_IP, ext_port, eff_proto), "")
        # Even without a handle (slow flush), the mapping is recorded;
        # the writer will fill it in shortly. Clients can use the port.

        granted = min(lifetime, MAX_LIFETIME)
        key = (EXT_IP, ext_port, eff_proto)

        # Parse FILTER options (RFC 6887 §13.3)
        filters = []
        if OPT_FILTER in opts and len(opts[OPT_FILTER]) >= FILTER_DATA.size:
            _, prefix_len, remote_port, remote_ip_raw = \
                FILTER_DATA.unpack_from(opts[OPT_FILTER])
            remote_ip = _decode_pcp_ip(remote_ip_raw)
            filters.append(dict(prefix_len=prefix_len, remote_port=remote_port,
                                remote_ip=remote_ip))

        _mappings[key] = dict(nonce=nonce, int_ip=int_ip, int_port=int_port,
                              expires=time.time() + granted, handle=handle,
                              filters=filters, b4=client_addr6)
        _allocated.add(key)

        # Check if PCP has consumed the entire port budget
        _enforce_port_budget()

        filter_str = f"  filter={filters[0]['remote_ip']}/{filters[0]['prefix_len']}" \
                     if filters else ""
        print(f"[+] PCP MAP  {int_ip}:{int_port} → {EXT_IP}:{ext_port}"
              f"  proto={_proto_str(eff_proto)}  lifetime={granted}s"
              f"  B4={client_addr6}{filter_str}")

        pld = MAP_PLD.pack(nonce, proto, b"\x00"*3,
                           int_port, ext_port, _v4mapped(EXT_IP))
        return _resp_hdr(OP_MAP, SUCCESS, granted) + pld


# ── PEER opcode handler ──────────────────────────────────────────────

def _handle_peer(client_addr6: str, lifetime: int,
                 peer_raw: bytes, opts: dict) -> bytes:
    """
    PEER opcode (RFC 6887 §12): learn/control the external address and port
    assigned by the NAT for an outbound flow.

    In DS-Lite, the B4 (or its client) uses PEER to discover what external
    IP:port the AFTR CGNAT assigned to a specific (int_port → remote_ip:remote_port)
    flow.  This is useful for applications that need to communicate their
    external transport address to a rendezvous server (e.g., ICE/STUN).

    The PEER response tells the client the actual external IP:port so it can
    be shared with a remote peer.  The mapping lifetime can also be extended,
    reducing the need for application-level keepalive messages.
    """
    if len(peer_raw) < PEER_PLD.size:
        return _error(OP_PEER, MALFORMED_REQUEST)

    nonce, proto, _, int_port, sug_ext_port, sug_ext_ip, \
        remote_port, _, remote_ip_raw = PEER_PLD.unpack_from(peer_raw)

    remote_ip = _decode_pcp_ip(remote_ip_raw)

    # Resolve internal IP via THIRD_PARTY
    if OPT_THIRD_PARTY in opts and len(opts[OPT_THIRD_PARTY]) == 16:
        int_ip = _decode_pcp_ip(opts[OPT_THIRD_PARTY])
        if not _third_party_owned(client_addr6, int_ip):
            return _error(OP_PEER, NOT_AUTHORIZED)
    else:
        int_ip = client_addr6

    eff_proto = proto if proto in (6, 17) else 6

    with _lock:
        peer_key = (client_addr6, eff_proto, int_port, remote_ip, remote_port)

        if lifetime == 0:
            # Delete peer mapping
            if peer_key in _peer_mappings:
                del _peer_mappings[peer_key]
                print(f"[-] PCP PEER DELETE  {int_ip}:{int_port}"
                      f" ↔ {remote_ip}:{remote_port}  B4={client_addr6}")
            pld = PEER_PLD.pack(nonce, proto, b"\x00"*3, int_port, 0,
                                b"\x00"*16, remote_port, b"\x00"*2,
                                remote_ip_raw)
            return _resp_hdr(OP_PEER, SUCCESS, 0) + pld

        # Check if we have a MAP mapping for this client's flow
        ext_ip_str = EXT_IP
        ext_port_assigned = 0

        for (m_ext_ip, m_ext_port, m_proto), m_info in _mappings.items():
            if m_info["int_ip"] == int_ip and m_proto == eff_proto:
                if m_info["int_port"] == int_port or int_port == 0:
                    ext_port_assigned = m_ext_port
                    ext_ip_str = m_ext_ip
                    break

        # If no explicit MAP exists, look up the CGNAT-assigned port in conntrack.
        # The conntrack line shape is:
        #   src=int_ip dst=remote_ip sport=int_port dport=remote_port \
        #     src=remote_ip dst=ext_ip sport=remote_port dport=ext_port
        # so the NAT external port is the SECOND dport= occurrence (reply tuple).
        if not ext_port_assigned:
            try:
                # int_port=0 is a wildcard scan: omit --sport to match any source port.
                ct_cmd = ["conntrack", "-L", "-s", int_ip, "-p", _proto_str(eff_proto)]
                if int_port != 0:
                    ct_cmd += ["--sport", str(int_port)]
                ct_out = subprocess.run(
                    ct_cmd,
                    capture_output=True, text=True, timeout=2,
                ).stdout
                for line in ct_out.strip().split('\n'):
                    if f'dport={remote_port}' in line and remote_ip in line:
                        # In the conntrack line, the reply tuple is
                        #   src=remote_ip dst=ext_ip sport=remote_port dport=ext_port
                        # so the NAT external IP and port are the 2nd dst= and 2nd dport=.
                        dports = re.findall(r'dport=(\d+)', line)
                        dsts   = re.findall(r'dst=(\S+)',  line)
                        if len(dports) >= 2:
                            port_val = int(dports[1])
                            if 1024 <= port_val <= 65534:
                                ext_port_assigned = port_val
                                if len(dsts) >= 2 and '.' in dsts[1]:
                                    ext_ip_str = dsts[1]
                                break
            except Exception:
                pass

        granted = min(lifetime, MAX_LIFETIME) if ext_port_assigned else 0
        result = SUCCESS if ext_port_assigned else NETWORK_FAILURE

        if ext_port_assigned:
            _peer_mappings[peer_key] = dict(
                nonce=nonce, ext_ip=ext_ip_str, ext_port=ext_port_assigned,
                expires=time.time() + granted,
            )
            print(f"[+] PCP PEER  {int_ip}:{int_port} ↔ {remote_ip}:{remote_port}"
                  f"  ext={ext_ip_str}:{ext_port_assigned}"
                  f"  proto={_proto_str(eff_proto)}  lifetime={granted}s"
                  f"  B4={client_addr6}")

        pld = PEER_PLD.pack(
            nonce, proto, b"\x00"*3, int_port,
            ext_port_assigned, _v4mapped(ext_ip_str),
            remote_port, b"\x00"*2, remote_ip_raw,
        )
        return _resp_hdr(OP_PEER, result, granted) + pld


# ── Request dispatcher ───────────────────────────────────────────────

def dispatch(data: bytes, addr: tuple) -> bytes | None:
    if len(data) < HDR_REQ.size:
        return None

    ver, ro, _, lifetime, client_ip_raw = HDR_REQ.unpack_from(data)
    opcode = ro & 0x7F
    r_bit  = (ro >> 7) & 1

    if ver != PCP_VERSION:
        return _error(opcode, UNSUPP_VERSION)
    if r_bit:
        return None  # silently drop responses

    client_addr6 = addr[0].split("%")[0]
    _known_clients.add(addr)

    if opcode == OP_ANNOUNCE:
        # RFC 6887 §14.1: ANNOUNCE carries no opcode-specific payload.
        # Client sends to learn current epoch; server responds with epoch.
        return _resp_hdr(OP_ANNOUNCE, SUCCESS, 0)

    if opcode == OP_MAP:
        if len(data) < HDR_REQ.size + MAP_PLD.size:
            return _error(OP_MAP, MALFORMED_REQUEST)
        if _PCP_AUTH_REQUIRED and not _auth_ok(data, MAP_PLD.size):
            return _error(OP_MAP, NOT_AUTHORIZED)
        map_raw = data[HDR_REQ.size: HDR_REQ.size + MAP_PLD.size]
        opts    = _parse_options(data[HDR_REQ.size + MAP_PLD.size:])
        return _handle_map(client_addr6, lifetime, map_raw, opts)

    if opcode == OP_PEER:
        if len(data) < HDR_REQ.size + PEER_PLD.size:
            return _error(OP_PEER, MALFORMED_REQUEST)
        if _PCP_AUTH_REQUIRED and not _auth_ok(data, PEER_PLD.size):
            return _error(OP_PEER, NOT_AUTHORIZED)
        peer_raw = data[HDR_REQ.size: HDR_REQ.size + PEER_PLD.size]
        opts     = _parse_options(data[HDR_REQ.size + PEER_PLD.size:])
        return _handle_peer(client_addr6, lifetime, peer_raw, opts)

    return _error(opcode, UNSUPP_OPCODE)


# ── Expiry background thread ─────────────────────────────────────────

def _expiry_loop():
    while True:
        time.sleep(30)
        now = time.time()
        with _lock:
            expired = [k for k, m in _mappings.items() if m["expires"] <= now]
            for k in expired:
                m = _mappings.pop(k)
                _allocated.discard(k)
                _nft_del(m["handle"])
                ext_ip, ext_port, proto = k
                _enforce_port_budget()
                print(f"[-] PCP EXPIRED  {m['int_ip']}:{m['int_port']}"
                      f" → {ext_ip}:{ext_port}  proto={_proto_str(proto)}")


# ── Main ─────────────────────────────────────────────────────────────

def _startup_cleanup():
    """Remove stale state left by a previous server instance.

    (1) PCP-EXHAUST DROP rules in filter/forward, and (2) the pcp_dnat DNAT
    rules. A fresh server starts with an EMPTY in-memory pool, so the nft
    pcp_dnat chain must be flushed to stay in sync (otherwise stale rules
    accumulate and the chain count desyncs from the real pool usage). This
    matches RFC 6887 restart semantics: the server advertises an epoch reset
    and clients re-establish their mappings, which re-populates the chain.
    """
    out = subprocess.run(
        ["nft", "-a", "list", "chain", "ip", "filter", "forward"],
        capture_output=True, text=True,
    ).stdout
    for line in out.split("\n"):
        if _BLOCK_COMMENT in line:
            m = re.search(r"# handle (\d+)", line)
            if m:
                subprocess.run(
                    ["nft", "delete", "rule", "ip", "filter",
                     "forward", "handle", m.group(1)],
                    capture_output=True,
                )
    # Flush the DNAT mappings of the previous instance so the chain matches
    # this instance's empty pool (no stale-rule accumulation across restarts).
    subprocess.run(
        ["nft", "flush", "chain", "ip", "nat", PCP_CHAIN],
        capture_output=True,
    )


def main():
    # Remove stale PCP-EXHAUST rules from any previous server instance
    _startup_cleanup()
    # Ensure the pcp_dnat chain exists (nftables.conf creates it; this is a safety net)
    subprocess.run(f"nft add chain {NFT_TABLE} {PCP_CHAIN} 2>/dev/null || true",
                   shell=True)

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Absorb T7 exhaustion bursts. SO_RCVBUFFORCE (33) bypasses net.core.rmem_max
    # for CAP_NET_ADMIN processes — the AFTR namespace runs root inside a
    # privileged container, so this is permitted and avoids needing to retune
    # the host-side sysctl.
    SO_RCVBUFFORCE = 33
    for opt in (SO_RCVBUFFORCE, socket.SO_RCVBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, 16 * 1024 * 1024)
            break
        except OSError:
            continue
    sock.bind(("", PCP_PORT))

    print(f"[*] PCP Server  UDP6/{PCP_PORT}  ext={EXT_IP}  "
          f"pool={PORT_LOW}-{PORT_HIGH}")
    print(f"    nftables chain: {NFT_TABLE} → {PCP_CHAIN}")
    print(f"    conntrack reservation: enabled (shared session table with SNAT)")
    print(f"    opcodes: ANNOUNCE(0), MAP(1), PEER(2)")
    print(f"    options: THIRD_PARTY(1), PREFER_FAILURE(2), FILTER(3)")

    threading.Thread(target=_expiry_loop, daemon=True).start()
    threading.Thread(target=_nft_batch_writer, daemon=True).start()

    # RFC 6887 §14.1.2: Send unsolicited ANNOUNCE on startup/restart
    # to signal epoch change.  Known clients will re-establish mappings.
    def _send_announce_on_restart():
        """Broadcast ANNOUNCE to multicast after brief startup delay."""
        time.sleep(2)
        announce_pkt = _resp_hdr(OP_ANNOUNCE, SUCCESS, 0)
        # Send to PCP multicast address (ff02::1 on link-local)
        try:
            asock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            asock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            asock.sendto(announce_pkt, ("ff02::1", PCP_PORT, 0, 0))
            asock.close()
            print(f"[*] Unsolicited ANNOUNCE sent (epoch={_epoch()})")
        except Exception as e:
            print(f"[!] ANNOUNCE broadcast failed: {e}")

    threading.Thread(target=_send_announce_on_restart, daemon=True).start()

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            resp = dispatch(data, addr)
            if resp:
                sock.sendto(resp, addr)
        except KeyboardInterrupt:
            print("\n[!] PCP Server shutting down.")
            break
        except Exception as e:
            print(f"[!] {e}")

    sock.close()


if __name__ == "__main__":
    main()
