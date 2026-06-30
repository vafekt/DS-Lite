#!/usr/bin/env python3
"""
pcp_proxy.py  –  PCP Proxy for DS-Lite B4 (plain mode)
draft-ietf-pcp-dslite-00 §2 / RFC 6887 / RFC 6908 §2.11

Runs on the B4 CPE, inside the B4 network namespace.
Listens on UDP/5351 on the LAN IPv4 interface for PCP requests from clients.
Forwards MAP and PEER requests over IPv6 UDP/5351 to the AFTR PCP server,
injecting:
  • Client IP field   = B4's own ISP-side IPv6 address (DS-Lite tunnel endpoint)
  • THIRD_PARTY option (code 1, 16 bytes) = client's IPv4 as ::ffff:a.b.c.d

Security (draft-ietf-pcp-dslite-00 §4, RFC 6887 §18.1 Simple Threat Model):
  The proxy MUST strip any THIRD_PARTY options from clients and inject its own.
  This prevents LAN clients from creating mappings for arbitrary addresses.
  The proxy provides a control point for access-list enforcement.

Responses from the AFTR are relayed back to the originating IPv4 client unchanged.

Plain-mode flow (draft-ietf-pcp-dslite-00 §2):
  Client(IPv4) → B4-proxy(IPv4/5351) → AFTR-server(IPv6/5351) → nftables DNAT rule
"""

import argparse
import socket
import struct
import sys
import threading

PCP_PORT    = 5351
PCP_MC_PORT = 5350     # RFC 6887 §8.5 — client port for unsolicited ANNOUNCE
PCP_VERSION = 2
OP_ANNOUNCE = 0
OP_MAP      = 1
OP_PEER     = 2
OPT_THIRD_PARTY = 1
OPT_AUTH        = 10   # testbed PCP authentication (shared-key HMAC tag)

# ── RFC 6887 §8.5 client epoch state ─────────────────────────────────
# A conformant PCP client tracks the server's epoch. If an ANNOUNCE (or any
# response) reports an epoch that has gone BACKWARDS, the server lost state and
# the client MUST re-create all its mappings. The B4 proxy is the PCP client to
# the AFTR, so it implements this here: it remembers the MAP requests it relayed
# and, on an epoch reset, re-sends them (the renewal storm T9 induces).
_state_lock = threading.Lock()
_last_epoch = None
_relayed_maps = {}     # key -> rewritten MAP request bytes (to renew)

# ── PCP authentication (matches pcp_server.py) ───────────────────────
# When T_PCP_AUTH=1 the legitimate proxy appends an HMAC-SHA256 tag over the
# rewritten request, keyed by the secret shared with the AFTR. The AFTR rejects
# any MAP/PEER lacking a valid tag, so the attack tools' unauthenticated PCP is
# refused while legitimate subscriber PCP through the proxy keeps working.
import os as _os
import hmac as _hmac
import hashlib as _hashlib
_PCP_AUTH_ENABLED = _os.environ.get("T_PCP_AUTH", "0") == "1"
_PCP_AUTH_KEY = _os.environ.get("PCP_AUTH_KEY", "ds-lite-pcp-shared-key-2026").encode()
_AUTH_TAG_LEN = 16

def _append_auth(pkt: bytes) -> bytes:
    """Append the OPT_AUTH HMAC tag (16 B data → 20 B option, 4-aligned)."""
    if not _PCP_AUTH_ENABLED:
        return pkt
    tag = _hmac.new(_PCP_AUTH_KEY, pkt, _hashlib.sha256).digest()[:_AUTH_TAG_LEN]
    return pkt + OPT_HDR.pack(OPT_AUTH, 0, _AUTH_TAG_LEN) + tag

# Common request header: version(1)|R|opcode(1)|reserved(2)|lifetime(4)|client_ip(16)
HDR_REQ = struct.Struct(">BB H I 16s")

# Option header: code(1)|reserved(1)|length(2)
OPT_HDR = struct.Struct(">BB H")

MAP_PLD_SIZE  = 36   # 12(nonce)+1(proto)+3(rsv)+2(int_port)+2(ext_port)+16(ext_ip)
PEER_PLD_SIZE = 56   # MAP_PLD(36) + 2(remote_port)+2(rsv)+16(remote_ip)


def _v4mapped(ipv4_str: str) -> bytes:
    """Encode IPv4 as IPv4-mapped IPv6 (::ffff:a.b.c.d)."""
    return b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(ipv4_str)


_PASSTHROUGH_THIRD_PARTY = False   # set from --passthrough-third-party flag


def _rewrite_request(data: bytes, client_ip4: str, b4_ip6: str) -> bytes:
    """
    Rewrite an inbound PCP request from an IPv4 client for forwarding to AFTR.

    Changes made (per draft-ietf-pcp-dslite-00 §2):
      1. Replace Client IP field with B4's 128-bit IPv6 address.
      2. Insert THIRD_PARTY option (code 1) carrying client's IPv4-mapped IPv6.
         Any existing THIRD_PARTY option from the client is stripped (security).

    When _PASSTHROUGH_THIRD_PARTY is True (insecure demo mode), requests that
    already carry a THIRD_PARTY option have it forwarded unchanged instead of
    being replaced — simulating a misconfigured B4 that does not enforce
    RFC 6887 §13.1 / draft-ietf-pcp-dslite-00 §4 client isolation.

    Returns the modified packet bytes.
    """
    if len(data) < HDR_REQ.size:
        return data

    ver, ro, res, lifetime, _ = HDR_REQ.unpack_from(data)
    opcode = ro & 0x7F

    # B4's IPv6 address as 16 raw bytes
    b4_ip6_bytes = socket.inet_pton(socket.AF_INET6, b4_ip6)

    # Rebuild header with new client IP
    new_hdr = HDR_REQ.pack(ver, ro, res, lifetime, b4_ip6_bytes)

    # Build THIRD_PARTY option: code=1, rsv=0, length=16 (option data bytes)
    third_party_payload = _v4mapped(client_ip4)
    third_party_opt = OPT_HDR.pack(OPT_THIRD_PARTY, 0, 16) + third_party_payload
    # Options are padded to 4-byte boundary; 4 (hdr) + 16 (data) = 20 bytes already aligned

    rest = data[HDR_REQ.size:]

    if opcode == OP_MAP and len(rest) >= MAP_PLD_SIZE:
        map_pld = rest[:MAP_PLD_SIZE]
        existing_opts_raw = rest[MAP_PLD_SIZE:]

        if _PASSTHROUGH_THIRD_PARTY and _has_option(existing_opts_raw, OPT_THIRD_PARTY):
            # Passthrough mode: client supplied THIRD_PARTY — forward it unchanged.
            # The proxy still replaces the Client IP field (correct DS-Lite behaviour)
            # but does NOT substitute its own THIRD_PARTY, so the AFTR sees the
            # attacker-controlled THIRD_PARTY value directly.
            return _append_auth(new_hdr + map_pld + existing_opts_raw)

        # Secure mode (RFC 6887 §13.1): strip client THIRD_PARTY, inject own.
        clean_opts = _strip_option(existing_opts_raw, OPT_THIRD_PARTY)
        return _append_auth(new_hdr + map_pld + third_party_opt + clean_opts)

    if opcode == OP_PEER and len(rest) >= PEER_PLD_SIZE:
        peer_pld = rest[:PEER_PLD_SIZE]
        existing_opts_raw = rest[PEER_PLD_SIZE:]

        if _PASSTHROUGH_THIRD_PARTY and _has_option(existing_opts_raw, OPT_THIRD_PARTY):
            return _append_auth(new_hdr + peer_pld + existing_opts_raw)

        # Secure mode: strip client THIRD_PARTY from client, inject ours
        clean_opts = _strip_option(existing_opts_raw, OPT_THIRD_PARTY)
        return _append_auth(new_hdr + peer_pld + third_party_opt + clean_opts)

    # ANNOUNCE or unknown opcode: just rewrite the header
    return new_hdr + rest


def _strip_option(opts_raw: bytes, target_code: int) -> bytes:
    """Return opts_raw with all occurrences of target_code removed."""
    out, i = b"", 0
    while i + OPT_HDR.size <= len(opts_raw):
        code, rsv, length = OPT_HDR.unpack_from(opts_raw, i)
        padded_len = (length + 3) & ~3
        chunk = opts_raw[i: i + OPT_HDR.size + padded_len]
        if code != target_code:
            out += chunk
        i += OPT_HDR.size + padded_len
    return out


def _has_option(opts_raw: bytes, target_code: int) -> bool:
    """Return True if opts_raw contains at least one option with target_code."""
    i = 0
    while i + OPT_HDR.size <= len(opts_raw):
        code, _, length = OPT_HDR.unpack_from(opts_raw, i)
        if code == target_code:
            return True
        i += OPT_HDR.size + ((length + 3) & ~3)
    return False


def _handle_client(data: bytes, client_addr: tuple,
                   b4_ip6: str, aftr_ip6: str,
                   downstream_sock: socket.socket):
    """
    Forward one PCP request to the AFTR and relay the response to the client.
    Runs in its own daemon thread.
    """
    client_ip4 = client_addr[0]

    # Silently drop response packets (R-bit set) from clients
    if len(data) >= 2 and (data[1] & 0x80):
        return

    modified = _rewrite_request(data, client_ip4, b4_ip6)

    # Remember relayed MAP requests so we can renew them on an epoch reset
    # (RFC 6887 §8.5). Keyed by client + opcode + first payload bytes.
    if len(data) >= 2 and (data[1] & 0x7F) == OP_MAP:
        with _state_lock:
            _relayed_maps[(client_ip4, bytes(modified[:40]))] = modified

    # Open a transient IPv6 socket to the AFTR PCP server. Bind it to the B4's
    # own tunnel address so the upstream PCP always sources from b4_ip6 rather
    # than whatever the kernel's source selection picks (which may be a
    # SLAAC/residual address). This keeps the PCP control channel inside the
    # B4<->AFTR IPsec selector, so it is encrypted along with the softwire.
    up_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    up_sock.settimeout(5.0)
    try:
        try:
            up_sock.bind((b4_ip6, 0))
        except OSError:
            pass
        up_sock.sendto(modified, (aftr_ip6, PCP_PORT, 0, 0))
        try:
            resp, _ = up_sock.recvfrom(4096)
            _track_epoch(resp)        # seed epoch from legitimate responses
            downstream_sock.sendto(resp, client_addr)
        except socket.timeout:
            # RFC 6887 §8.1.1: client will retransmit on timeout
            pass
    except Exception as e:
        print(f"[!] proxy error for {client_ip4}: {e}")
    finally:
        up_sock.close()


def _parse_epoch(pkt: bytes):
    """Return the epoch from a PCP response header, or None."""
    if len(pkt) < 12 or not (pkt[1] & 0x80):
        return None
    return struct.unpack('>I', pkt[8:12])[0]


def _track_epoch(resp: bytes):
    global _last_epoch
    e = _parse_epoch(resp)
    if e is not None:
        with _state_lock:
            _last_epoch = e


def _renew_all(aftr_ip6: str, b4_ip6: str):
    """Re-send every relayed MAP to the AFTR — the renewal storm a real client
    triggers after detecting an epoch reset (RFC 6887 §8.5)."""
    with _state_lock:
        maps = list(_relayed_maps.values())
    if not maps:
        print("[epoch] reset detected but no mappings to renew", flush=True)
        return
    print(f"[epoch] EPOCH RESET — re-creating {len(maps)} mapping(s) at AFTR",
          flush=True)
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        try:
            s.bind((b4_ip6, 0))
        except OSError:
            pass
        n = 0
        for m in maps:
            try:
                s.sendto(m, (aftr_ip6, PCP_PORT, 0, 0))
                n += 1
            except Exception:
                pass
        print(f"[epoch] renewal storm sent: {n} MAP request(s)", flush=True)
    finally:
        s.close()


def _confirm_epoch_reset(aftr_ip6: str, prev_epoch) -> bool:
    """RFC 7652 §3: confirm a suspected epoch reset by sending an authenticated
    unicast ANNOUNCE request to the AFTR and reading its real (authenticated)
    epoch. Returns True only if the server's authoritative epoch has genuinely
    gone backwards relative to `prev_epoch`. A spoofed multicast ANNOUNCE cannot
    influence this, so a forged reset is rejected."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        # ANNOUNCE request: version=2, opcode=0, reserved, lifetime=0, client-ip
        req = struct.pack('>BBHI', PCP_VERSION, OP_ANNOUNCE, 0, 0) + (b'\x00' * 12)
        req = _append_auth(req)     # OPT_AUTH HMAC tag (server requires it)
        s.sendto(req, (aftr_ip6, PCP_PORT))
        resp, _ = s.recvfrom(4096)
        s.close()
        if len(resp) < 12:
            return False
        server_epoch = struct.unpack('>I', resp[8:12])[0]
        # genuine reset iff the AUTHENTICATED server epoch is below what we had
        return prev_epoch is not None and server_epoch < prev_epoch
    except Exception:
        return False          # no authenticated confirmation -> do not renew


def _announce_listener(b4_ip6: str, aftr_ip6: str):
    """RFC 6887 §8.5: listen for unsolicited multicast ANNOUNCE; on an epoch
    decrease (server restart / spoofed reset) renew all mappings."""
    global _last_epoch
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("::", PCP_MC_PORT))
    except OSError as e:
        print(f"[epoch] could not bind ANNOUNCE port {PCP_MC_PORT}: {e}",
              flush=True)
        return
    print(f"[epoch] ANNOUNCE listener up on UDP6/{PCP_MC_PORT}", flush=True)
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except Exception:
            continue
        if len(data) < 12 or not (data[1] & 0x80) \
           or (data[1] & 0x7F) != OP_ANNOUNCE:
            continue
        e = struct.unpack('>I', data[8:12])[0]
        with _state_lock:
            prev = _last_epoch
        print(f"[epoch] ANNOUNCE epoch={e} (prev={prev}) from {addr[0]}",
              flush=True)
        if prev is not None and e < prev:
            # RFC 7652 defence (T9): an UNSOLICITED multicast ANNOUNCE is not
            # trusted. When PCP auth is enabled, do NOT renew on the raw
            # ANNOUNCE — first CONFIRM the reset with an integrity-protected
            # unicast ANNOUNCE request to the AFTR. A forged ANNOUNCE (the
            # attacker's spoof) cannot make the real server report a reset, so
            # the confirmation fails and no renewal storm is emitted.
            if _PCP_AUTH_ENABLED:
                if _confirm_epoch_reset(aftr_ip6, prev):
                    print("[epoch] reset CONFIRMED via authenticated unicast "
                          "ANNOUNCE — renewing", flush=True)
                    _renew_all(aftr_ip6, b4_ip6)
                else:
                    print("[epoch] unsolicited ANNOUNCE NOT confirmed by the "
                          "server (forged/spoofed) — ignoring (no storm)",
                          flush=True)
                    continue   # do not adopt the spoofed epoch
            else:
                print("[epoch] server epoch went BACKWARDS — mappings presumed "
                      "lost, renewing", flush=True)
                _renew_all(aftr_ip6, b4_ip6)
        with _state_lock:
            if prev is None or e >= prev:
                _last_epoch = e


def main():
    ap = argparse.ArgumentParser(
        description="PCP Proxy for DS-Lite B4 (plain mode, draft-ietf-pcp-dslite-00)"
    )
    ap.add_argument("--lan-ip",   required=True,
                    help="B4 LAN IPv4 address to listen on (e.g. 10.0.1.1)")
    ap.add_argument("--b4-ip6",   required=True,
                    help="B4's ISP-side IPv6 address (DS-Lite tunnel endpoint)")
    ap.add_argument("--aftr-ip6", required=True,
                    help="AFTR PCP server IPv6 address")
    ap.add_argument("--passthrough-third-party", action="store_true",
                    help="(insecure demo) Forward client THIRD_PARTY options unchanged "
                         "instead of stripping and replacing with proxy's own. "
                         "Simulates a misconfigured B4 that violates RFC 6887 §13.1.")
    args = ap.parse_args()

    global _PASSTHROUGH_THIRD_PARTY
    _PASSTHROUGH_THIRD_PARTY = args.passthrough_third_party
    if _PASSTHROUGH_THIRD_PARTY:
        print("[!] THIRD_PARTY passthrough enabled (insecure demo mode)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Absorb PCP flood bursts (T7). SO_RCVBUFFORCE (33) bypasses rmem_max for CAP_NET_ADMIN.
    SO_RCVBUFFORCE = 33
    for opt in (SO_RCVBUFFORCE, socket.SO_RCVBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, 16 * 1024 * 1024)
            break
        except OSError:
            continue
    sock.bind((args.lan_ip, PCP_PORT))

    print(f"[*] PCP Proxy  UDP4/{PCP_PORT}"
          f"  lan={args.lan_ip}"
          f"  b4_ip6={args.b4_ip6}"
          f"  aftr={args.aftr_ip6}")

    # RFC 6887 §8.5 — background listener for unsolicited multicast ANNOUNCE,
    # so a (spoofed) epoch reset triggers a real mapping-renewal storm (T9).
    threading.Thread(
        target=_announce_listener,
        args=(args.b4_ip6, args.aftr_ip6),
        daemon=True,
    ).start()

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(
                target=_handle_client,
                args=(data, addr, args.b4_ip6, args.aftr_ip6, sock),
                daemon=True,
            ).start()
        except KeyboardInterrupt:
            print("\n[!] PCP Proxy shutting down.")
            break
        except Exception as e:
            print(f"[!] {e}")

    sock.close()


if __name__ == "__main__":
    main()
