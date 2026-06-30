#!/usr/bin/python3
# snmpv3_usm.py — SNMPv3 User-based Security Model (USM), authNoPriv, with the
# engineID<->address pinning fix from:
#   Lawrence, Traynor et al., "Under New Management: Practical Attacks on
#   SNMPv3" (USENIX WOOT 2012), §"Fixing the Vulnerability".
#
# The paper shows SNMPv3's *discovery* is unauthenticated, letting an adversary
# force key selection / redirect. Its fix: do not trust discovery to choose the
# key — keep a pinned snmpEngineID<->address list and authenticate every request
# (USM auth). We implement that: the agent has a fixed authoritative engineID
# pinned at the manager, and every request must carry a valid HMAC-SHA-96
# msgAuthenticationParameters keyed by the user's localized key (RFC 3414 §6),
# inside the engineBoots/engineTime timeliness window (RFC 3414 §3.2,
# anti-replay). Unauthenticated SNMPv1/v2c (the T14/T15 attack) is dropped.
#
# authNoPriv (not authPriv) because the lab container has no AES (no
# cryptography/pycryptodome, no network). Auth alone already blocks T14 (SET)
# and T15 (GET): an attacker without the user key cannot forge a valid request,
# so the agent never acts on or replies to it. Adding privacy (AES-CFB) would
# additionally encrypt responses on the wire and is a drop-in once AES exists.
#
# Self-contained BER so it does not couple to the agent's encoder.
import hashlib
import hmac
import struct

USM_SECURITY_MODEL = 3
MSG_FLAG_AUTH = 0x01
MSG_FLAG_PRIV = 0x02
MSG_FLAG_REPORTABLE = 0x04
AUTH_PARAM_LEN = 12          # HMAC-SHA-96 truncation (RFC 3414 §6.3.1)


# ── minimal BER ──────────────────────────────────────────────────────────────
def _len(n):
    if n < 0x80:
        return bytes([n])
    b = b""
    while n:
        b = bytes([n & 0xFF]) + b
        n >>= 8
    return bytes([0x80 | len(b)]) + b


def tlv(tag, val):
    return bytes([tag]) + _len(len(val)) + val


def enc_int(n):
    if n == 0:
        return tlv(0x02, b"\x00")
    b = b""
    neg = n < 0
    nn = n if not neg else (~n)
    while nn:
        b = bytes([nn & 0xFF]) + b
        nn >>= 8
    if not b:
        b = b"\x00"
    if not neg and (b[0] & 0x80):
        b = b"\x00" + b
    return tlv(0x02, b)


def enc_oct(b):
    if isinstance(b, str):
        b = b.encode()
    return tlv(0x04, b)


def enc_seq(b):
    return tlv(0x30, b)


def rd_tlv(buf, off):
    """Return (tag, value_bytes, value_offset, next_offset)."""
    tag = buf[off]
    off += 1
    ln = buf[off]
    off += 1
    if ln & 0x80:
        nb = ln & 0x7F
        ln = int.from_bytes(buf[off:off + nb], "big")
        off += nb
    return tag, buf[off:off + ln], off, off + ln


# ── RFC 3414 §A.2.2: password -> key, then localize to the engine ────────────
def password_to_key_sha1(password, engine_id):
    pw = password.encode() if isinstance(password, str) else password
    if not pw:
        pw = b"\x00"
    h = hashlib.sha1()
    # expand to 2^20 bytes by cycling the password
    count = 0
    pwlen = len(pw)
    buf = bytearray(64)
    total = 0
    while total < 1048576:
        for i in range(64):
            buf[i] = pw[count % pwlen]
            count += 1
        h.update(buf)
        total += 64
    ku = h.digest()
    return hashlib.sha1(ku + engine_id + ku).digest()


def hmac_sha96(localized_key, message):
    return hmac.new(localized_key, message, hashlib.sha1).digest()[:AUTH_PARAM_LEN]


# ── USM message build / parse ────────────────────────────────────────────────
def build_usm_message(msg_id, engine_id, engine_boots, engine_time,
                      user, localized_key, scoped_pdu, reportable=True):
    """Build a complete authNoPriv SNMPv3 message and sign it."""
    flags = MSG_FLAG_AUTH | (MSG_FLAG_REPORTABLE if reportable else 0)
    header = enc_seq(
        enc_int(msg_id) + enc_int(65507) +
        enc_oct(bytes([flags])) + enc_int(USM_SECURITY_MODEL))

    def usm_params(auth_param):
        return enc_seq(
            enc_oct(engine_id) + enc_int(engine_boots) + enc_int(engine_time) +
            enc_oct(user) + enc_oct(auth_param) + enc_oct(b""))

    # 1st pass: zeroed auth param
    sec0 = enc_oct(usm_params(b"\x00" * AUTH_PARAM_LEN))
    msg0 = enc_seq(enc_int(3) + header + sec0 + scoped_pdu)
    # compute HMAC over the whole message, then splice the tag in
    tag = hmac_sha96(localized_key, msg0)
    sec1 = enc_oct(usm_params(tag))
    return enc_seq(enc_int(3) + header + sec1 + scoped_pdu)


def parse_usm_message(data):
    """Return a dict with version, flags, engine ids, user, auth offset, etc.
    Returns None if not a parseable SNMPv3 message."""
    try:
        tag, body, voff, _ = rd_tlv(data, 0)
        if tag != 0x30:
            return None
        off = voff
        t, ver, _, off = rd_tlv(data, off)
        version = int.from_bytes(ver, "big")
        if version != 3:
            return {"version": version}
        # header
        t, hdr, hvoff, off = rd_tlv(data, off)
        ho = hvoff
        t, mid, _, ho = rd_tlv(data, ho)
        t, mms, _, ho = rd_tlv(data, ho)
        t, flags, _, ho = rd_tlv(data, ho)
        t, smod, _, ho = rd_tlv(data, ho)
        # security params (OCTET STRING wrapping a SEQUENCE)
        t, sec, secvoff, off = rd_tlv(data, off)
        st, susm, suvoff, _ = rd_tlv(data, secvoff)
        so = suvoff
        t, eng, _, so = rd_tlv(data, so)
        t, boots, _, so = rd_tlv(data, so)
        t, etime, _, so = rd_tlv(data, so)
        t, user, _, so = rd_tlv(data, so)
        # auth param: capture absolute offset of its VALUE in the datagram
        at, aval, avoff, anext = rd_tlv(data, so)
        so = anext
        scoped_off = off
        return {
            "version": 3,
            "msg_id": int.from_bytes(mid, "big"),
            "flags": flags[0] if flags else 0,
            "engine_id": eng,
            "engine_boots": int.from_bytes(boots, "big"),
            "engine_time": int.from_bytes(etime, "big"),
            "user": user,
            "auth_value_off": avoff,
            "auth_value_len": len(aval),
            "auth_param": aval,
            "scoped_pdu": data[scoped_off:],
        }
    except Exception:
        return None


def verify_auth(data, parsed, localized_key):
    """Recompute HMAC with the auth param field zeroed; constant-time compare."""
    if parsed.get("flags", 0) & MSG_FLAG_AUTH == 0:
        return False
    if parsed["auth_value_len"] != AUTH_PARAM_LEN:
        return False
    o = parsed["auth_value_off"]
    zeroed = data[:o] + b"\x00" * AUTH_PARAM_LEN + data[o + AUTH_PARAM_LEN:]
    expect = hmac_sha96(localized_key, zeroed)
    return hmac.compare_digest(expect, parsed["auth_param"])


def build_scoped_pdu(context_engine_id, pdu_bytes, context_name=b""):
    return enc_seq(enc_oct(context_engine_id) + enc_oct(context_name) + pdu_bytes)


if __name__ == "__main__":
    eid = b"\x80\x00\x1f\x88\x80" + b"dslite-aftr1"
    key = password_to_key_sha1("S3cr3t-oam-2026", eid)
    spdu = build_scoped_pdu(eid, tlv(0xA0, enc_int(1) + enc_int(0) + enc_int(0) + enc_seq(b"")))
    m = build_usm_message(1, eid, 1, 100, b"oamuser", key, spdu)
    p = parse_usm_message(m)
    assert p and p["version"] == 3 and p["user"] == b"oamuser"
    assert verify_auth(m, p, key), "self auth must verify"
    # tamper: flip a scoped-pdu byte -> must fail
    bad = bytearray(m); bad[-1] ^= 0x01
    p2 = parse_usm_message(bytes(bad))
    assert not verify_auth(bytes(bad), p2, key), "tamper must fail"
    # wrong key -> must fail
    assert not verify_auth(m, p, password_to_key_sha1("wrong", eid))
    print("snmpv3_usm self-test OK (auth verifies, tamper/wrong-key rejected)")
