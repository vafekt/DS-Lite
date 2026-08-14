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
# pinned at the manager, and every request must carry a valid HMAC
# msgAuthenticationParameters keyed by the user's localized key, inside the
# engineBoots/engineTime timeliness window (anti-replay). Unauthenticated
# SNMPv1/v2c (the T10/T11 attack) is dropped.
#
# Authentication protocol. The DS-Lite MIB's own Security Considerations
# (RFC 7870 §9) require SNMPv3 USM with authentication and privacy. USM's
# original HMAC-SHA-96 (RFC 3414, 2002) is dated, so the default here is the
# modern usmHMAC192SHA256 protocol of RFC 7860 (2016) — HMAC-SHA-256 truncated
# to 192 bits — with the RFC 3414 SHA-1 protocol kept selectable for comparison.
# Both localize the key to the engine by the RFC 3414 §A.2.2 procedure, run with
# the chosen hash.
#
# authNoPriv (not authPriv) because the lab container has no AES (no
# cryptography/pycryptodome, no network). Auth alone already blocks T10 (SET)
# and T11 (GET): an attacker without the user key cannot forge a valid request,
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
AUTH_PARAM_LEN = 12          # legacy HMAC-SHA-96 truncation (RFC 3414 §6.3.1)


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


# ── authentication protocols ─────────────────────────────────────────────────
# RFC 3414 §A.2.2 key localization, run with a selectable hash, plus HMAC
# truncated to the protocol's msgAuthenticationParameters length.
class AuthProto:
    __slots__ = ("name", "hashfn", "trunc")

    def __init__(self, name, hashfn, trunc):
        self.name = name
        self.hashfn = hashfn
        self.trunc = trunc

    def localize(self, password, engine_id):
        return password_to_key(password, engine_id, self.hashfn)

    def sign(self, localized_key, message):
        return hmac.new(localized_key, message, self.hashfn).digest()[:self.trunc]


SHA1 = AuthProto("usmHMACSHA", hashlib.sha1, 12)          # RFC 3414 HMAC-SHA-96
SHA256 = AuthProto("usmHMAC192SHA256", hashlib.sha256, 24)  # RFC 7860 HMAC-SHA-256/192
DEFAULT_AUTH = SHA256


# ── RFC 3414 §A.2.2: password -> key, then localize to the engine ────────────
def password_to_key(password, engine_id, hashfn=hashlib.sha256):
    pw = password.encode() if isinstance(password, str) else password
    if not pw:
        pw = b"\x00"
    h = hashfn()
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
    return hashfn(ku + engine_id + ku).digest()


def password_to_key_sha1(password, engine_id):
    return password_to_key(password, engine_id, hashlib.sha1)


def password_to_key_sha256(password, engine_id):
    return password_to_key(password, engine_id, hashlib.sha256)


# ── USM message build / parse ────────────────────────────────────────────────
def build_usm_message(msg_id, engine_id, engine_boots, engine_time,
                      user, localized_key, scoped_pdu, reportable=True,
                      auth=DEFAULT_AUTH):
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
    sec0 = enc_oct(usm_params(b"\x00" * auth.trunc))
    msg0 = enc_seq(enc_int(3) + header + sec0 + scoped_pdu)
    # compute HMAC over the whole message, then splice the tag in
    tag = auth.sign(localized_key, msg0)
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


def verify_auth(data, parsed, localized_key, auth=DEFAULT_AUTH):
    """Recompute HMAC with the auth param field zeroed; constant-time compare."""
    if parsed.get("flags", 0) & MSG_FLAG_AUTH == 0:
        return False
    if parsed["auth_value_len"] != auth.trunc:
        return False
    o = parsed["auth_value_off"]
    zeroed = data[:o] + b"\x00" * auth.trunc + data[o + auth.trunc:]
    expect = auth.sign(localized_key, zeroed)
    return hmac.compare_digest(expect, parsed["auth_param"])


def build_scoped_pdu(context_engine_id, pdu_bytes, context_name=b""):
    return enc_seq(enc_oct(context_engine_id) + enc_oct(context_name) + pdu_bytes)


if __name__ == "__main__":
    eid = b"\x80\x00\x1f\x88\x80" + b"dslite-aftr1"
    for proto in (SHA256, SHA1):
        key = proto.localize("S3cr3t-oam-2026", eid)
        spdu = build_scoped_pdu(eid, tlv(0xA0, enc_int(1) + enc_int(0) + enc_int(0) + enc_seq(b"")))
        m = build_usm_message(1, eid, 1, 100, b"oamuser", key, spdu, auth=proto)
        p = parse_usm_message(m)
        assert p and p["version"] == 3 and p["user"] == b"oamuser"
        assert p["auth_value_len"] == proto.trunc
        assert verify_auth(m, p, key, auth=proto), f"{proto.name}: self auth must verify"
        # tamper: flip a scoped-pdu byte -> must fail
        bad = bytearray(m); bad[-1] ^= 0x01
        p2 = parse_usm_message(bytes(bad))
        assert not verify_auth(bytes(bad), p2, key, auth=proto), f"{proto.name}: tamper must fail"
        # wrong key -> must fail
        assert not verify_auth(m, p, proto.localize("wrong", eid), auth=proto)
        print(f"snmpv3_usm self-test OK for {proto.name} "
              f"(auth verifies, tamper/wrong-key rejected)")
