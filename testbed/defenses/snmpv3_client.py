#!/usr/bin/python3
# snmpv3_client.py — legit SNMPv3 USM authNoPriv manager (the authorized OAM
# station). Proves that with the T14/T15 defence ON, a holder of the user key
# can still GET/SET, while the unauthenticated attacker (snmp_attack.py, v2c)
# is dropped. engineID is pinned (no discovery), per "Under New Management".
import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import snmpv3_usm as usm

ENGINE_ID = b"\x80\x00\x1f\x88\x80" + b"dslite-aftr1"
BOOTS = 1


def enc_oid(oid):
    first = 40 * oid[0] + oid[1]
    body = bytearray([first])
    for n in oid[2:]:
        if n < 0x80:
            body.append(n)
        else:
            stack = []
            while n:
                stack.insert(0, n & 0x7F)
                n >>= 7
            for i in range(len(stack) - 1):
                stack[i] |= 0x80
            body.extend(stack)
    return usm.tlv(0x06, bytes(body))


def varbind(oid, val_tlv):
    return usm.tlv(0x30, enc_oid(oid) + val_tlv)


def get_pdu(req_id, oid):
    vbl = usm.tlv(0x30, varbind(oid, usm.tlv(0x05, b"")))   # value = NULL
    return usm.tlv(0xA0, usm.enc_int(req_id) + usm.enc_int(0) + usm.enc_int(0) + vbl)


def set_pdu(req_id, oid, ival):
    vbl = usm.tlv(0x30, varbind(oid, usm.enc_int(ival)))
    return usm.tlv(0xA3, usm.enc_int(req_id) + usm.enc_int(0) + usm.enc_int(0) + vbl)


def request(host, port, user, key, pdu, msg_id=1234):
    scoped = usm.build_scoped_pdu(ENGINE_ID, pdu)
    et = int(time.time()) & 0x7FFFFFFF
    # the agent measures time since its own start; we send our wallclock-derived
    # value and rely on the shared host clock + ±150s window.
    msg = usm.build_usm_message(msg_id, ENGINE_ID, BOOTS, et, user, key, scoped)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(msg, (host, port))
    try:
        data, _ = s.recvfrom(65535)
    except socket.timeout:
        return None, "timeout (no authenticated response)"
    p = usm.parse_usm_message(data)
    if not p or p.get("version") != 3:
        return None, "non-USM response"
    if not usm.verify_auth(data, p, key):
        return None, "response auth FAILED"
    return p["scoped_pdu"], "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=161)
    ap.add_argument("--user", default="oamuser")
    ap.add_argument("--secret", default=os.environ.get("SNMP_SECRET", "S3cr3t-oam-2026"))
    ap.add_argument("--oid", default="1.3.6.1.2.1.240.1.3.1.1")
    ap.add_argument("--set", type=int, default=None, dest="setval")
    a = ap.parse_args()
    key = usm.password_to_key_sha1(a.secret, ENGINE_ID)
    oid = tuple(int(x) for x in a.oid.split("."))
    pdu = set_pdu(1234, oid, a.setval) if a.setval is not None else get_pdu(1234, oid)
    scoped, status = request(a.host, a.port, a.user.encode(), key, pdu)
    if scoped is None:
        print(f"[usm-client] FAILED: {status}")
        sys.exit(1)
    # crude value extraction: last INTEGER in the response scoped PDU
    val = None
    i = 0
    while i < len(scoped) - 1:
        if scoped[i] == 0x02:
            ln = scoped[i + 1]
            if ln and i + 2 + ln <= len(scoped):
                val = int.from_bytes(scoped[i + 2:i + 2 + ln], "big", signed=True)
        i += 1
    action = "SET" if a.setval is not None else "GET"
    print(f"[usm-client] {action} {a.oid} OK (authenticated); response integer={val}")


if __name__ == "__main__":
    main()
