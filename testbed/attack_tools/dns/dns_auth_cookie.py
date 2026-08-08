#!/usr/bin/python3
# dns_auth_cookie.py - minimal cookie-aware authoritative server (RFC 7873). It
# answers AAAA for the queried name with a fixed IPv6 and, when the query carries
# an EDNS(0) Client Cookie, echoes it plus an 8-byte Server Cookie. Used as the
# legitimate upstream in the DNS Cookies positive control: it shows that a normal
# resolution still succeeds while the cookies defence is on (the resolver accepts
# a reply that carries the correct cookie).
import hashlib
import secrets
import socket
import struct
import sys

addr = sys.argv[1] if len(sys.argv) > 1 else "::"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 53
answer_ip = sys.argv[3] if len(sys.argv) > 3 else "2001:db8:cafe::10"
SECRET = secrets.token_bytes(16)


def skip_name(data, off):
    while True:
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln


def parse(data):
    txid = struct.unpack("!H", data[0:2])[0]
    qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
    start = 12
    off = start
    while data[off] != 0:
        off += 1 + data[off]
    off += 1
    qtype, qclass = struct.unpack("!HH", data[off:off + 4])
    qend = off + 4
    qname = data[start:qend - 4]
    off = qend
    for _ in range(an + ns):
        off = skip_name(data, off)
        _, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10 + rdlen
    client_cookie = None
    for _ in range(ar):
        noff = skip_name(data, off)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[noff:noff + 10])
        rd = noff + 10
        if rtype == 41:
            p, end = rd, rd + rdlen
            while p + 4 <= end:
                oc, ol = struct.unpack("!HH", data[p:p + 4])
                p += 4
                if oc == 10 and ol >= 8:
                    client_cookie = data[p:p + 8]
                p += ol
        off = rd + rdlen
    return txid, qname, qtype, client_cookie


s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port))
print(f"[auth-cookie] authoritative on [{addr}]:{port} -> {answer_ip}, echoes DNS cookies",
      flush=True)
while True:
    try:
        data, caddr = s.recvfrom(2048)
        txid, qname, qtype, cc = parse(data)
    except Exception:
        continue
    if qtype != 28:
        continue
    hdr = struct.pack("!HHHHHH", txid, 0x8580, 1, 1, 0, 1 if cc else 0)  # QR=1 AA=1
    q = qname + struct.pack("!HH", 28, 1)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, answer_ip)
    add = b""
    if cc:
        server_cookie = hashlib.sha256(cc + SECRET).digest()[:8]
        cookie = cc + server_cookie
        rdata = struct.pack("!HH", 10, len(cookie)) + cookie
        add = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, len(rdata)) + rdata
    s.sendto(hdr + q + rr + add, caddr)
