#!/usr/bin/python3
# dns_cookies_forwarder.py - B4-side recursive DNS forwarder that implements the
# DNS Cookies defence (Eastlake & Andrews, "Domain Name System (DNS) Cookies",
# RFC 7873, 2016). Companion to dns_0x20_forwarder.py; the SAME off-path attacker
# (dns_offpath_poison.py) is run against it so the two defences are comparable.
#
# RFC 7873 (Sec. 5): the resolver puts a random 8-byte Client Cookie in an
# EDNS(0) COOKIE option on every query. A legitimate authoritative echoes the
# Client Cookie (and appends a Server Cookie). The resolver accepts a reply ONLY
# if it carries the correct Client Cookie. An OFF-PATH attacker cannot see the
# query, so it cannot know the 64-bit Client Cookie; every forged reply is
# dropped even with the right upstream port and a matching TXID.
#
# --cookies 1 (defence ON) | 0 (OFF: accept any TXID-matching reply = baseline).
import argparse
import random
import secrets
import socket
import struct
import threading
import time

CACHE = {}
CACHE_LOCK = threading.Lock()


def parse_question(data):
    txid = struct.unpack("!H", data[0:2])[0]
    off = 12
    labels = []
    while True:
        ln = data[off]
        if ln == 0:
            off += 1
            break
        labels.append(data[off + 1:off + 1 + ln])
        off += 1 + ln
    qtype, qclass = struct.unpack("!HH", data[off:off + 4])
    off += 4
    return txid, labels, qtype, qclass, off


def build_qname(labels):
    out = b""
    for l in labels:
        out += bytes([len(l)]) + l
    return out + b"\x00"


def build_answer_aaaa(txid, labels, ipv6):
    q = build_qname(labels) + struct.pack("!HH", 28, 1)
    hdr = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, ipv6)
    return hdr + q + rr


def opt_cookie_rr(client_cookie):
    # EDNS(0) OPT RR (type 41) carrying one COOKIE option (option-code 10).
    rdata = struct.pack("!HH", 10, len(client_cookie)) + client_cookie
    return b"\x00" + struct.pack("!HHIH", 41, 4096, 0, len(rdata)) + rdata


def build_query(txid, labels, qtype, client_cookie):
    arcount = 1 if client_cookie else 0
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, arcount)   # RD=1
    q = build_qname(labels) + struct.pack("!HH", qtype, 1)
    return hdr + q + (opt_cookie_rr(client_cookie) if client_cookie else b"")


def skip_name(data, off):
    while True:
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln


def reply_client_cookie(data):
    """Return the Client Cookie (first 8 bytes of the reply's COOKIE option), or
    None if the reply carries no valid DNS cookie."""
    try:
        qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
        off = 12
        for _ in range(qd):
            off = skip_name(data, off) + 4
        for _ in range(an + ns):
            off = skip_name(data, off)
            _, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10 + rdlen
        for _ in range(ar):
            noff = skip_name(data, off)
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[noff:noff + 10])
            rd = noff + 10
            if rtype == 41:                       # OPT
                p, end = rd, rd + rdlen
                while p + 4 <= end:
                    ocode, olen = struct.unpack("!HH", data[p:p + 4])
                    p += 4
                    if ocode == 10 and olen >= 8:
                        return data[p:p + 8]
                    p += olen
            off = rd + rdlen
    except Exception:
        return None
    return None


def extract_aaaa(data):
    try:
        txid = struct.unpack("!H", data[0:2])[0]
        _, labels, qtype, qclass, off = parse_question(data)
        an = struct.unpack("!H", data[6:8])[0]
        ipv6 = None
        for _ in range(an):
            off = skip_name(data, off)
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            if rtype == 28 and rdlen == 16 and ipv6 is None:
                ipv6 = socket.inet_ntop(socket.AF_INET6, data[off:off + 16])
            off += rdlen
        return txid, labels, ipv6
    except Exception:
        return None, None, None


def run(a):
    fam = socket.AF_INET6 if ":" in a.listen_ip else socket.AF_INET
    srv = socket.socket(fam, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.listen_ip, a.listen_port))
    up_fam = socket.AF_INET6 if ":" in a.upstream else socket.AF_INET
    print(f"[cookie-fwd] listen {a.listen_ip}:{a.listen_port} upstream {a.upstream} "
          f"src-port {a.src_port} cookies={'ON' if a.cookies else 'OFF'}", flush=True)
    while True:
        data, caddr = srv.recvfrom(2048)
        try:
            ctxid, labels, qtype, qclass, qend = parse_question(data)
        except Exception:
            continue
        key = tuple(l.lower() for l in labels)
        with CACHE_LOCK:
            hit = CACHE.get(key)
        if hit and hit[1] > time.time():
            srv.sendto(build_answer_aaaa(ctxid, [l.lower() for l in labels], hit[0]), caddr)
            continue
        up = socket.socket(up_fam, socket.SOCK_DGRAM)
        up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            up.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 33554432)
        except Exception:
            pass
        up.bind((a.src_ip, a.src_port))
        up.settimeout(a.timeout)
        utxid = random.randint(0, 0xFFFF)
        client_cookie = secrets.token_bytes(8) if a.cookies else None
        up.sendto(build_query(utxid, labels, qtype, client_cookie), (a.upstream, 53))
        answer = None
        deadline = time.time() + a.timeout
        while time.time() < deadline:
            try:
                rdata, raddr = up.recvfrom(2048)
            except socket.timeout:
                break
            if raddr[0] != a.upstream:
                continue
            rtxid, rlabels, ipv6 = extract_aaaa(rdata)
            if rtxid != utxid:
                continue                          # TXID mismatch
            if a.cookies and reply_client_cookie(rdata) != client_cookie:
                print(f"[cookie-fwd] DROP reply (no/incorrect DNS cookie) from {raddr[0]} "
                      f"txid={rtxid}", flush=True)
                continue                          # RFC 7873: cookie must match
            if ipv6:
                answer = ipv6
                break
        up.close()
        if answer:
            with CACHE_LOCK:
                CACHE[key] = (answer, time.time() + 60)
            srv.sendto(build_answer_aaaa(ctxid, [l.lower() for l in labels], answer), caddr)
            print(f"[cookie-fwd] cached {b'.'.join(key).decode()} -> {answer}", flush=True)
        else:
            srv.sendto(struct.pack("!HHHHHH", ctxid, 0x8182, 1, 0, 0, 0) +
                       build_qname([l.lower() for l in labels]) +
                       struct.pack("!HH", qtype, 1), caddr)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen-ip", default="::1")
    p.add_argument("--listen-port", type=int, default=5354)
    p.add_argument("--upstream", required=True)
    p.add_argument("--src-ip", default="::")
    p.add_argument("--src-port", type=int, default=33333)
    p.add_argument("--timeout", type=float, default=9.0)
    p.add_argument("--cookies", type=int, default=1)
    run(p.parse_args())


if __name__ == "__main__":
    main()
