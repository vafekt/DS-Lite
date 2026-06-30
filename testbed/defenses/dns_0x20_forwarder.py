#!/usr/bin/python3
# dns_0x20_forwarder.py — a minimal recursive DNS forwarder that implements the
# DNS-0x20 defence of Dagon, Antonakakis, Vixie, Jinmei & Lee, "Increased DNS
# Forgery Resistance Through 0x20-Bit Encoding" (ACM CCS 2008).
#
# This is the B4-side resolver that the off-path attacker targets when the B4
# resolves the AFTR FQDN (RFC 6334). It is the place the 0x20 defence lives.
#
# 0x20 algorithm (Dagon §3): before sending a query upstream, randomise the CASE
# of every letter in the QNAME (DNS names are case-insensitive for matching but
# case-PRESERVING on the wire). The authoritative server echoes the QNAME with
# its case intact. The resolver accepts a reply only if the QNAME case matches
# the random pattern it sent. An off-path attacker cannot see the query, so it
# cannot reproduce the case pattern — its forged reply is dropped. This is pure
# DNS-layer entropy (≈ one extra bit per letter), on top of TXID + source port.
#
# Toggle:  --zerox20 1  (defence ON, randomise+verify case) | 0 (OFF, baseline).
# Stock dnsmasq 2.90 has no 0x20; production resolvers do (e.g. unbound
# use-caps-for-id: yes). We implement Dagon's exact mechanism here so it can be
# switched on/off against the live attack.
import argparse
import os
import random
import socket
import struct
import sys
import threading
import time

CACHE = {}            # qname(lower) -> (ipv6_str, expiry)
CACHE_LOCK = threading.Lock()


def parse_question(data):
    """Return (txid, labels[list of raw-case bytes], qtype, qclass, qend)."""
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


def randomise_case(labels):
    out = []
    for l in labels:
        b = bytearray(l)
        for i, c in enumerate(b):
            if 65 <= c <= 90 or 97 <= c <= 122:        # ASCII letter
                b[i] = (c & ~0x20) | (random.getrandbits(1) << 5)
        out.append(bytes(b))
    return out


def labels_lower(labels):
    return tuple(l.lower() for l in labels)


def build_query(txid, labels, qtype):
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)   # RD=1
    return hdr + build_qname(labels) + struct.pack("!HH", qtype, 1)


def build_answer_aaaa(txid, labels, ipv6):
    # response to the CLIENT: header (QR=1), echo question (lowercase), 1 AAAA RR
    q = build_qname(labels) + struct.pack("!HH", 28, 1)
    hdr = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, ipv6)
    return hdr + q + rr


def extract_reply(data, qend):
    """Return (txid, labels-as-sent-case, first AAAA ipv6 or None)."""
    txid = struct.unpack("!H", data[0:2])[0]
    _, labels, qtype, qclass, off = parse_question(data)
    ancount = struct.unpack("!H", data[6:8])[0]
    ipv6 = None
    for _ in range(ancount):
        # name (compressed or not)
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while data[off] != 0:
                off += 1 + data[off]
            off += 1
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if rtype == 28 and rdlen == 16 and ipv6 is None:
            ipv6 = socket.inet_ntop(socket.AF_INET6, data[off:off + 16])
        off += rdlen
    return txid, labels, ipv6


def run(a):
    fam = socket.AF_INET6 if ":" in a.listen_ip else socket.AF_INET
    srv = socket.socket(fam, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.listen_ip, a.listen_port))
    up_fam = socket.AF_INET6 if ":" in a.upstream else socket.AF_INET
    print(f"[0x20-fwd] listen {a.listen_ip}:{a.listen_port} upstream {a.upstream} "
          f"src-port {a.src_port} 0x20={'ON' if a.zerox20 else 'OFF'}", flush=True)
    while True:
        data, caddr = srv.recvfrom(2048)
        try:
            ctxid, labels, qtype, qclass, qend = parse_question(data)
        except Exception:
            continue
        key = labels_lower(labels)
        with CACHE_LOCK:
            hit = CACHE.get(key)
        if hit and hit[1] > time.time():
            srv.sendto(build_answer_aaaa(ctxid, [l.lower() for l in labels], hit[0]), caddr)
            continue
        # forward upstream with a fixed source port (models a port the attacker
        # already derandomised, e.g. via SADDNS) and a random upstream TXID.
        up = socket.socket(up_fam, socket.SOCK_DGRAM)
        up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            up.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 33554432)  # 32 MB
        except Exception:
            pass
        up.bind((a.src_ip, a.src_port))
        up.settimeout(a.timeout)
        utxid = random.randint(0, 0xFFFF)
        sent_labels = randomise_case(labels) if a.zerox20 else [l for l in labels]
        up.sendto(build_query(utxid, sent_labels, qtype), (a.upstream, 53))
        answer = None
        deadline = time.time() + a.timeout
        while time.time() < deadline:
            try:
                rdata, raddr = up.recvfrom(2048)
            except socket.timeout:
                break
            if raddr[0] != a.upstream:
                continue
            try:
                rtxid, rlabels, ipv6 = extract_reply(rdata, qend)
            except Exception:
                continue
            if rtxid != utxid:
                continue                       # TXID mismatch
            if a.zerox20 and tuple(rlabels) != tuple(sent_labels):
                print(f"[0x20-fwd] DROP reply (case mismatch) from {raddr[0]} "
                      f"txid={rtxid}", flush=True)
                continue                       # 0x20: case must match
            if ipv6:
                answer = ipv6
                break
        up.close()
        if answer:
            with CACHE_LOCK:
                CACHE[key] = (answer, time.time() + 60)
            srv.sendto(build_answer_aaaa(ctxid, [l.lower() for l in labels], answer), caddr)
            print(f"[0x20-fwd] cached {b'.'.join(key).decode()} -> {answer}", flush=True)
        else:
            # SERVFAIL
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
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--zerox20", type=int, default=0)
    run(p.parse_args())


if __name__ == "__main__":
    main()
