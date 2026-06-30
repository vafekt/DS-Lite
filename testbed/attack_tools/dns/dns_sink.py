#!/usr/bin/python3
# dns_sink.py — a UDP DNS endpoint that NEVER answers. Models a slow/unresponsive
# authoritative server, which keeps the B4 resolver's query in flight long enough
# for the off-path SADDNS-style poisoning window (T11). Bind to a specific addr so
# it does not clash with a real resolver on the same host.
import socket
import sys

addr = sys.argv[1] if len(sys.argv) > 1 else "::"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 53
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port))
print(f"[dns-sink] swallowing queries on [{addr}]:{port} (never answers)", flush=True)
while True:
    s.recvfrom(2048)
