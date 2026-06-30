#!/usr/bin/python3
# Robust connection-sink: ONE process accepts and HOLDS every TCP connection
# (no fork-per-connection like socat ...,fork). It can hold thousands of
# simultaneous ESTABLISHED connections, which the T1 SIEGE phase (ESTABLISHED
# binding hold) needs. A fork-per-connection sink crashes under that load and
# silently breaks the SIEGE.
#
#   python3 conn_sink.py [port]      (default 6666)
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 6666
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', port))
srv.listen(4096)

held = []  # keep a reference so the kernel keeps each connection ESTABLISHED
while True:
    try:
        conn, _ = srv.accept()
        conn.setblocking(False)   # drain nothing, never close -> held open
        held.append(conn)
    except OSError:
        pass
