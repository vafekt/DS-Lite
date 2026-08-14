#!/usr/bin/python
# Victim Connectivity Monitor – DS-Lite NAT Exhaustion Impact Demo
#
# Run this from the client1 or client2 network namespace while running the
# attack tools in the attacker namespace.  Shows connection success/failure
# and latency in real-time so you can observe service degradation.
#
# Usage:
#   ip netns exec client1 python3 /testbed/attack_tools/victim_test.py
#   ip netns exec client2 python3 /testbed/attack_tools/victim_test.py
#
# Or from an already-exec'd client shell:
#   python3 /testbed/attack_tools/victim_test.py [--target 198.51.100.2] [--port 80]
#
# Expected observations:
#   Before attack : OK  ~5-20 ms   100% success
#   UDP flood only : mostly OK, occasional delay as GC evicts conntrack entries
#   + nat_hold.py  : FAIL / TIMEOUT – server busy (nc blocked) + conntrack full
import argparse
import collections
import socket
import sys
import time

CYAN   = '\033[0;36m'
GREEN  = '\033[0;32m'
YELLOW = '\033[1;33m'
RED    = '\033[0;31m'
BOLD   = '\033[1m'
DIM    = '\033[2m'
NC     = '\033[0m'


def tcp_probe(target, port, timeout):
    """
    Open a TCP connection, send a minimal HTTP GET, read first bytes of response.
    Returns (success: bool, latency_ms: float, note: str).
    """
    t0 = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.sendall(b'GET / HTTP/1.0\r\nHost: ' + target.encode() + b'\r\n\r\n')
        resp = s.recv(64)
        s.close()
        ms = (time.monotonic() - t0) * 1000
        first = resp.split(b'\r\n')[0].decode(errors='replace') if resp else '(empty)'
        return True, ms, first
    except socket.timeout:
        ms = (time.monotonic() - t0) * 1000
        return False, ms, 'TIMEOUT'
    except ConnectionRefusedError:
        ms = (time.monotonic() - t0) * 1000
        return False, ms, 'CONN_REFUSED'
    except OSError as e:
        ms = (time.monotonic() - t0) * 1000
        return False, ms, str(e)[:35]


def rate_bar(pct, width=20):
    filled = int(pct / 100 * width)
    return '█' * filled + '░' * (width - filled)


def main():
    p = argparse.ArgumentParser(
        description='Victim connectivity monitor – observe DS-Lite NAT exhaustion impact.',
        epilog=(
            'Run from client1/client2 netns:\n'
            '  ip netns exec client1 python3 /testbed/attack_tools/victim_test.py\n\n'
            'Attack tools (attacker netns):\n'
            '  python3 nat_exhaustion.py eth0 --mode fast --proto udp \\\n'
            '      --src-ip4 <IP> --gateway 10.0.1.1 --dst-ip4 198.51.100.2 \\\n'
            '      --threads 8 --batch 256\n'
            '  python3 nat_hold.py --target 198.51.100.2 --port 80 --conns 200'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('--target',   default='198.51.100.2',
                   help='Target IP (default: 198.51.100.2)')
    p.add_argument('--port',     type=int, default=80,
                   help='Target port (default: 80)')
    p.add_argument('--interval', type=float, default=1.0,
                   help='Probe interval in seconds (default: 1.0)')
    p.add_argument('--timeout',  type=float, default=5.0,
                   help='Per-probe TCP timeout (default: 5.0s)')
    p.add_argument('--window',   type=int, default=10,
                   help='Rolling window size for success rate (default: 10)')
    args = p.parse_args()

    print(f"{BOLD}╔══════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}║   Victim Connectivity Monitor  –  DS-Lite NAT Exhaustion     ║{NC}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{NC}")
    print(f"  Target  : {args.target}:{args.port}")
    print(f"  Interval: {args.interval}s   Timeout: {args.timeout}s   "
          f"Window: {args.window} probes")
    print()
    print(f"  {'#':>5}  {'Status':<8}  {'Latency':>9}  "
          f"{'Roll%':>6}  {'Bar (last ' + str(args.window) + ')':22}  Note")
    print("  " + "─" * 72)

    history  = collections.deque(maxlen=args.window)
    total    = success = fail = 0
    sum_ms   = 0.0

    try:
        while True:
            total += 1
            ok, ms, note = tcp_probe(args.target, args.port, args.timeout)
            history.append(ok)

            if ok:
                success += 1
                sum_ms  += ms
                result_s = f"{GREEN}OK{NC}      "
                ms_s     = f"{GREEN}{ms:7.1f} ms{NC}"
            else:
                fail    += 1
                result_s = f"{RED}FAIL{NC}    "
                ms_s     = f"{RED}{ms:7.1f} ms{NC}"

            roll_rate = sum(history) / len(history) * 100 if history else 100.0

            if roll_rate >= 90:
                rcol = GREEN
            elif roll_rate >= 50:
                rcol = YELLOW
            else:
                rcol = RED

            bar = rate_bar(roll_rate)

            print(
                f"  {total:>5}  {result_s}  {ms_s}  "
                f"{rcol}{roll_rate:5.1f}%{NC}  {rcol}{bar}{NC}  "
                f"{DIM}{note[:30]}{NC}"
            )

            time.sleep(args.interval)

    except KeyboardInterrupt:
        pass

    print()
    print(f"  {BOLD}── Summary ──────────────────────────────────────────{NC}")
    print(f"  Total probes   : {total}")
    avg = sum_ms / success if success else 0
    print(f"  Success        : {GREEN}{success}{NC}  ({success/total*100:.1f}%)")
    print(f"  Failures       : {RED}{fail}{NC}  ({fail/total*100:.1f}%)")
    if success:
        print(f"  Avg latency    : {avg:.1f} ms")
    print()


if __name__ == '__main__':
    main()
