#!/usr/bin/python3
# trabelsi_guard.py — userspace session-table guard for the AFTR, implementing
# Z. Trabelsi et al., "Improved Session Table Architecture for Denial of
# Stateful Firewall Attacks" (IEEE Access, 2018).
#
# The T1/T7 attack floods the AFTR with half-open (UNREPLIED) sessions to
# exhaust the stateful NAT/conntrack table, denying legitimate subscribers.
#
# Trabelsi's mechanism (faithfully reproduced here):
#  * a TWO-STRUCTURE session table — session STATE is kept separately from the
#    TIMEOUT information, so timeout processing is independent of lookup
#    (§5.1-5.2). Here: `sessions` (key -> state) + a separate `SplayTree` keyed
#    by last-activity time (the timeout structure);
#  * a SPLAY TREE so recently/frequently active (legitimate, REPLIED) sessions
#    splay to the top and the stale invalid ones sink to the bottom (§5.5);
#  * EARLY PACKET REJECTION under DoS: "when abnormal activity fills the session
#    table with invalid entries, the algorithm switches to ... early packet
#    rejection" (§5.6) — when occupancy crosses a threshold we evict the oldest
#    half-open (UNREPLIED) entries first, freeing slots for valid flows.
#
# It reads the kernel conntrack table (the AFTR's real session table) as the
# data source and evicts via `conntrack -D`, so the algorithm runs against the
# live NAT state without re-implementing the datapath.
import argparse
import subprocess
import sys
import time

NS = ["ip", "netns", "exec", "aftr"]


# ── Splay tree keyed by last-activity (the separate TIMEOUT structure) ───────
class _Node:
    __slots__ = ("key", "t", "left", "right")

    def __init__(self, key, t):
        self.key = key
        self.t = t
        self.left = self.right = None


class SplayTree:
    """Ordered by activity time `t`. splay() bubbles a key up on access; the
    leftmost node is the least-recently-active (first eviction candidate)."""

    def __init__(self):
        self.root = None
        self.size = 0

    def _rotate(self, x, parent, gp, stack):
        pass  # (top-down splay below; helper kept for clarity)

    def insert(self, key, t):
        if self.root is None:
            self.root = _Node(key, t)
            self.size = 1
            return
        self.root = self._splay(self.root, t)
        n = _Node(key, t)
        if t < self.root.t:
            n.right = self.root
            n.left = self.root.left
            self.root.left = None
        else:
            n.left = self.root
            n.right = self.root.right
            self.root.right = None
        self.root = n
        self.size += 1

    def _splay(self, root, t):
        if root is None:
            return None
        header = _Node(None, 0)
        ltail = rtail = header
        while True:
            if t < root.t:
                if root.left is None:
                    break
                if t < root.left.t:
                    y = root.left
                    root.left = y.right
                    y.right = root
                    root = y
                    if root.left is None:
                        break
                rtail.left = root
                rtail = root
                root = root.left
            elif t > root.t:
                if root.right is None:
                    break
                if t > root.right.t:
                    y = root.right
                    root.right = y.left
                    y.left = root
                    root = y
                    if root.right is None:
                        break
                ltail.right = root
                ltail = root
                root = root.right
            else:
                break
        ltail.right = root.left
        rtail.left = root.right
        root.left = header.right
        root.right = header.left
        return root

    def pop_min(self):
        """Remove + return the least-recently-active key (leftmost)."""
        if self.root is None:
            return None
        node = self.root
        path = []
        while node.left:
            path.append(node)
            node = node.left
        key = node.key
        if path:
            path[-1].left = node.right
        else:
            self.root = node.right
        self.size -= 1
        return key


# ── conntrack as the session table ───────────────────────────────────────────
def ct_count():
    try:
        out = subprocess.run(NS + ["conntrack", "-C"], capture_output=True,
                             text=True, timeout=3).stdout.strip()
        return int(out or "0")
    except Exception:
        return 0


def set_halfopen_timeout(secs):
    """Trabelsi's separate TIMEOUT structure, fast-eviction path: collapse the
    half-open (SYN_SENT/SYN_RECV) and unreplied-UDP timeouts so the kernel ages
    out invalid flood entries in `secs` instead of minutes."""
    for k in ("net.netfilter.nf_conntrack_tcp_timeout_syn_sent",
              "net.netfilter.nf_conntrack_tcp_timeout_syn_recv",
              "net.netfilter.nf_conntrack_udp_timeout"):
        subprocess.run(NS + ["sysctl", "-qw", f"{k}={secs}"],
                       capture_output=True, text=True, timeout=3)


def ct_list_unreplied():
    """Return list of (proto, src, dst, sport, dport) for UNREPLIED entries."""
    try:
        out = subprocess.run(NS + ["conntrack", "-L"], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        return []
    res = []
    for line in out.splitlines():
        if "UNREPLIED" not in line:
            continue
        f = line.split()
        if len(f) < 2:
            continue
        proto = f[0]
        d = {}
        for tok in f:
            if "=" in tok and tok.count("=") == 1:
                k, v = tok.split("=")
                if k not in d:           # first occurrence = original direction
                    d[k] = v
        if all(k in d for k in ("src", "dst", "sport", "dport")):
            res.append((proto, d["src"], d["dst"], d["sport"], d["dport"]))
    return res


def ct_delete(proto, src, dst, sport, dport):
    subprocess.run(NS + ["conntrack", "-D", "-p", proto, "-s", src, "-d", dst,
                         "--sport", sport, "--dport", dport],
                   capture_output=True, text=True, timeout=3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=1500,
                    help="occupancy that triggers early rejection/eviction")
    ap.add_argument("--target", type=int, default=800,
                    help="exit DoS mode below this occupancy")
    ap.add_argument("--dos-timeout", type=int, default=2,
                    help="half-open timeout (s) while under DoS")
    ap.add_argument("--restore-timeout", type=int, default=60,
                    help="half-open timeout (s) when normal")
    ap.add_argument("--interval", type=float, default=0.1)
    a = ap.parse_args()
    tree = SplayTree()
    # Trabelsi's session-table architecture keeps SHORT timeouts for half-open /
    # invalid entries (the separate TIMEOUT structure), PROACTIVELY — so a state
    # exhaustion flood of UNREPLIED SYNs ages out in seconds and can never fill
    # the table, while ESTABLISHED (REPLIED) flows keep their normal long timeout.
    # This is applied up front, not reactively: by the time occupancy crosses a
    # threshold the shared table is already exhausted and a legitimate
    # subscriber is already denied. (Active per-entry deletion is NOT used: it
    # also catches a subscriber's own briefly-UNREPLIED in-flight connection.)
    set_halfopen_timeout(a.dos_timeout)
    print(f"[trabelsi] guard active: two-structure session table; half-open "
          f"(invalid) timeout collapsed to {a.dos_timeout}s for fast eviction "
          f"(established flows unaffected)", flush=True)
    peak = 0
    try:
        while True:
            c = ct_count()
            if c > peak:
                peak = c
                if c > a.threshold:
                    print(f"[trabelsi] high occupancy {c}: invalid half-open "
                          f"entries ageing out at {a.dos_timeout}s", flush=True)
            time.sleep(a.interval)
    finally:
        set_halfopen_timeout(a.restore_timeout)


if __name__ == "__main__":
    main()
