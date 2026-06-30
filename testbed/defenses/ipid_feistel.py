#!/usr/bin/python3
# ipid_feistel.py — Scalable Randomized IP-ID selection, the gateway defence
# proposed by Gilad & Herzberg, "Fragmentation Considered Vulnerable"
# (ACM TISSEC 15(4), 2013), Section 8.3.
#
# The T6 attack (Softwire Reassembly Poisoning) works because the inner-IPv4
# IP-ID is a PREDICTABLE per-destination counter: an off-path / spoofing
# attacker guesses the victim's next IP-ID and injects a spoofed fragment that
# shares the victim's reassembly four-tuple (src, dst, proto, id), colliding
# with the victim's genuine fragment at the AFTR and getting the whole datagram
# dropped.
#
# Gilad-Herzberg's defence (deployed at the network GATEWAY, no host changes):
# rewrite the IP-ID on the fly with a keyed pseudo-random PERMUTATION
#   id' = pi_{k_{s,d,p}}(id)
# built from a 3-round Feistel network, with one secret key per
# <source, destination, protocol> triplet, rekeyed every 2^(eta-1) packets.
#
# Guarantees the paper proves and we re-check in the self-test:
#   * pi is a bijection  -> two DIFFERENT reassembly tuples never collide after
#     rewriting (no accidental loss), even for the same <s,d,p>;
#   * fragments of the SAME datagram (same original id) map to the SAME id'
#     -> reassembly still works;
#   * id' is unpredictable from a large set -> the attacker can no longer guess
#     the victim's id, so the band/counter-prediction attack fails.
#
# eta = 16 for inner IPv4 (the layer the AFTR reassembles in DS-Lite).
import hashlib
import hmac
import os

ETA = 16                      # IPv4 IP-ID width
_HALF = ETA // 2
_MASK = (1 << _HALF) - 1
_ROUNDS = 3                   # Luby-Rackoff: 3 rounds -> pseudorandom permutation


class IpIdFeistel:
    """Per-<src,dst,proto> keyed Feistel permutation over the IP-ID field."""

    def __init__(self, master_key=None, rekey_after=(1 << (ETA - 1))):
        self._master = master_key or os.urandom(32)
        self._keys = {}            # (s,d,p) -> (key, counter)
        self._rekey_after = rekey_after

    def _tuple_key(self, s, d, p):
        st = self._keys.get((s, d, p))
        if st is None or st[1] >= self._rekey_after:
            # derive (or rekey) a per-triplet key from the master secret
            seed = f"{s}|{d}|{p}|{os.urandom(4).hex()}".encode()
            k = hmac.new(self._master, seed, hashlib.sha256).digest()
            st = [k, 0]
            self._keys[(s, d, p)] = st
        st[1] += 1
        return st[0]

    @staticmethod
    def _F(key, rnd, half):
        # round function: keyed hash of (round || half) reduced to _HALF bits
        msg = bytes([rnd]) + half.to_bytes(2, "big")
        h = hmac.new(key, msg, hashlib.sha256).digest()
        return int.from_bytes(h[:2], "big") & _MASK

    def _permute(self, key, idv):
        L = (idv >> _HALF) & _MASK
        R = idv & _MASK
        for r in range(_ROUNDS):
            L, R = R, L ^ self._F(key, r, R)
        return ((L << _HALF) | R) & ((1 << ETA) - 1)

    def remap(self, s, d, p, idv):
        """Rewrite the IP-ID for a packet with reassembly tuple (s,d,p,idv)."""
        return self._permute(self._tuple_key(s, d, p), idv)

    # deterministic remap that does NOT advance the rekey counter — used when a
    # datagram arrives already fragmented and every fragment must map identically
    def remap_fixed(self, s, d, p, idv):
        st = self._keys.get((s, d, p))
        if st is None:
            self._tuple_key(s, d, p)
            st = self._keys[(s, d, p)]
        return self._permute(st[0], idv)


def _selftest():
    f = IpIdFeistel(master_key=b"unit-test-master-key-32-bytes!!!")
    s, d, p = "10.0.1.100", "198.51.100.2", 1

    # (a) bijection: for a fixed key, mapping all 2^16 ids is a permutation
    key = f._tuple_key(s, d, p)
    outs = [f._permute(key, i) for i in range(1 << ETA)]
    assert len(set(outs)) == (1 << ETA), "not a permutation (collisions!)"

    # (b) same tuple+id -> same id' (fragments of one datagram stay together)
    assert f.remap_fixed(s, d, p, 4321) == f.remap_fixed(s, d, p, 4321)

    # (c) distinct reassembly tuples never collide into one context:
    #     same id, different proto -> different permutation -> (almost surely) different id'
    a = f.remap_fixed(s, d, 1, 4321)
    b = f.remap_fixed(s, d, 6, 4321)
    assert a != b, "distinct tuples mapped to same reassembly id"

    # (d) anti-prediction: the attacker sees id=n and predicts n+1 (counter).
    #     Show pi(n+1) is NOT pi(n)+1, so a band riding "current+1" misses.
    hits = 0
    for n in range(0, 2000):
        if f.remap_fixed(s, d, p, n + 1) == (f.remap_fixed(s, d, p, n) + 1) & 0xFFFF:
            hits += 1
    # for a counter id the attacker would be right 2000/2000 times; with the
    # permutation it is right only ~1/65536 of the time.
    assert hits <= 2, f"permutation too predictable ({hits} sequential hits)"

    print("ipid_feistel self-test OK:")
    print("  (a) 2^16 ids form a permutation (zero collisions)")
    print("  (b) same (s,d,p,id) -> same id' (reassembly preserved)")
    print("  (c) distinct reassembly tuples stay separate")
    print(f"  (d) sequential-prediction hits over 2000 ids = {hits} "
          f"(a counter would be 2000) -> band attack defeated")


if __name__ == "__main__":
    _selftest()
