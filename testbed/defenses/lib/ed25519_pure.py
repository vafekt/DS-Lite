"""Pure-Python Ed25519 (EdDSA over Curve25519), per RFC 8032.

DHCPv6Auth (Albalawi & Aljuhani, Sadhana 45:33, 2020) specifies Ed25519 as the
DSA used to sign DHCPv6 server messages. The lab container has no `cryptography`
or `pynacl` and no network to install them, so we vendor the RFC 8032 reference
construction here. It is slow (a few ms per op) but exact; correctness, not
throughput, is what the off/on defense oracle needs.

API:  keygen() -> (priv32, pub32);  sign(priv32, msg) -> sig64;
      verify(pub32, msg, sig64) -> bool.
"""
import hashlib
import os

# Curve25519 / Ed25519 parameters (RFC 8032 §5.1).
_b = 256
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _q - 2, _q)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _H(m):
    return hashlib.sha512(m).digest()


def _inv(x):
    return pow(x, _q - 2, _q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = [_Bx % _q, _By % _q, 1, (_Bx * _By) % _q]   # extended coords (X,Y,Z,T)


def _edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _q
    b = ((y1 + x1) * (y2 + x2)) % _q
    c = (t1 * 2 * _d * t2) % _q
    dd = (z1 * 2 * z2) % _q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g
    return [x3 % _q, y3 % _q, z3 % _q, t3 % _q]


def _scalarmult(P, e):
    if e == 0:
        return [0, 1, 1, 0]
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodeint(y):
    return y.to_bytes(32, "little")


def _encodepoint(P):
    x, y, z, t = P
    zi = _inv(z)
    x = (x * zi) % _q
    y = (y * zi) % _q
    bits = bytearray(_encodeint(y))
    bits[31] = (bits[31] & 0x7f) | ((x & 1) << 7)
    return bytes(bits)


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def publickey(sk):
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def _Hint(m):
    h = _H(m)
    return int.from_bytes(h, "little")


def sign(sk, msg):
    """sk = 32-byte seed (private key). Returns 64-byte signature."""
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    A = _encodepoint(_scalarmult(_B, a))
    r = _Hint(h[32:64] + msg)
    R = _scalarmult(_B, r)
    Rs = _encodepoint(R)
    S = (r + _Hint(Rs + A + msg) * a) % _L
    return Rs + _encodeint(S)


def _decodeint(s):
    return int.from_bytes(s, "little")


def _isoncurve(P):
    x, y, z, t = P
    zi = _inv(z)
    x = (x * zi) % _q
    y = (y * zi) % _q
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != _bit(s, _b - 1):
        x = _q - x
    P = [x, y, 1, (x * y) % _q]
    if not _isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def verify(pk, msg, sig):
    """pk = 32-byte public key, sig = 64-byte signature."""
    try:
        if len(sig) != 64 or len(pk) != 32:
            return False
        R = _decodepoint(sig[:32])
        A = _decodepoint(pk)
        S = _decodeint(sig[32:64])
        h = _Hint(sig[:32] + pk + msg)
        x1, y1, z1, t1 = _scalarmult(_B, S)
        x2, y2, z2, t2 = _edwards_add(R, _scalarmult(A, h))
        # compare in projective coords: X1/Z1 == X2/Z2 and Y1/Z1 == Y2/Z2
        if (x1 * z2 - x2 * z1) % _q != 0:
            return False
        if (y1 * z2 - y2 * z1) % _q != 0:
            return False
        return True
    except Exception:
        return False


def keygen():
    sk = os.urandom(32)
    return sk, publickey(sk)


if __name__ == "__main__":
    sk, pk = keygen()
    m = b"DHCPv6Auth self-test"
    s = sign(sk, m)
    assert verify(pk, m, s)
    assert not verify(pk, m + b"x", s)
    assert not verify(pk, m, bytes(64))
    print("ed25519_pure self-test OK  pub=", pk.hex()[:16], "...")
