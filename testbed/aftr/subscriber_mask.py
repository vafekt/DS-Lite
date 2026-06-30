"""RFC 7785 subscriber-mask derivation.

RFC 7785 (Informational) recommends that DS-Lite AFTRs derive a *subscriber
identifier* from the B4's IPv6 source address by applying a configured
"subscriber-mask".  The subscriber-mask is "an integer that indicates the
length of significant bits to be applied on the source IPv6 address (internal
side) to identify unambiguously a CPE" (RFC 7785 §3).

When the AFTR uses the subscriber-mask-derived prefix as the binding key
rather than the full /128 source address, two consequences follow:

  - Two different /128 addresses that share the prefix are treated as the
    same subscriber.  This implements RFC 7785's recommendation that
    "Resource contexts created and maintained by the AFTR SHOULD be based on
    the delegated IPv6 prefix instead of the B4's IPv6 address" (RFC 7785 §3).
  - When a B4's IPv6 address changes within the delegated prefix, the binding
    survives.  RFC 7785 §3 makes this an explicit SHOULD requirement.

This module provides the pure-Python derivation; the AFTR uses it from the
traceability logger to emit the correct subscriber identifier per
RFC 6888 §4, and from any module that wishes to bind resource limits to the
prefix rather than to individual /128 addresses.

The default subscriber-mask is 56, matching the RFC 7785 §3 default
("a default value of 56 bits"). This corresponds to the typical /56
delegated prefix in residential IPv6 deployments. Operators with a
different prefix-delegation policy override the default by setting the
SUBSCRIBER_MASK environment variable to an integer in [1, 128].
"""

from __future__ import annotations

import ipaddress
import os


DEFAULT_SUBSCRIBER_MASK_LEN = 56


def _validate_mask(mask_len: int) -> int:
    if not isinstance(mask_len, int):
        raise TypeError(f"subscriber-mask length must be int, got {type(mask_len).__name__}")
    if not 1 <= mask_len <= 128:
        raise ValueError(
            f"subscriber-mask length must be in [1, 128], got {mask_len}"
        )
    return mask_len


def configured_mask_len(env: dict[str, str] | None = None) -> int:
    """Return the subscriber-mask length to use.

    Reads SUBSCRIBER_MASK from `env` (defaulting to os.environ).  Falls back
    to DEFAULT_SUBSCRIBER_MASK_LEN if the variable is unset.  Raises
    ValueError if the variable is set to a non-integer or to a value outside
    the [1, 128] range, so misconfiguration is reported at startup rather
    than silently ignored.
    """
    env = os.environ if env is None else env
    raw = env.get("SUBSCRIBER_MASK")
    if raw is None or raw == "":
        return DEFAULT_SUBSCRIBER_MASK_LEN
    try:
        mask_len = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"SUBSCRIBER_MASK must be an integer, got {raw!r}"
        ) from exc
    return _validate_mask(mask_len)


def derive_subscriber_id(source_ipv6: str, mask_len: int | None = None) -> str:
    """Return the RFC 7785 subscriber identifier for `source_ipv6`.

    The identifier is the textual representation of the IPv6 prefix obtained
    by truncating `source_ipv6` to `mask_len` bits (defaulting to the
    configured subscriber-mask length).  Two source addresses that share the
    same prefix produce the same identifier, which is the invariant the AFTR
    relies on for prefix-based binding.

    >>> derive_subscriber_id("2001:db8:cafe::4001", 64)
    '2001:db8:cafe::/64'
    >>> derive_subscriber_id("2001:db8:cafe::4002", 64)
    '2001:db8:cafe::/64'
    >>> derive_subscriber_id("2001:db8:beef::1", 64)
    '2001:db8:beef::/64'
    """
    if mask_len is None:
        mask_len = configured_mask_len()
    _validate_mask(mask_len)
    addr = ipaddress.IPv6Address(source_ipv6)
    network = ipaddress.IPv6Network((addr, mask_len), strict=False)
    return network.with_prefixlen


def same_subscriber(addr_a: str, addr_b: str, mask_len: int | None = None) -> bool:
    """Return True if `addr_a` and `addr_b` belong to the same subscriber.

    Two IPv6 addresses belong to the same subscriber iff they share the same
    `mask_len`-bit prefix.  This is the predicate the AFTR uses to decide
    whether a binding created under one B4 address should be migrated to a
    different address per RFC 7785 §3.
    """
    return derive_subscriber_id(addr_a, mask_len) == derive_subscriber_id(addr_b, mask_len)


if __name__ == "__main__":  # pragma: no cover
    import doctest
    doctest.testmod(verbose=True)
