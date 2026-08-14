#!/usr/bin/env python3
"""RFC 6888 §4 subscriber-traceability logger for the DS-Lite AFTR.

RFC 6888 (BCP) §4 catalogues the per-mapping fields a CGN operator needs in
order to attribute a public-IPv4 source-address-and-port at a given time to
the responsible subscriber.  This module implements that logging.

The logger runs inside the AFTR network namespace and watches the kernel
connection-tracking event stream emitted by `conntrack -E -e NEW,DESTROY`.
Each event line is reformatted into a structured record containing the
fields RFC 6888 §4 calls out (subscriber identifier, internal address and
port, public IPv4 source address and port, destination address and port,
protocol, and a timestamp).

The subscriber identifier is derived from the B4's IPv6 source address by
applying the configured subscriber-mask (RFC 7785 §3); when an event does
not carry an outer-IPv6 hint via the conntrack mark (for example because
the source is the wildcard tunnel), the subscriber identifier is recorded
as ``unknown`` and the operator can still recover the responsible CPE via
the public-source IPv4 column.

Per RFC 6888 §REQ-12, destination addresses and ports are recorded *only*
when the operator opts in via the ``LOG_DESTINATIONS=1`` environment
variable; the default is *not* to log destinations.

Output is appended one JSON object per line to the path given by the
``TRACEABILITY_LOG_PATH`` environment variable (default
``/var/log/dslite-aftr-traceability.log``).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Iterable, Iterator

from subscriber_mask import configured_mask_len, derive_subscriber_id


DEFAULT_LOG_PATH = "/var/log/dslite-aftr-traceability.log"


@dataclass(frozen=True)
class MappingEvent:
    """A single RFC 6888 §4 mapping event.

    Fields follow the per-mapping data set called out in §4 (the section
    that introduces logging requirements for IPv4-address-sharing
    deployments).  ``destination_addr`` and ``destination_port`` are set
    to ``None`` unless destination logging is explicitly enabled per
    REQ-12.
    """

    event_type: str             # NEW or DESTROY
    timestamp: str              # ISO 8601 UTC timestamp from the AFTR clock
    protocol: str               # tcp, udp, icmp, ...
    internal_src_ipv4: str
    internal_src_port: int | None
    public_src_ipv4: str
    public_src_port: int | None
    subscriber_id: str          # RFC 7785 §3 prefix or 'unknown'
    b4_ipv6: str | None         # specific B4 tunnel-local IPv6 (per-CPE)
    ct_mark: int | None         # raw conntrack mark, for cross-reference
    destination_addr: str | None = None
    destination_port: int | None = None


# Map ct mark (set by the testbed's ip6/ip mangle hooks) → B4 IPv6 source
# address.  `nftables.conf` does `meta mark set @nh,160,32` on the IPv6
# next-header-4 (DS-Lite softwire) frames, which captures the low 32 bits
# of the outer IPv6 source address.  Because nftables stores the mark in
# host byte order while the IPv6 address is in network byte order, the
# mark observed in `conntrack -E` is the byte-swapped low 32 bits of the
# B4's tunnel-local IPv6 address.  `mark_for_ipv6()` performs that swap so
# callers can build a correct mapping at runtime.
#
# The mapping is provided at logger start by setup.sh, which knows each
# B4's live SLAAC/DHCPv6 address, via either:
#   * the CT_MARK_MAP_FILE env var — a path to a JSON object
#     ``{"<mark-decimal-or-hex>": "<ipv6>", ...}``; or
#   * the CT_MARK_TO_IPV6 env var — the same JSON object inline.
# The hardcoded defaults exist only as a fallback for unit tests; they do
# NOT match a running testbed because SLAAC IIDs are randomized per boot.
DEFAULT_CT_MARK_MAP: dict[int, str] = {}


def mark_for_ipv6(ipv6_addr: str) -> int:
    """Return the ct-mark value the kernel will assign for `ipv6_addr`.

    `nftables.conf` does `meta mark set @nh,160,32` to extract the low 32
    bits of the outer IPv6 source.  The kernel stores marks in host byte
    order, so on a little-endian host the value reported by `conntrack -E`
    is the byte-swapped low 32 bits of the B4 IPv6 address.  Computing it
    here keeps setup.sh in shell while producing the exact integer the
    logger will see in conntrack-event lines.
    """
    import ipaddress
    addr = ipaddress.IPv6Address(ipv6_addr)
    low32_be = int(addr).to_bytes(16, "big")[-4:]
    return int.from_bytes(low32_be, sys.byteorder)


def _parse_mark_key(key: str | int) -> int:
    """Accept a JSON object key as decimal or hex; tolerate either."""
    if isinstance(key, int):
        return key
    text = key.strip()
    try:
        return int(text)
    except ValueError:
        return int(text, 16)


def load_ct_mark_map(env: dict[str, str] | None = None) -> dict[int, str]:
    """Return the ct-mark → B4-IPv6 mapping, overridable via env.

    Precedence: ``CT_MARK_MAP_FILE`` (path to JSON) > ``CT_MARK_TO_IPV6``
    (inline JSON) > ``DEFAULT_CT_MARK_MAP``.
    """
    env = os.environ if env is None else env
    raw = None
    path = env.get("CT_MARK_MAP_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            raise ValueError(
                f"CT_MARK_MAP_FILE={path!r} not readable: {exc}"
            ) from exc
    if raw is None:
        raw = env.get("CT_MARK_TO_IPV6")
    if not raw:
        return dict(DEFAULT_CT_MARK_MAP)
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "ct-mark map must be JSON object {mark: ipv6}, "
            f"got {raw!r}: {exc}"
        ) from exc
    return {_parse_mark_key(k): str(v) for k, v in decoded.items()}


# Conntrack -E output is line-oriented but its exact shape varies with
# protocol and event type: DESTROY events omit the timeout field that NEW
# events carry; ICMP entries lack sport/dport; UDP/TCP carry both an
# original direction and a reply (post-NAT) direction.  Rather than use
# one big alternation regex, we extract each field with a targeted search
# and pick the original- vs reply-direction fields by document order.

# `conntrack -E -o extended` prefixes each event with the layer-3 protocol
# name and number ("ipv4 2" or "ipv6 10") before the layer-4 protocol name
# and number.  The layer-4 protocol is what RFC 6888 §4 wants logged, so we
# skip the L3 tokens and capture the L4 name.  When `-o extended` is not in
# effect, the L3 prefix is absent and the first token after the event tag is
# the L4 protocol directly; the regex tolerates both shapes by making the
# L3-prefix capture optional.
_EVENT_TAG_RE = re.compile(
    r"\[(NEW|DESTROY)\]\s+(?:ipv[46]\s+\d+\s+)?(\w+)\b"
)
_MARK_RE      = re.compile(r"mark=(\d+)")
_SRC_RE       = re.compile(r"src=(\S+)")
_DST_RE       = re.compile(r"dst=(\S+)")
_SPORT_RE     = re.compile(r"sport=(\d+)")
_DPORT_RE     = re.compile(r"dport=(\d+)")


def parse_event_line(
    line: str,
    *,
    ct_mark_map: dict[int, str],
    mask_len: int,
    log_destinations: bool,
    now_iso: str | None = None,
) -> MappingEvent | None:
    """Parse one `conntrack -E` output line into a MappingEvent.

    Returns None if the line is not a NEW/DESTROY event (the conntrack
    monitor occasionally emits UPDATE events that we ignore, plus headers
    and blank lines on shutdown).  Raises ValueError if the line claims to
    be NEW or DESTROY but cannot be parsed; this surfaces format drift
    rather than hiding it.

    The parser uses a small set of targeted regexes rather than one large
    pattern so that protocol- and event-type variants (DESTROY with no
    timeout, ICMP with no ports, UDP/TCP with both directions) all parse
    uniformly.  The conntrack-event line lists fields in the
    *original direction* first (internal IPv4 and port on the LAN side of
    the AFTR) followed by the *reply direction* (the post-NAT public IPv4
    and port assigned by the AFTR).
    """
    if "[NEW]" not in line and "[DESTROY]" not in line:
        return None
    tag = _EVENT_TAG_RE.search(line)
    if tag is None:
        raise ValueError(f"unparseable event line: {line.strip()!r}")
    # A missing ct mark is not format drift: loopback flows on the AFTR
    # (e.g. snmpd querying itself) bypass the mangle hook that tags
    # softwire-decapsulated traffic, so no mark is set. Record the event
    # with ct_mark=None and subscriber_id='unknown' rather than crashing
    # the daemon.
    mark = _MARK_RE.search(line)
    event_type = tag.group(1)
    protocol = tag.group(2).lower()

    # Conntrack lists original direction first (subscriber → Internet), then
    # reply direction (Internet → subscriber) post-NAT.  The mapping's
    # public-side address and port are therefore the reply direction's `dst`
    # and `dport` (where the post-NAT public destination appears, namely the
    # AFTR's externally visible address and port).
    srcs = _SRC_RE.findall(line)
    dsts = _DST_RE.findall(line)
    sports = _SPORT_RE.findall(line)
    dports = _DPORT_RE.findall(line)

    internal_src_ipv4 = srcs[0] if srcs else ""
    internal_src_port = int(sports[0]) if sports else None
    public_src_ipv4 = dsts[1] if len(dsts) >= 2 else dsts[0] if dsts else ""
    public_src_port = (
        int(dports[1]) if len(dports) >= 2 else
        int(dports[0]) if dports else None
    )
    # Per RFC 6888 REQ-12, destination address and port are recorded only
    # when explicitly opted in.  The original-direction destination is the
    # external endpoint the subscriber contacted.
    destination_addr = (dsts[0] if dsts else None) if log_destinations else None
    destination_port = (
        int(dports[0]) if log_destinations and dports else None
    )

    mark_value = int(mark.group(1)) if mark is not None else None
    b4_ipv6 = ct_mark_map.get(mark_value) if mark_value is not None else None
    subscriber = (
        derive_subscriber_id(b4_ipv6, mask_len) if b4_ipv6 is not None else "unknown"
    )
    return MappingEvent(
        event_type=event_type,
        timestamp=now_iso or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        protocol=protocol,
        internal_src_ipv4=internal_src_ipv4,
        internal_src_port=internal_src_port,
        public_src_ipv4=public_src_ipv4,
        public_src_port=public_src_port,
        subscriber_id=subscriber,
        b4_ipv6=b4_ipv6,
        ct_mark=mark_value,
        destination_addr=destination_addr,
        destination_port=destination_port,
    )


def format_log_line(event: MappingEvent) -> str:
    """Render a MappingEvent as a single JSON-Lines record."""
    return json.dumps({k: v for k, v in asdict(event).items() if v is not None})


def stream_conntrack_events(
    command: list[str] | None = None,
) -> Iterator[str]:
    """Yield one conntrack-event line at a time.

    Spawned by `main()`; isolated so the parsing logic can be exercised in
    tests with a list-of-lines stub.
    """
    cmd = command or ["conntrack", "-E", "-e", "NEW,DESTROY", "-o", "extended"]
    proc = subprocess.Popen(  # noqa: S603 - exact argv is constructed locally
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            yield line
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def run(
    lines: Iterable[str],
    *,
    log_path: str,
    ct_mark_map: dict[int, str],
    mask_len: int,
    log_destinations: bool,
) -> None:
    """Consume conntrack-event lines and append formatted records to `log_path`.

    A single malformed conntrack line must not terminate the daemon: long-
    running CGN telemetry is unacceptable to lose entirely because of one
    format-drift event. Parse errors are reported on stderr and processing
    continues with the next line.
    """
    with open(log_path, "a", buffering=1, encoding="utf-8") as sink:
        for line in lines:
            try:
                event = parse_event_line(
                    line,
                    ct_mark_map=ct_mark_map,
                    mask_len=mask_len,
                    log_destinations=log_destinations,
                )
            except ValueError as exc:
                sys.stderr.write(f"dslite-aftr-traceability: skip bad line: {exc}\n")
                continue
            if event is None:
                continue
            sink.write(format_log_line(event) + "\n")


def main() -> int:
    log_path = os.environ.get("TRACEABILITY_LOG_PATH", DEFAULT_LOG_PATH)
    log_destinations = os.environ.get("LOG_DESTINATIONS", "0") == "1"
    mask_len = configured_mask_len()
    ct_mark_map = load_ct_mark_map()

    # Make Ctrl-C / SIGTERM a clean exit; the log file is line-buffered so
    # flushing is automatic.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    sys.stderr.write(
        "dslite-aftr-traceability: started "
        f"(log={shlex.quote(log_path)}, mask=/{mask_len}, "
        f"log_destinations={int(log_destinations)})\n"
    )
    run(
        stream_conntrack_events(),
        log_path=log_path,
        ct_mark_map=ct_mark_map,
        mask_len=mask_len,
        log_destinations=log_destinations,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
