# SAVI — per-port source binding (softwire outer-source spoof)

Tree defence leaf **"SAVI per-port source binding"** — defends **T1, T3, T5, T6,
T9** (every attack that forges a softwire **outer source**).

## Mechanism
Source Address Validation Improvement (SAVI, RFC 7039) binds each carrier access
port to the IPv6 source it is allowed to use. A frame whose outer source is the
victim B4 (`2001:db8:cafe::b41`) but that arrives on the **attacker's** port is
dropped at the access port, before it reaches the AFTR.

## OFF vs ON (measured)
| | result |
|---|---|
| OFF (no binding) | `OFF.pcap` — **14** spoofed `::b41 → ::10` proto-4 frames reach the AFTR |
| ON (SAVI) | `ON.pcap` — **0** spoofed frames reach the AFTR (dropped at the access port) |

Capture point: AFTR `eth-isp`, filter `ip6 src ::b41 and ip6 dst ::10 and ip6 proto 4`.
The attacker (`::13a`) forges the victim B4's outer source; OFF the AFTR sees the
spoof, ON it sees nothing.

## Reproduce
`bash testbed/defenses/verify_all.sh` (SAVI block) — toggles via
`article_defenses.sh SAVI on|off`.

## Recognition rule
A frame whose outer IPv6 source is a B4 identity but that ingresses on a different
access port is present OFF and absent ON.
