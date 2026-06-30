# PCP_OWNERSHIP — ownership binding (cross-subscriber PCP)

Tree defence leaf **"PCP ownership binding"** — defends **T8, T10** (THIRD_PARTY /
PEER targeting a non-owned co-subscriber).

## Mechanism
The AFTR binds every PCP MAP/PEER to the requester's own delegated prefix. A
request whose internal address (THIRD_PARTY / PEER) is **not owned** by the
requester is refused, so no DNAT is installed for, and no mapping is disclosed
about, another subscriber.

## OFF vs ON (measured)
| | result |
|---|---|
| OFF (no check) | `OFF.pcap` + `OFF.dnat.txt` — **5** cross-subscriber DNAT rules installed (`→ 10.0.2.100`) |
| ON (ownership binding) | `ON.pcap` + `ON.dnat.txt` — **0** cross-subscriber DNAT rules |

Toggle: the AFTR PCP server runs with `T10_THIRD_PARTY_OWNERSHIP_CHECK=1` for ON.
The attacker (client1, behind B4-1) requests a THIRD_PARTY MAP naming B4-2's
`10.0.2.100`; OFF the AFTR installs the DNAT, ON it refuses.

## Reproduce
`bash testbed/defenses/verify_all.sh` (PCP_OWNERSHIP block).

## Recognition rule
A PCP MAP/PEER naming an internal address outside the requester's prefix yields an
installed DNAT / a returned mapping OFF, and a refusal ON.
