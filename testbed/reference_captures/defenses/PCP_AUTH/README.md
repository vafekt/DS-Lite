# PCP_AUTH — authenticated ANNOUNCE / confirm (epoch-reset storm)

Tree defence leaf **"Authenticated ANNOUNCE / confirm"** — defends **T9** (forged
PCP ANNOUNCE epoch reset provoking a mass re-mapping storm).

## Mechanism
PCP clients re-create every mapping when they see the epoch jump backwards. With
authenticated/confirmed ANNOUNCE, a client ignores (or out-of-band confirms) an
unauthenticated epoch reset, so a forged ANNOUNCE provokes no renewal storm.

## OFF vs ON (measured)
| | result |
|---|---|
| OFF (unauthenticated) | `OFF.pcap` + `OFF.storms.txt` — **6** renewal storms triggered by the forged ANNOUNCE |
| ON (`T_PCP_AUTH=1`) | `ON.pcap` + `ON.storms.txt` — **0** renewal storms |

Capture point: B4-1 `eth-isp`, `udp port 5351 or 5350`. The attacker forges a PCP
ANNOUNCE from the AFTR source; OFF the proxy emits renewal storms, ON it does not.

## Reproduce
`bash testbed/defenses/verify_all.sh` (PCP_AUTH block).

## Recognition rule
A forged ANNOUNCE is followed by a burst of MAP renewals OFF, and by silence ON.
