# NAT_LOG — per-binding attribution log (shared-IP abuse)

Tree defence leaf **"Per-binding attribution log"** — defends **T2** (abuse from
the shared public IPv4 that, without logging, cannot be attributed to the
responsible subscriber and collateral-blocks the co-subscribers).

## Mechanism
The AFTR logs each NAT binding (internal subscriber ↔ shared external IP:port ↔
destination) so abusive flows egressing the shared `192.0.2.1` can be attributed
to the specific subscriber, instead of blocklisting the shared address and
punishing every co-subscriber.

## OFF vs ON (measured)
| | result |
|---|---|
| OFF (no logging) | `OFF.attribution.log` + `OFF.count.txt` — **0** attribution records (abuse unattributable) |
| ON (per-binding log) | `ON.attribution.log` + `ON.count.txt` — **200** records mapping the abuse to the subscriber |

The attacker (client1) scans from the shared IP; OFF nothing ties the abuse to a
subscriber, ON every flow is logged with its internal owner.

## Reproduce
`bash testbed/defenses/verify_all.sh` (NAT_LOG block).

## Recognition rule
Abusive flows from the shared public IP have **no** owner record OFF and a
per-binding owner record (internal IP:port) ON.
