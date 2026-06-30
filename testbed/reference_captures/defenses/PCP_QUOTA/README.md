# PCP_QUOTA — per-subscriber PCP quota (port-pool exhaustion)

Tree defence leaf **"Per-subscriber PCP quota"** — defends **T7** (one subscriber
draining the shared AFTR PCP pool and starving others).

## Mechanism
The AFTR PCP pool is shared across B4s. A per-B4 quota (`T_PCP_QUOTA=N`) caps the
concurrent mappings any one subscriber may hold, so a flooder cannot consume the
whole pool and freeze its co-subscribers.

## OFF vs ON (measured)
| | result |
|---|---|
| OFF (no quota), pool 60 | `OFF.pcap` + `OFF.b4-2-map.txt` — B4-1 fills the pool → co-subscriber **b4-2 MAP REFUSED** (`result_code=8 NO_RESOURCES`) |
| ON (quota=20), pool 60 | `ON.pcap` + `ON.b4-2-map.txt` — B4-1 capped at 20 → **b4-2 MAP created** (`192.0.2.1:…`) |

The pool is deliberately small (60) so the flood actually fills it; the mechanism
is identical at production sizes. (A 400-pool is not drained within the test
window — that, not a defence failure, was an earlier false negative in the
verifier; now fixed in `verify_all.sh`.)

## Reproduce
`bash testbed/defenses/verify_all.sh` (PCP_QUOTA block).

## Recognition rule
After one subscriber floods MAP requests, a *different* subscriber's MAP returns
`NO_RESOURCES` OFF and succeeds ON.
