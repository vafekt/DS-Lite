# TRABELSI — two-structure session table / early eviction (NAT exhaustion)

Tree defence leaf **"Two-structure session table / early eviction"** — defends
**T1** (per-B4 NAT/conntrack state exhaustion, the SIEGE phase holding ESTABLISHED
connections to the cap).

## Mechanism
A two-structure session table separates half-open/idle state from established
flows and evicts the cheap-to-create entries early, so a flood of held
connections cannot pin the per-subscriber cap and deny the legitimate victim.
(Trabelsi et al., *Improved Session Table Architecture for Denial of Stateful
Firewall Attacks*.)

## OFF vs ON (measured)
| | result |
|---|---|
| OFF (single table) | `OFF.result.txt` — SIEGE holds the cap → victim `client1=000` (denied) |
| ON (early eviction) | `ON.result.txt` — held state evicted → victim `client1=200` (served) |

Driven through the live runner (`run_attack_live.sh T1`, two-phase SHOCK+SIEGE)
with the defence toggled via `article_defenses.sh TRABELSI`.

## Reproduce
`bash testbed/defenses/verify_all.sh` (TRABELSI block).

## Recognition rule
Under a sustained held-connection flood the victim is denied (`000`) OFF and
served (`200`) ON.
