# FEISTEL_IPID — unpredictable packet identifiers (secondary control for T6)

Article-grounded control (Gilad & Herzberg 2013) for the reassembly-collision
attack **T6**. It is a **secondary** control: the reliable defence for the live
T6 attack is **SAVI** (see [`../SAVI/`](../SAVI/)). This control addresses only
the *prediction* the classic band attack relies on.

## Mechanism
The classic band attack needs the victim's next packet identifier to be
predictable (a sequential counter), so the attacker can pre-place a colliding
fragment at the identifier the victim is about to use. Replacing the identifier
source with a keyed permutation makes the next value unpredictable, so an
attacker that only *predicts* can no longer aim the collision.

## What it does and does not stop (honest scope)
This is an algorithmic property, verified by the module self-test
([`selftest.txt`](selftest.txt)) over 2000 identifiers:

| | result |
|---|---|
| OFF (sequential counter) | an attacker predicting "next = current+1" hits **2000 / 2000** |
| ON (keyed permutation) | sequential-prediction hits = **0** |

Defeating prediction does **not** fully stop an on-path attacker that *observes*
the live identifier and races it: measured victim loss with this control on is
variable (roughly 0-60%). The live T6 attack in this testbed is reliably closed
by **SAVI**, which drops the attacker's spoofed fragments outright (victim loss
0%).

## Reproduce
`bash testbed/defenses/verify_all.sh` (FEISTEL_IPID block) or
`docker exec ds-lite-lab python3 /testbed/defenses/ipid_feistel.py`.

## Recognition rule
Successive inner IP-IDs are consecutive (predictable) OFF and a non-sequential
permutation (0 next-ID predictions) ON.
