# DNS_0X20 — DNS 0x20 case randomization (off-path resolver poisoning)

Tree defence leaf **"DNS 0x20 case randomization"** — defends **T11** (off-path
poisoning of the B4 resolver for the AFTR FQDN).

## Mechanism
The resolver randomizes the letter-case of each query name (DNS 0x20 encoding) and
requires the answer to echo the exact case. This adds entropy the off-path
attacker cannot guess, so its forged answers (which can only brute-force TXID +
port) are rejected.

## OFF vs ON (measured)
| | result |
|---|---|
| OFF (no 0x20) | `OFF.result.txt` — AFTR FQDN poisoned: resolved to the attacker (`2001:db8:cafe:0:…`) |
| ON (0x20 randomization) | `ON.result.txt` — `resolved to <none>` (forged answers rejected) |

Driven through the live runner (`run_attack_live.sh T11`) with the defence toggled
OFF/ON via `article_defenses.sh DNS_0X20`.

## Reproduce
`bash testbed/defenses/verify_all.sh` (DNS_0X20 block).

## Recognition rule
The B4's cached AFTR FQDN resolves to the attacker OFF and to nothing/the
legitimate AFTR ON, for an identical off-path forged-answer flood.
