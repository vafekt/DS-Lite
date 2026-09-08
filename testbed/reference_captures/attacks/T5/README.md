# T5 — Unauthenticated Softwire Decapsulation

Reference packet captures for T5, regenerated from the testbed by
re-running the attack under capture (`testbed/scripts/run_attack_live.sh`;
one capture point per file). The step-by-step narration, measured signal,
and verdict are in [`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `t5_1-attacker-4in6.pcap` | 4000 |
| `t5_2-aftr-egress.pcap` | 4000 |

## Verdict

```
reference: an unprovisioned host relays IPv4 to the Internet through the AFTR, laundered as the shared public IPv4 (>0)
this run:  relayed packets egressing as 192.0.2.1 -> 198.51.100.2 = 10
verdict:   MATCH   (attack reproduced the stored result)
```
