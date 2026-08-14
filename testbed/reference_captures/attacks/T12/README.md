# T12 — Softwire Identity Multiplication

Reference packet captures for T12, regenerated from the testbed by
re-running the attack under capture (`testbed/scripts/run_attack_live.sh`;
one capture point per file). The step-by-step narration, measured signal,
and verdict are in [`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `t12_1-attacker-4in6.pcap` | 4000 |
| `t12_2-aftr-egress.pcap` | 4000 |

## Verdict

```
reference: one forged identity is capped and leaves co-residents reachable (200); many forged identities fill the 64512-port pool and deny both co-residents (200->000)
this run:  ONE: pool=2000 co-res=200/200; MANY: pool=64512 co-res=000/000
verdict:   MATCH   (attack reproduced the stored result)
```
