# T1 — NAT Binding-Table Exhaustion

Reference packet captures for T1, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T1_1-attacker-ISP.pcap` | 4002 |
| `T1_2-AFTR-ISP-recv.pcap` | 4002 |
| `T1_3-AFTR-WAN-postNAT.pcap` | 4000 |

## Verdict

```
reference: victim 200->000 in BOTH phases: SHOCK (half-open, volatile) + SIEGE (completed, durable); co-sub stays 200
this run:  SHOCK connections=2000/2000 half-open client1=000 ; SIEGE connections=2002/2000 completed client1=000 client2=200
verdict:   MATCH   (attack reproduced the stored result)
```
