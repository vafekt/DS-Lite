# T6 — Softwire Reassembly Poisoning

Reference packet captures for T6, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T6_1-attacker-preseed.pcap` | 2217 |
| `T6_2-aftr-collide.pcap` | 2217 |

## Verdict

```
reference: victim's fragmented flow collides on overlap and is dropped (high loss)
this run:  victim oversized-ping packet loss = 90%
verdict:   MATCH   (attack reproduced the stored result)
```
