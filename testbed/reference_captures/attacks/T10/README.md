# T10 — Cross-Subscriber PCP PEER Enumeration

Reference packet captures for T10, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T10_1-cross-sub-peer-leak.pcap` | 409 |
| `T10_2-aftr-pcp.pcap` | 409 |

## Verdict

```
reference: cross-subscriber observation-isolation broken (leaked external port == victim's real port)
this run:  trials passed: 2/2 aggregate TP=2 FP=0 FN=4, precision=100.00%, recall=33.33% 
verdict:   MATCH   (attack reproduced the stored result)
```
