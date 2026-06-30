# T9 — PCP ANNOUNCE Spoof (Epoch Reset)

Reference packet captures for T9, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T9_1-attacker-announce.pcap` | 1212 |
| `T9_2-b4-renew-storm.pcap` | 1212 |

## Verdict

```
reference: one ANNOUNCE triggers a renew storm (MAP packets >> announce count)
this run:  MAP-renew packets = 1211 after 10 ANNOUNCE
verdict:   MATCH   (attack reproduced the stored result)
```
