# T7 — PCP Port-Exhaustion DoS

Reference packet captures for T7, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T7_1-pcp-uplink.pcap` | 1203 |
| `T7_2-aftr-pcp.pcap` | 1203 |

## Verdict

```
reference: pool drained; a co-resident's legit MAP is refused (NO_RESOURCES)
this run:  co-resident MAP REFUSED (frozen)
verdict:   MATCH   (attack reproduced the stored result)
```
