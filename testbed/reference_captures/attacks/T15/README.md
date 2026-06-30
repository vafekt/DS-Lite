# T15 — SNMP MIB Information Disclosure

Reference packet captures for T15, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T15_1-snmp-walk.pcap` | 594 |
| `T15_2-mgmt-station.pcap` | 594 |

## Verdict

```
reference: the MIB read discloses multiple subscribers' private connections (>=2 subscribers)
this run:  distinct subscriber inner IPs disclosed = 2
verdict:   MATCH   (attack reproduced the stored result)
```
