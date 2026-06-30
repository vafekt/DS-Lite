# T14 — SNMP Alarm-Table Write

Reference packet captures for T14, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T14_1-snmp-set.pcap` | 10 |
| `T14_2-mgmt-station.pcap` | 10 |

## Verdict

```
reference: attacker raises the per-user port alarm (PortNumber) to Integer32 max (never fires); ConnectNumber out-of-range SET rejected per RFC 60..90
this run:  PortNumber 1000->2147483647; ConnectNumber stayed 60 on out-of-range set
verdict:   MATCH   (attack reproduced the stored result)
```
