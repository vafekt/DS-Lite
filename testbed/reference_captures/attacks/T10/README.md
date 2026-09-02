# T10 — DS-Lite MIB Unauthenticated Access

Reference packet captures for T10, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `t10_1-snmp-set.pcap` | 564 |
| `t10_2-mgmt-station.pcap` | 564 |

## Verdict

```
reference: unauthenticated MIB access raises the per-user port alarm to Integer32 max (never fires) AND discloses >=2 softwire tunnel-source identities; ConnectNumber out-of-range SET rejected per RFC 60..90
this run:  PortNumber 1000->2147483647; subscribers disclosed 2; ConnectNumber stayed 60
verdict:   MATCH   (attack reproduced the stored result)
```
