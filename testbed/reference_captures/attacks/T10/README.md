# T10 — DS-Lite MIB Unauthenticated Access

Reference packet captures for T10, regenerated from the testbed by
re-running the attack under capture (`testbed/scripts/run_attack_live.sh`;
one capture point per file). The step-by-step narration, measured signal,
and verdict are in [`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `t10_1-snmp-set.pcap` | 604 |
| `t10_2-mgmt-station.pcap` | 604 |

## Verdict

```
reference: unauthenticated MIB access raises the per-user port alarm to Integer32 max (never fires) AND discloses >=2 subscribers' private connections; ConnectNumber out-of-range SET rejected per RFC 60..90
this run:  PortNumber 1000->2147483647; subscribers disclosed 2; ConnectNumber stayed 60
verdict:   MATCH   (attack reproduced the stored result)
```
