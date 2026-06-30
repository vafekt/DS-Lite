# T5 — Downstream Softwire Injection

Reference packet captures for T5, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T5_1-attacker-forges.pcap` | 32 |
| `T5_2-injected-into-LAN.pcap` | 32 |

## Verdict

```
reference: forged inner-IPv4 (src 203.0.113.66) bypasses the CGN and reaches the victim LAN (>0)
this run:  spoofed-src packets delivered onto B4-1 LAN = 15
verdict:   MATCH   (attack reproduced the stored result)
```
