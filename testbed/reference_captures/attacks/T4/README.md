# T4 — Unencrypted-Tunnel Interception

Reference packet captures for T4, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T4_1-victim-softwire.pcap` | 76 |
| `T4_2-attacker-reads.pcap` | 76 |

## Verdict

```
reference: attacker reads the victim's inner web flow in cleartext off the softwire (>0)
this run:  readable inner web-flow packets = 41, plaintext HTTP markers = 30
verdict:   MATCH   (attack reproduced the stored result)
```
