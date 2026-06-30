# T12 — Rogue AFTR Substitution

Reference packet captures for T12, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T12_1-rogue-dhcpv6.pcap` | 5 |
| `T12_2-b4-receives.pcap` | 5 |
| `T12_3-victim-tunnels-to-attacker.pcap` | 6 |

## Verdict

```
reference: B4 adopts attacker name (aftr-evil.attacker.example) AND rebuilds its softwire to the attacker (2001:db8:cafe:0:dc70:efff:fea1:249d); victim loses service
this run:  name=aftr-evil.attacker.example., softwire remote 2001:db8:cafe::10->2001:db8:cafe:0:dc70:efff:fea1:249d, victim HTTP=000, frames-to-attacker=4
verdict:   MATCH   (attack reproduced the stored result)
```
