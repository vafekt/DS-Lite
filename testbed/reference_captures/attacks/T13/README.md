# T13 — Transparent AFTR Hijack

Reference packet captures for T13, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T13_1-rogue-dns.pcap` | 13 |
| `T13_2-b4-receives.pcap` | 11 |
| `T13_3-victim-tunnels-to-attacker.pcap` | 6 |

## Verdict

```
reference: name stays aftr.dslite.example.com (legit) but the softwire is rebuilt to the attacker (2001:db8:cafe:0:dc70:efff:fea1:249d); victim traffic diverted to the attacker
this run:  name=aftr.dslite.example.com. (kept legit), softwire remote 2001:db8:cafe::10->2001:db8:cafe:0:dc70:efff:fea1:249d, victim HTTP=000, frames-to-attacker=4
verdict:   MATCH   (attack reproduced the stored result)
```
