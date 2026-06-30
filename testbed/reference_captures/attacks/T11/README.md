# T11 — Softwire DNS-Discovery Hijack

Reference packet captures for T11, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T11_1-offpath-flood.pcap` | 4000 |
| `T11_2-b4-resolver.pcap` | 4000 |

## Verdict

```
reference: off-path flood poisons the B4 cache: aftr.dslite.example.com -> attacker (2001:db8:cafe:0:dc70:efff:fea1:249d)
this run:  aftr.dslite.example.com resolved to 2001:db8:cafe:0:dc70:efff:fea1:249d at the B4 resolver
verdict:   MATCH   (attack reproduced the stored result)
```
