# T3 — Softwire Identity Takeover (NDP-poison MITM)

Reference packet captures for T3, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T3_1-poison-NAs.pcap` | 287 |
| `T3_2-attacker-intercept.pcap` | 7 |
| `T3_3-victim-cutoff.pcap` | 11 |

## Verdict

```
reference: AFTR neighbor entry for 2001:db8:cafe::b41 flips to the attacker; victim 200->000; returns stolen
this run:  neighbor entry ->2a:29:47:aa:9c:56, client1 200->000, intercepted=7
verdict:   MATCH   (attack reproduced the stored result)
```
