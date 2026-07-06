# T8 — Unauthorized THIRD_PARTY Forwarding

Reference packet captures for T8, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T8_1-thirdparty-map.pcap` | 10 |
| `T8_2-aftr-pcp.pcap` | 10 |
| `T8_3-inbound-to-victim.pcap` | 8 |

## Verdict

```
reference: attacker opens an inbound port on the shared IP to a NON-OWNED co-sub; external traffic then reaches the victim
this run:  forged inbound-forwarding rules=5 (192.0.2.1:1024->10.0.2.100:9447); external probe reached victim=yes
verdict:   MATCH   (attack reproduced the stored result)
```
