# T2 — Shared-IPv4 Reputation Poisoning

Reference packet captures for T2, regenerated from the testbed by
`testbed/scripts/capture_references.sh` (one capture point per file).
The step-by-step narration, measured signal, and verdict are in
[`RESULT.txt`](RESULT.txt).

## Capture points

| file | packets |
|---|---|
| `T2_1-client-LAN.pcap` | 2219 |
| `T2_2-B4-softwire-uplink.pcap` | 2223 |
| `T2_3-AFTR-WAN-sharedIP.pcap` | 2219 |

## Verdict

```
reference: all abuse egresses as the shared 192.0.2.1 (collective reputation damage)
this run:  abuse packets sourced from 192.0.2.1 on the WAN = 1239
verdict:   MATCH   (attack reproduced the stored result)
```
