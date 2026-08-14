# DECAP-BIND vs T11 — unauthenticated softwire decapsulation relay

An UNPROVISIONED carrier host builds an IPv4-in-IPv6 softwire to the AFTR (no
DHCPv6/PCP) and relays IPv4 to the Internet, laundered as the shared public IPv4
(the RFC 6333 rogue-decapsulation class; Beitis & Vanhoef, USENIX 2025).

DECAP-BIND instantiates the RFC 6333 §11 ingress filter: at the AFTR softwire
ingress, after decapsulation and before CGNAT, it drops any decapsulated packet
that no provisioned softwire accounts for. A legitimate provisioned subscriber is
unaffected.

Files (`server eth0` is the external target; the captured ICMP source is the
shared public IPv4 `192.0.2.1`, i.e. traffic laundered through the AFTR):

| File | Meaning |
|------|---------|
| `DECAP_BIND_OFF_server_eth0.pcap`       | attacker relay egresses as `192.0.2.1` |
| `DECAP_BIND_ON_server_eth0.pcap`        | attacker relay blocked (empty capture) |
| `DECAP_BIND_ON-legit_server_eth0.pcap`  | provisioned subscriber (client1) still relays |
| `DECAP_BIND_{OFF,ON,ON-legit}.result.txt` | echo-requests reaching the Internet as the shared IPv4 |

Measured (echo-requests reaching the Internet as the shared IPv4):

```
OFF attacker: 3   (relay works)
ON  attacker: 0   (blocked)
ON  client1 : 3   (legitimate subscriber unaffected)
```

Reproduce: `bash testbed/defenses/capture_t12_decap.sh`
Oracle: `DECAP_BIND` in `testbed/defenses/verify_all.sh`.
