# SAVI vs T12 — softwire identity multiplication (shared-pool drain)

T12 forges MANY outer softwire identities from `2001:db8:cafe:dead::/64` (a
different /64 than the carrier prefix) to open bindings until the shared
64,512-port pool is drained, denying every co-resident behind the shared public
IPv4.

Source-address validation (SAVI, RFC 7039 / BCP 38) binds each carrier-bridge
port to the one global source it owns and drops every other. The rule must cover
all global unicast (`2000::/3`), not just the carrier /64: the flood forges from
a different /64, so a carrier-/64-only rule misses it entirely (verified — see
below).

Files (`aftr eth-isp` is the AFTR's carrier-facing interface, after the bridge):

| File | Meaning |
|------|---------|
| `SAVI_T12_OFF_aftr_eth-isp.pcap` | forged `cafe:dead::` softwire packets reaching the AFTR (sampled, `-c 500`) |
| `SAVI_T12_ON_aftr_eth-isp.pcap`  | none reach — dropped at the bridge (empty capture) |
| `SAVI_T12_{OFF,ON}.result.txt`   | pool size and co-resident reachability |

Measured:

```
OFF: 500 forged reach AFTR, pool=64512, co-residents 000/000  (isolation broken)
ON : 0   forged reach AFTR, pool=0,     co-residents 200/200  (isolation held)
```

Reproduce: `bash testbed/defenses/capture_t12_decap.sh`
Oracle: `SAVI_T12` in `testbed/defenses/verify_all.sh`.
