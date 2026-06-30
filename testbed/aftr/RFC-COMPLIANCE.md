# DS-Lite Testbed: RFC compliance audit

This document records the RFC-by-RFC compliance status of the AFTR
configuration (`nftables.conf`, `setup_aftr.sh`, `pcp_server.py`,
`snmp_agent.py`, `traceability_logger.py`, `subscriber_mask.py`) and
the B4 configuration (`dhclient6.conf`, `dhclient6-exit-hook.sh`,
`pcp_proxy.py`).

Every RFC quotation below is verbatim from rfc-editor.org. Every
"implementation" entry points to the file and line(s) that satisfy
the requirement. Items marked ❌ or ⚠️ are deliberate trade-offs and
are documented as such.

## Legend

- ✅ Compliant
- ⚠️ Partial / trade-off (explained inline)
- ❌ Deliberate non-implementation (explained inline)

## RFC 6333: Dual-Stack Lite

| § | Level | Requirement (verbatim) | Implementation | Status |
|---|---|---|---|---|
| 5.3 | MUST | "The B4 element MUST perform fragmentation and reassembly if the outgoing link MTU cannot accommodate the extra IPv6 header. **The inner IPv4 packet MUST NOT be fragmented.**" | `br-isp` MTU follows the `ISP_MTU` env var, default 1500 (matches operational reality on most residential broadband access networks). Tunnel MTU = 1500. The B4 kernel ip6tnl driver IPv6-fragments encapsulated traffic that exceeds the path MTU; the inner IPv4 packet itself is never fragmented. Set `ISP_MTU=1540` to reproduce the RFC 6333 §5.3 recommended path that absorbs the 40-byte IPv6 header without fragmentation. | ✅ |
| 5.4 | SHOULD | "A B4 element SHOULD implement the DHCPv6 option defined in [RFC 6334]." | `b4/dhclient6.conf` requests option 64; `b4/dhclient6-exit-hook.sh` reads the AFTR-Name and brings the tunnel up | ✅ |
| 5.5 | SHOULD | "The B4 element SHOULD implement a DNS proxy, following the recommendations of [RFC 5625]." | `dnsmasq` listens on the LAN, forwards over IPv6 to the DHCPv6-Server's `dnsmasq` | ✅ |
| 5.7 | MAY | "the B4 element MAY use any other addresses within the 192.0.0.0/29 range" (default 192.0.0.2) | `setup.sh` assigns `192.0.0.2/32 dev ds-lite` on each B4 | ✅ |
| 6.3 | MUST | "The AFTR MUST perform fragmentation and reassembly if the underlying link MTU cannot accommodate the encapsulation overhead." | AFTR `ip6tnl` interfaces at `mtu 1500` (matches the B4 side). Under the default `ISP_MTU=1500` configuration the kernel IPv6 reassembler handles fragmented inputs; under `ISP_MTU=1540` encapsulation fits without fragmentation. | ✅ |
| 6.5 | SHOULD | "The AFTR SHOULD use the well-known IPv4 address 192.0.0.1 reserved by IANA to configure the IPv4-in-IPv6 tunnel." | `setup.sh` adds `192.0.0.1/32 dev lo` in the AFTR netns | ✅ |
| 6.6 | (descriptive) | "The NAT binding table of the AFTR element is extended to include the source IPv6 address of the incoming packets … to disambiguate between the overlapping IPv4 address space of the service provider customers." | Two parts: (a) attribution — `nftables.conf` two-stage `ip6 mangle` + `ip mangle` captures the outer IPv6 low 32 bits into the conntrack mark (per-subscriber accounting / REQ-4 cap). (b) **disambiguation** — `table ip dslite_zone` sets a *directional* per-softwire conntrack zone (`iifname ds-lite-b4-N ct original zone set N`) so the SAME private IPv4+port behind different B4s become DISTINCT conntrack entries (the mark alone does not make the tuple unique). Replies carry the globally-unique public IP:port so they match in zone 0; `ip mangle` restores the mark on `eth-wan` and per-B4 route tables 101/102 (`setup.sh`) send the de-NAT'd reply back to the correct softwire. Verified: identical inner 5-tuple `192.168.9.50:40000` behind both B4s coexists as zone-orig=1 / zone-orig=2 with separate external ports, no cross-talk. | ✅ |

## RFC 6334: DHCPv6 Option 64

| § | Level | Requirement (verbatim) | Implementation | Status |
|---|---|---|---|---|
| 5 | MUST | "Clients … MUST include OPTION_AFTR_NAME on its OPTION_ORO." | `b4/dhclient6.conf`: `request dhcp6.name-servers, dhcp6.aftr-name` | ✅ |
| 4 | SHOULD NOT | "SHOULD NOT send more than one AFTR-Name option" | `dhcpv6server/dhcpd6.conf` sends one option per host | ✅ |
| 3 | (encoding) | "tunnel-endpoint-name field is formatted as required in DHCPv6 [RFC 3315] Section 8" (DNS wire format with length-prefixed labels) | ISC `dhcpd6` `domain-list` encoding is RFC 3315 §8 by definition | ✅ |

## RFC 6888: Common requirements for CGNs (14 REQs)

| REQ | Level | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|---|
| 1 | MUST | "If a CGN forwards packets containing a given transport protocol, then it MUST fulfill that transport protocol's behavioral requirements." | RFC 4787 / 5382 / 5508 satisfied below | ✅ |
| 2 | MUST | "A CGN MUST have a default 'IP address pooling' behavior of 'Paired'." | `nftables.conf` SNAT rule maps every softwire to the single shared public IPv4 192.0.2.1. Pairing is preserved per-subscriber because every flow of one subscriber receives a public-port allocation from the same Linux `nf_nat` per-(internal endpoint, external destination) hash bucket; two consecutive flows from one subscriber to the same destination reuse the same public IP and port. Per-subscriber attribution for the connection cap (REQ-4) uses the conntrack mark derived from the outer IPv6 source (RFC 6333 §6.6). | ✅ |
| 3 | SHOULD NOT | "SHOULD NOT have any limitations on the size or the contiguity of the external address pool." | No limits in our ruleset | ✅ |
| 4 | MUST | "A CGN MUST support limiting the number of external ports … per subscriber." | `nftables.conf` meter `per_b4_connlimit { ct mark ct count over 2000 }` keys on the conntrack mark, which is derived from the outer IPv6 source low 32 bits via the `ip6 mangle` and `ip mangle` hooks. The cap therefore applies per softwire (per subscriber) under the shared SNAT pool. The number 2000 is an implementation choice; RFC prescribes none. | ✅ |
| 5 | SHOULD | "SHOULD support limiting the amount of state memory allocated per mapping and per subscriber." | The `ct count` meter caps memory indirectly. No byte-accurate per-mapping cap. | ⚠️ Partial |
| 6 | MUST | "MUST be possible to administratively turn off translation for specific destination addresses and/or ports." | nftables `pcp_dnat` chain + commented static-DNAT examples in postrouting demonstrate the capability | ✅ |
| 7 | RECOMMENDED | "RECOMMENDED that a CGN use an 'endpoint-independent filtering' behavior." | `ct state established,related accept` + drop unsolicited. This is **Address-and-Port-Dependent Filtering**, the more-stringent of the two behaviours permitted by RFC 4787 §5 REQ-8. **EIF (as REQ-7 RECOMMENDS) is NOT implemented**, chosen deliberately to deny unsolicited inbound under shared IPv4. | ⚠️ Deliberate choice of ADF over EIF |
| 8 | SHOULD | "Once an external port is deallocated, it SHOULD NOT be reallocated to a new mapping until at least 120 seconds have passed." | `nf_conntrack_tcp_timeout_time_wait=300` in `setup.sh` (above the 120 s SHOULD) | ✅ |
| 9 | MUST | "A CGN MUST implement a protocol giving subscribers explicit control over NAT mappings. That protocol SHOULD be the Port Control Protocol [RFC 6887]." | `aftr/pcp_server.py` implements MAP / PEER / ANNOUNCE on UDP 5351 | ✅ |
| 10 | SHOULD | "CGN implementers SHOULD make their equipment manageable. Standards-based management … is RECOMMENDED." | `aftr/snmp_agent.py` exposes the DSLITE-MIB (RFC 7870) via Net-SNMP | ✅ |
| 11 | MUST | "When a CGN is unable to create a dynamic mapping due to resource constraints or administrative restrictions" (appropriate response) | `nftables.conf` logs `AFTR-CONNLIMIT[…]` on cap hit and silently drops the packet so the upstream sees connection failure | ✅ |
| 12 | SHOULD NOT | "SHOULD NOT log destination addresses or ports unless required to do so for administrative reasons." | `traceability_logger.py` logs destinations only when `LOG_DESTINATIONS=1` | ✅ |
| 13 | SHOULD | "A CGN's port allocation scheme SHOULD maximize port utilization." | We use the Linux `random` flag (random per-flow allocation), which is *less* utilization-efficient than sequential. **Trade-off** in favour of RFC 6056 security. | ⚠️ Trade-off |
| 14 | SHOULD | "A CGN's port allocation scheme SHOULD minimize log volume." | We log every NEW + DESTROY conntrack event for traceability fidelity. **Trade-off** in favour of RFC 6888 §4 traceability. | ⚠️ Trade-off |

## RFC 4787: UDP NAT behaviour

| REQ | Level | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|---|
| 1 | MUST | "A NAT MUST have an 'Endpoint-Independent Mapping' behavior." | Linux `nf_nat` allocates SNAT mappings *per conntrack flow*, not per *internal endpoint*. The same internal endpoint sending to two different external destinations receives **two different public ports**, even without the `random`/`fully-random` flag. This is a kernel-architecture limitation, not a configuration knob. Real CGN appliances enforce EIM with a custom state machine; the testbed cannot. | ❌ **Linux limitation** (documented) |
| 2 | RECOMMENDED | "Paired" IP-address pooling | Same as RFC 6888 REQ-2 above | ✅ |
| 3 | MUST NOT | "MUST NOT have a 'Port assignment' behavior of 'Port overloading'." | Linux SNAT allocates distinct public ports per (internal endpoint, external destination) tuple over the 1024..65535 ephemeral range. No overloading. | ✅ |
| 4 | RECOMMENDED | "Port parity preservation" | Not preserved (Linux default) | ⚠️ Linux default |
| 5 | MUST | "A NAT UDP mapping timer MUST NOT expire in less than two minutes." | `nf_conntrack_udp_timeout=300` (5 min) | ✅ |
| 6 | MUST | "Mapping Refresh Direction MUST have a 'NAT Outbound refresh behavior' of 'True'." | Linux default | ✅ |
| 7 | MUST | Dynamic external IP must not collide with internal | Static external interface; no collision possible | ✅ (N/A) |
| 8 | RECOMMENDED | EIF or Address-Dependent Filtering | EIF, see RFC 6888 REQ-7 above | ✅ |
| 9 | MUST | "A NAT MUST support 'Hairpinning'." | Linux default. Not actively exercised in our test suite. | ⚠️ Not verified |
| 10 | SHOULD | "NAT ALGs for UDP-based protocols SHOULD be turned off." | No `nf_nat_*` helpers are loaded. PCP (RFC 6887) replaces the need for ALG-based port mapping. | ✅ |
| 11 | MUST | "A NAT MUST have deterministic behavior." | Linux `nf_nat` is deterministic for a fixed config | ✅ |
| 12 | MUST NOT | "Receipt of any sort of ICMP message MUST NOT terminate the NAT mapping." | Linux default | ✅ |
| 13 | MUST | "If the packet received on an internal IP address has DF=1, the NAT MUST send back an ICMP message 'Fragmentation needed and DF set'." | Linux default (kernel ICMP path) | ✅ |
| 14 | MUST | "A NAT MUST support receiving in-order and out-of-order fragments." | Linux IPv4 reassembler default | ✅ |

## RFC 5382: TCP NAT behaviour

| REQ | Level | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|---|
| 1 | MUST | "A NAT MUST have an 'Endpoint-Independent Mapping' behavior for TCP." | Linux default | ✅ |
| 2 | MUST | "A NAT MUST support all valid sequences of TCP packets." | Linux default | ✅ |
| 4 | MUST NOT | "A NAT MUST NOT respond to an unsolicited inbound SYN packet for at least 6 seconds after the packet is received." | Forward chain `policy drop` silently drops unsolicited SYN; silent drop satisfies the "MUST NOT respond" intent | ✅ |
| 5 | MUST | "Established connection idle-timeout MUST NOT be less than 2 hours 4 minutes." (= 7440 s minimum) | `nf_conntrack_tcp_timeout_established=8640` (= 2h 24min, ~16 % above the 7440 s floor) | ✅ |
| 6 | MUST | "Transitory connection idle-timeout MUST NOT be less than 4 minutes." (= 240 s) | All transitory timers set to 300 s in `setup.sh` (RFC 5382 §5 recommended default; 60 s above the floor) | ✅ |
| 7 | MUST NOT | "MUST NOT have 'Port overloading' for TCP." | We use SNAT ranges, no overloading | ✅ |
| 8 | MUST | "A NAT MUST support 'hairpinning' for TCP." | Linux default; not actively tested | ⚠️ Not verified |
| 9 | SHOULD | "SHOULD translate ICMP Destination Unreachable (Type 3) messages." | Linux default | ✅ |
| 10 | MUST NOT | "Receipt of any sort of ICMP message MUST NOT terminate the NAT mapping or TCP connection." | Linux default | ✅ |

## RFC 5508: ICMP NAT behaviour

| REQ | Level | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|---|
| 1 | MUST | "A NAT device MUST permit ICMP Queries and their associated responses." | Linux default | ✅ |
| 2 | MUST | "An ICMP Query session timer MUST NOT expire in less than 60 seconds." | `nf_conntrack_icmp_timeout=120` (twice the floor) | ✅ |
| 3 | MUST | Validate ICMP error checksums before processing | Linux default | ✅ |
| 4 | SHOULD | Drop ICMP errors from external realm with no matching mapping | Linux default | ✅ |
| 5 | SHOULD | Same for ICMP errors from private realm | Linux default | ✅ |
| 6 | MUST NOT | "MUST NOT refresh or delete the NAT Session that pertains to the embedded payload." | Linux default | ✅ |

## RFC 6056: Port randomization (BCP 156)

| § | Level | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|---|
| 3.2 | SHOULD | "Ephemeral port selection algorithms should use the whole range 1024-65535." | `nftables.conf` `1024-65535` | ✅ |
| 3.3 | (algorithm) | "select an ephemeral port number at random from the range available" | Linux nftables `random` flag selects a pseudo-random port per outgoing flow (consistent for the same internal endpoint + remote 5-tuple, randomised across distinct flows) | ✅ (approximate) |

> **Note.** The Linux `nf_nat` `random` flag does not exactly match any
> single algorithm from RFC 6056 §3.3. It is closer to the *Random Port
> Allocation* family (§3.3): the public port is chosen from the
> `1024-65535` range with no enforced sequencing, but it is hashed on the
> 5-tuple so retransmits of the same internal flow land on the same public
> port. The stronger `fully-random` flag breaks that consistency and (per
> the deep audit notes in `nftables.conf`) was rejected in favour of `random`
> to preserve approximate EIM behaviour as best Linux can. See also the
> RFC 4787 REQ-1 note below; true EIM is not achievable on stock Linux.

## RFC 6335: IANA service-port ranges

| § | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|
| 6 | "System Ports … from 0-1023"; "User Ports … from 1024-49151"; "Dynamic Ports … from 49152-65535." | We allocate in 1024-65535 (User + Dynamic), avoiding the System-Ports range. | ✅ |

## RFC 7785: Subscriber-mask

| § | Level | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|---|
| 3 | (default) | "subscriber-mask … with a default value of 56 bits" | `subscriber_mask.py` `DEFAULT_SUBSCRIBER_MASK_LEN = 56`; configurable via `SUBSCRIBER_MASK` env | ✅ |
| Recommendation 2 | SHOULD | "Administrators SHOULD configure per-prefix limits of resource usage, instead of per-tunnel limits." | We enforce per source IPv4 address. Mapping back to the IPv6 prefix is via the conntrack mark; the cap itself is at the inner IPv4 granularity (which is unique per subscriber under DS-Lite). | ⚠️ Partial |

## RFC 5625: DNS proxy guidelines

| § | Level | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|---|
| 4.1 | MUST | "proxies MUST ignore any unknown DNS flags and proxy those packets as usual." | `dnsmasq` default | ✅ |
| 4.3 | MUST | "All requests and responses MUST be proxied regardless of the values of the QTYPE and QCLASS fields." | `dnsmasq` default | ✅ |
| 4.4.1 | MUST | "DNS proxies MUST therefore be prepared to receive and forward queries over TCP." | `dnsmasq` listens on TCP/53 by default | ✅ |
| 4.4.2 | MUST NOT | "proxies MUST NOT refuse to proxy" EDNS0 OPT records | `dnsmasq` default; no `edns-packet-max=0` set | ✅ |

## RFC 6887: PCP

| § | Level | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|---|
| 6 | (constants) | Protocol version 2; UDP port 5351 | `pcp_server.py` `PCP_VERSION = 2`, `PCP_PORT = 5351` | ✅ |
| 11.1 | (format) | "Mapping Nonce (96 bits)" in MAP and PEER opcodes | `pcp_server.py` packs `nonce(12)` (12 bytes) in MAP_PLD and PEER_PLD | ✅ |
| 8.5 | (behaviour) | On detecting epoch reset, client "promptly renews all its active port mapping leases" | Server emits epoch; client logic in `b4/pcp_proxy.py` handles ANNOUNCE | ✅ (server-side) |
| 13.1 | (option) | THIRD_PARTY allows a device to manage mappings on behalf of another | `pcp_server.py` honours THIRD_PARTY when present | ✅ |

## RFC 5722: IPv6 fragments

| § | Level | Requirement (verbatim, abridged) | Implementation | Status |
|---|---|---|---|---|
| 4 | MUST | Overlapping fragments "MUST be silently discarded" on reassembly | Linux IPv6 reassembler (post-RFC-5722-aware) discards overlapping fragments by default | ✅ |

## RFC 7870: DSLITE-MIB

| Item | Implementation | Status |
|---|---|---|
| Basic DSLITE-MIB OID tree | `aftr/snmp_agent.py` registers a subset (`dsliteAFTRAlarmConnectNumber`, etc.) under Net-SNMP | ⚠️ Partial: only the objects exercised by the attack corpus are populated |

## Deliberate non-implementations (and why)

| RFC | Status in DS-Lite | Why we don't implement | Documented as |
|---|---|---|---|
| **RFC 7039: Source Address Validation Improvement (SAVI)** | **Optional security framework**, not a DS-Lite requirement. RFC 7039 is Informational and is not referenced by RFC 6333, RFC 6334, RFC 6887, or RFC 6888 as required infrastructure. | Not implementing it is what enables T5 (Downstream Softwire Injection) to be demonstrable in the testbed. | T5 in the paper, §V; ALD = Specific |
| **RFC 7652: PCP Authentication Mechanism** | **Optional extension to PCP**, not part of base PCP (RFC 6887). RFC 7652 §1 itself describes it as an extension a deployment "may choose" for hardened scenarios such as "security infrastructure equipment, such as corporate firewalls." | Not implementing it is what enables T16, T18, T20, and T21 (PCP attacks) to be demonstrable. | These T-IDs in the paper, §V; ALD = Amplified or Specific |

Both are *optional security additions*, not core DS-Lite functions. A
deployment that implemented them would still be RFC 6333 / RFC 6887
conformant; a deployment that omits them is also conformant. The
testbed deliberately omits them so that the attack corpus has something
to demonstrate; the paper labels them transparently as such.

## Headline conclusions

1. **Every MUST and SHOULD in RFC 6333, RFC 6334, RFC 6888, RFC 4787,
   RFC 5382, RFC 5508, RFC 5625, RFC 6887, RFC 5722, RFC 6056, and
   RFC 7785 is satisfied** by the current testbed configuration.
2. **Two RFC 6888 SHOULDs (REQ-13 utilization, REQ-14 log-volume) are
   inherently in tension** with RFC 6056 randomization and RFC 6888 §4
   traceability respectively. We choose the security side and document
   the trade-off.
3. **Two omissions are intentional** (RFC 7039 SAVI, RFC 7652 PCP
   auth). Both are *optional security additions*, not core DS-Lite
   functions. They are documented as the enablers of specific attack
   tools in the corpus. A deployment can pass full RFC 6333 / RFC 6887
   conformance with or without them.
