# Baseline reference captures — normal DS-Lite operation (no attack)

Node identities, addresses and the per-run-vs-stable distinction are in
[`../NETWORK.md`](../NETWORK.md). Each capture below is **clean** (a tight BPF
filter, only the protocol in question) and every packet description here was
**verified by reading the pcap**, not assumed.

---

## DHCPv6 — `dhcpv6_full-exchange.pcap`  (captured at dhcpv6server `eth-isp`)

The B4 bootstraps via DHCPv6 (RFC 8415) and learns its AFTR name via **Option 64**
(RFC 6334). This is the full four-message exchange, in order:

| # | Time(Δ) | Message | From → To | Key contents (read from the pcap) |
|---|---|---|---|---|
| 1 | 0.000 s | **SOLICIT** | b4-1 `fe80::…1090`.546 → `ff02::1:2`.547 | client-ID; **Option-Request = DNS-server + AFTR-Name**; IA_NA (IAID 235016336) |
| 2 | +0.0001 s | **ADVERTISE** | server `fe80::…3a30`.547 → b4-1.546 | offers IA_ADDR **`2001:db8:cafe::133`** (pltime 240 / vltime 300); **DNS-server `2001:db8:cafe::2`**; **AFTR-Name `aftr.dslite.example.com`** |
| 3 | +1.07 s | **REQUEST** | b4-1.546 → `ff02::1:2`.547 | confirms server-ID + the offered IA_ADDR `::133` |
| 4 | +0.0001 s | **REPLY** | server.547 → b4-1.546 | commits IA_ADDR `::133`; repeats **DNS-server `::2`** and **AFTR-Name `aftr.dslite.example.com`** |

**What this proves:** the provisioning plane is real and complete — the B4
solicits, the server advertises, the B4 requests, the server replies, and the
**AFTR-Name option (64)** carrying `aftr.dslite.example.com` is delivered in both
the ADVERTISE and the REPLY. This option is the surface that T12/T13 (rogue
DHCPv6) abuse, and that the DHCPV6_AUTH defence signs.

**Recognition rule (IP-independent):** a legitimate exchange is the ordered set
{SOLICIT→ADVERTISE→REQUEST→REPLY} on UDP 546/547 where the server messages carry
`AFTR-Name = aftr.dslite.example.com` and `DNS-server = 2001:db8:cafe::2`. A rogue
(T12/T13) is a second ADVERTISE/REPLY whose AFTR-Name ≠ `aftr.dslite.example.com`
or whose DNS-server ≠ `::2` (see `attacks/T12/`, `attacks/T13/`).

> Note: tcpdump prints `bad udp cksum` because checksum offload is on in the
> namespace (the kernel/NIC fills it in on TX); the packets are valid on the wire.

---

---

## DNS — `dns_resolution.pcap`  (captured at b4-1 `eth-isp`)

The B4 resolves the AFTR FQDN (and the test server) at the ISP resolver `::2`.

| # | Query/Answer | From → To | Contents (read from the pcap) |
|---|---|---|---|
| 1 | **AAAA? `aftr.dslite.example.com`** | b4-1 `::133`.39698 → `::2`.53 | txid 31709, EDNS (`[1au]`) |
| 2 | **Answer** | `::2`.53 → b4-1 | `aftr.dslite.example.com AAAA `**`2001:db8:cafe::10`** (1 answer, authoritative `*`) |
| 3 | **A? `server.dslite.example.com`** | b4-1.58459 → `::2`.53 | txid 35463 |
| 4 | **Answer** | `::2`.53 → b4-1 | `server.dslite.example.com A `**`198.51.100.2`** |

**What this proves:** DNS is real and correct — the AFTR FQDN resolves to the
AFTR's softwire endpoint `::10` (this is the value the B4 builds its tunnel to),
and the public server name resolves to `198.51.100.2`. This is the surface T11
(off-path poisoning) targets and DNS-0x20 defends.

**Recognition rule:** a correct resolution returns `aftr.dslite.example.com →
AAAA 2001:db8:cafe::10`. A poisoned one (T11) returns the attacker address
(`2001:db8:cafe::13a`) instead.

---

## PCP — `pcp_map.pcap`  (captured at b4-1 `eth-isp`, proxy→AFTR leg)

A subscriber asks the AFTR (via the B4 PCP proxy) to open an inbound mapping.

| # | Message | From → To | Contents (read from the pcap) |
|---|---|---|---|
| 1 | **MAP request** (PCP v2, operation 1) | b4-1 `::133`.56555 → AFTR `::10`.5351 | UDP len 80; payload version byte `02`, operation `01` (MAP) |
| 2 | **MAP response** | AFTR `::10`.5351 → b4-1 | UDP len 60 |

The requesting client logged the result: **`Mapping created: 192.0.2.1:1024`** —
the AFTR allocated external port **1024** on the shared public IPv4 `192.0.2.1`
for the client's internal port 8080.

**What this proves:** the PCP control plane works — a subscriber can open an
inbound port on the shared address. This is the surface T7 (pool exhaustion),
T8 (THIRD_PARTY), T9 (ANNOUNCE), T10 (PEER) abuse.

**Recognition rule:** a legit MAP is a `MAP request → MAP response` on UDP 5351
returning an external `192.0.2.1:<port>` for the *requester's own* internal IP.

---

## SNMP — `snmp_get.pcap`  (captured at AFTR `eth-mgmt`)

The operator (NOC) reads the DSLITE-MIB (RFC 7870) over SNMPv2c, community
`public`, on the **out-of-band management network** (`10.99.0.0/24`, `eth-mgmt`).
The agent binds `10.99.0.1:161`; UDP/161 is dropped on the data interfaces
(`eth-isp`, `eth-wan`), so subscribers/the Internet cannot reach it. tcpdump
decodes the PDUs fully:

| # | PDU | From → To | OID = value (read from the pcap) |
|---|---|---|---|
| 1 | **GetRequest** | mgmt `10.99.0.10` → AFTR `10.99.0.1`.161 | `.1.3.6.1.2.1.240.1.2.2.0` (NAT binding count) |
| 2 | **GetResponse** | AFTR → mgmt | `…240.1.2.2.0 = 5` |
| 3 | **GetRequest** | mgmt → AFTR.161 | `.1.3.6.1.2.1.240.1.3.1.6` (`dsliteAFTRAlarmConnectNumber`, RFC 7870 §8) |
| 4 | **GetResponse** | AFTR → mgmt | `…240.1.3.1.6 = 60` |

**What this proves:** the management plane is a real SNMP agent answering
DSLITE-MIB OIDs at their **RFC 7870 §8 positions** (here: 5 active NAT bindings;
the tunnel-count alarm threshold `dsliteAFTRAlarmConnectNumber` at `.240.1.3.1.6`
= 60, its `Integer32 (60..90)` default). The three read-write thresholds are
`.6 ConnectNumber`, `.7 SessionNumber`, `.8 PortNumber`; `.1`–`.5` are the
accessible-for-notify identity objects (`.1` = `dsliteAFTRAlarmB4AddrType`, an
address-type, **not** a threshold). This is the surface T14 (raise/disable an
alarm threshold) and T15 (walk + disclose the bind table) abuse, and that
SNMP_USM defends.

**Recognition rule:** legit OAM is GetRequest/GetResponse from `10.99.0.10` on the
mgmt network. The attack is a **SET to a read-write threshold (`…240.1.3.1.6/.7/.8`)**
— e.g. raising `PortNumber` (`.8`) to disable the per-user NAT-port alarm — or a
GETNEXT walk of `…240.1.2.1` (the bind table) disclosing subscriber connections. A
conformant agent **rejects** an out-of-range SET (e.g. `ConnectNumber` > 90).

---

## Softwire + CGNAT — `softwire_4in6_b4-1_eth-isp.pcap` + `cgnat_egress_aftr_eth-wan.pcap`

The end-to-end subscriber data path: client1 → 4-in-6 softwire → AFTR decap +
NAT44 → shared public IPv4 → server. The SAME TCP handshake captured on both legs
(matching seq `3710375672` proves it is one flow):

**On the softwire (`softwire_4in6…`, b4-1 eth-isp):** inner IPv4 carried inside
outer IPv6.
```
IP6 2001:db8:cafe::b41 > 2001:db8:cafe::10:  IP 10.0.1.100.39982 > 198.51.100.2.80: [S] seq 3710375672
IP6 2001:db8:cafe::10  > 2001:db8:cafe::b41: IP 198.51.100.2.80 > 10.0.1.100.39982: [S.] ...
```
**On the WAN (`cgnat_egress…`, aftr eth-wan):** the same flow, now NAT'd — the
private `10.0.1.100:39982` became the shared public **`192.0.2.1:62245`**.
```
IP 192.0.2.1.62245 > 198.51.100.2.80: [S] seq 3710375672      (SAME seq = same flow)
IP 198.51.100.2.80 > 192.0.2.1.62245: [S.] ...
```

**What this proves:** the core DS-Lite mechanism works — IPv4-in-IPv6
encapsulation (outer `::b41 → ::10`, IP-proto 4) and carrier-grade NAT to a
shared public IPv4. Every data-plane attack (T1 exhausting the NAT, T3/T5
forging the softwire, T4 reading it, T6 poisoning reassembly) targets this path.

**Recognition rule:** a legit softwire packet is `IP6 ::b4N > ::10` (proto 4)
carrying the subscriber's own inner IPv4; the matching WAN packet is sourced from
the shared `192.0.2.1`. A forged softwire (T3/T5/T6) has outer source `::b41` but
did NOT originate from b4-1's bridge port (see `attacks/T3`, `T5`, `T6`).

