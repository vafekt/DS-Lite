# DS-Lite testbed — node legend (who is who in the captures)

Read this first. Every reference capture (`baseline/`, `attacks/`, `defenses/`)
refers to the nodes and addresses defined here.

## Stable identities (fixed by `testbed/setup.sh` — same every run)

| Node (netns) | Role | IPv4 | IPv6 (stable) | On segment |
|---|---|---|---|---|
| `client1` | subscriber host behind B4-1 (the **victim**) | `10.0.1.100` | – | B4-1 LAN |
| `client2` | subscriber host behind B4-2 (a **co-subscriber**, control) | `10.0.2.100` | – | B4-2 LAN |
| `b4-1` | B4 / CPE for subscriber 1 (encapsulates IPv4-in-IPv6) | LAN `10.0.1.1`, tunnel `192.0.0.2` | **`2001:db8:cafe::b41`** (softwire id) | carrier (br-isp) |
| `b4-2` | B4 / CPE for subscriber 2 | LAN `10.0.2.1`, tunnel `192.0.0.2` | **`2001:db8:cafe::b42`** | carrier |
| `aftr` | AFTR / CGNAT core (decapsulates + NAT44) | softwire `192.0.0.1`, **public `192.0.2.1`** (shared), mgmt `10.99.0.1` | **`2001:db8:cafe::10`** (softwire endpoint) | carrier + WAN + mgmt |
| `dns-server` | ISP recursive resolver | – | **`2001:db8:cafe::2`** | carrier |
| `dhcpv6server` | provisioning (DHCPv6 + RA) | – | **`2001:db8:cafe::1`** | carrier |
| `server` | public Internet web server | **`198.51.100.2`** | – | WAN |
| `server-router` | router between AFTR WAN and the server | `198.51.100.x` | – | WAN |
| `mgmt` | operator OAM / NOC station | **`10.99.0.10`** | – | mgmt (br-mgmt) |
| `attacker` | the adversary (created on demand) | – | **`2001:db8:cafe::13a`** | carrier |

The **shared public IPv4 `192.0.2.1`** is the CGNAT egress that *all* subscribers
share — the heart of the shared-fate attacks (T2). The **AFTR FQDN**
`aftr.dslite.example.com` is what the B4 resolves (DHCPv6 option 64 → DNS) to
find its AFTR.

## Per-run values (CHANGE every container start — do NOT hard-match these)

- **MAC addresses** — pinned in `setup.sh` / `attack_lib.sh` so link-local and
  SLAAC are reproducible and match Fig.1 of the paper: b4-1 `b6:7a:fa:cb:9a:72`,
  b4-2 `42:a9:c9:d5:e4:d7`, aftr `d2:fb:f6:71:7d:2b`, dhcpv6 `f2:47:33:7c:d8:ac`,
  dns `3e:fe:d4:fc:87:cb`, attacker `2a:29:47:aa:9c:56`. The DHCPv6-leased B4
  address (e.g. `::134`) is still assigned dynamically and may vary.
- **DHCPv6-leased / SLAAC IPv6 on the B4** — e.g. this run b4-1 also holds
  `::1da/128` (DHCPv6 lease) and `2001:db8:cafe:0:20b7:eff:fe02:1090/64` (SLAAC).
  These are *extra* addresses; the softwire is always sourced from the stable
  `::b41`. The attacker SLAAC address also varies; its stable carrier address is
  `::13a`.

**Recognition rule of thumb:** match attacks/impact by the **stable identities
and protocol fields** (e.g. "softwire packet whose outer IPv6 source is `::b41`
but did not originate from b4-1's port", "SNMP SET to a read-write alarm-threshold OID `…240.1.3.1.6/.7/.8`",
"DHCPv6 ADVERTISE Option-64 ≠ `aftr.dslite.example.com`"), never by a MAC or a
leased address.

## Services & protocols (what each node speaks)

| Protocol | Where | Detail |
|---|---|---|
| **4-in-6 softwire** | b4-1/b4-2 `eth-isp` ↔ aftr `eth-isp` | IPv4-in-IPv6, IP-proto 4; outer IPv6 `::b4N → ::10` |
| **CGNAT (NAT44)** | aftr `eth-wan` | many subscribers → shared `192.0.2.1` |
| **DHCPv6** (RFC 8415) + **option 64** (RFC 6334) | dhcpv6server `::1` ↔ b4 | AFTR-Name = `aftr.dslite.example.com.` ; UDP 547 (server) / 546 (client) ; multicast `ff02::1:2` |
| **DNS** | resolver `::2` | `aftr.dslite.example.com` → AAAA `2001:db8:cafe::10`; `server.dslite.example.com` → A `198.51.100.2`; `client1.dslite.example.com` → A `10.0.1.100`; UDP 53 |
| **PCP** (RFC 6887) | client → b4 proxy `10.0.x.1:5351` → aftr `::10:5351` | MAP / PEER / ANNOUNCE; multicast ANNOUNCE on `ff02::1:5350` |
| **SNMP** (DSLITE-MIB, RFC 7870) | mgmt `10.99.0.10` → aftr `10.99.0.1:161` (OUT-OF-BAND mgmt net) | community `public` (v1/v2c baseline); OID base `1.3.6.1.2.1.240`; r/w alarm thresholds `dsliteAFTRAlarm{Connect,Session,Port}Number` = `…240.1.3.1.{6,7,8}` (ConnectNumber is `Integer32 60..90`) |
| **HTTP** | client → `198.51.100.2:80` | the end-to-end subscriber traffic through softwire + CGNAT |

## Reading the captures

- Filenames say the capture point: `<node>_<iface>`. The carrier side is
  `b4-1 eth-isp` (softwire/DHCPv6/DNS/PCP/neighbor discovery); the public side is
  `aftr eth-wan` (CGNAT egress); the management side is `aftr eth-mgmt` (SNMP).
- Each `attacks/Tn/` and `defenses/<DEF>/` folder has a `README.md` that
  describes every capture, the relevant packets (verified by reading the pcap),
  the impact, and the IP-independent recognition rule.

## How to read a TCP connection attempt (RST vs. retransmission vs. no reply)

Across these captures a client's `SYN` ends in one of three ways. The difference
tells you *exactly* what happened to the packet, so it matters:

| What you see | What it means | Why it happens |
|---|---|---|
| `SYN` → `SYN-ACK` (`[S]` → `[S.]`) | **Success.** Port open and reachable. | The server accepted the connection. Normal traffic. |
| `SYN` → `RST` (`[S]` → `[R.]` / `[R]`) | **Actively refused.** The host is reachable but nothing is listening on that port. | The server's TCP stack got the SYN, found no listener, and *replied* with a reset. A RST is a deliberate "go away" — proof the host received your packet. (Seen in T2's port **scan**: the scanner hits closed ports, the server RSTs each.) |
| `SYN`, then the **same** `SYN` again ~1s/2s/4s later, **no reply at all** | **Silently dropped (blackhole).** The packet was discarded somewhere in the path with no notification. | Nobody answers, so the client's kernel cannot tell "lost" from "slow" and **retransmits the identical SYN** (same source port, same seq) on an exponential timer (RTO ≈ 1s, 2s, 4s). Wireshark labels the repeats `[TCP Retransmission]`. This is what a **drop** looks like — there is no RST because the dropper stays silent. |

So:
- **RST** = an active rejection by a host that *did* receive the packet (e.g. a
  closed port). You learn the host is up.
- **Retransmission / no reply** = a silent **drop** in the path (a full NAT
  table, a firewall/blocklist `drop`, a blackhole). You learn nothing came back.
- A lone `SYN` with no follow-up is the *start* of that same drop story; if the
  capture runs long enough you will see the retransmits.

In this testbed the **denial-of-service impacts (T1 NAT-full, T2 blocklist) show
up as the third row** — retransmitted SYNs with no answer — because the victim's
packets are silently dropped. A `RST` is *not* a DoS symptom; it is a normal
"port closed" answer and appears in the **scan** traffic, not the impact.
