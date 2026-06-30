# DS-Lite Security Testbed — Full Walkthrough

A complete, honest description of the testbed: how it is set up, how it runs, how
to monitor it, the 15 attacks (with their impact), and the 11 defences (with their
impact). Written so you can read it top-to-bottom, reproduce every step, and
evaluate the work yourself.

> **Scope & integrity note.** Every attack and defence in this document has been
> run live and verified. The consolidated off/on verification (real measured
> numbers) is in [`results/defense_verification/VERIFY_ALL.txt`](../results/defense_verification/VERIFY_ALL.txt)
> and is reproducible with `bash testbed/defenses/verify_all.sh`. Reference packet
> captures are in [`testbed/reference_captures/`](reference_captures/).

---

## 1. What DS-Lite is (the thing under test)

DS-Lite (RFC 6333) lets an ISP keep serving IPv4 to customers over an IPv6-only
access network, sharing a few public IPv4 addresses among many subscribers:

```
  client (10.0.1.100)                                      Internet
        │ IPv4                                          (198.51.100.2)
        ▼                                                     ▲
   ┌─────────┐   IPv4-in-IPv6 softwire    ┌──────────────┐    │ shared public
   │   B4    │═══════════════════════════▶│     AFTR     │────┘ IPv4 192.0.2.1
   │ (CPE)   │   (4-in-6, proto 41)       │ (CGNAT core) │   (CGNAT / NAT44)
   └─────────┘                            └──────────────┘
   encapsulates                            decapsulates, then NAT44s many
   IPv4 in IPv6                            subscribers behind one public IPv4
```

- **B4** (Basic Bridging BroadBand element) = the customer CPE. It encapsulates
  the subscriber's IPv4 packets inside IPv6 and sends them to the AFTR.
- **AFTR** (Address Family Transition Router) = the ISP core. It decapsulates,
  then performs carrier-grade NAT (CGNAT) so many subscribers egress under one
  shared public IPv4.
- The B4 learns which AFTR to use via **DHCPv6 option 64** (an AFTR *name*,
  RFC 6334), which it then **DNS-resolves** to an address and builds the softwire.
- **PCP** (Port Control Protocol, RFC 6887) lets a subscriber ask the AFTR for an
  inbound port mapping. **SNMP** (DSLITE-MIB, RFC 7870) manages the AFTR.

Every one of those mechanisms is an attack surface, and that is what the testbed
exercises.

---

## 2. Architecture of the testbed

The whole lab is **one privileged Docker container** that builds an isolated
network out of Linux network namespaces (one per role) wired by Linux bridges.

```
                         ┌──────────────────── br-isp (carrier IPv6 segment) ──────────────────────┐
   client1 ──[eth-lan]── B4-1 ──[eth-isp]──┤                                                       │
   (10.0.1.100)          (::b41)           ├── AFTR ──[eth-wan]── server-router ── server          │
                                           │   (::10)             (198.51.100.x)  (198.51.100.2)   │
   client2 ──[eth-lan]── B4-2 ──[eth-isp]──┤                                                       │
   (10.0.2.100)          (::b42)           ├── dhcpv6server (::1)   dns-server (::2)               │
                                           ├── attacker (::13a)  ← created on demand               │
                                           └───────────────────────────────────────────────────────┘
   mgmt (10.99.0.x) ──[br-mgmt]── AFTR mgmt (10.99.0.1)   ← SNMP management plane
```

Namespaces (`docker exec ds-lite-lab ip netns list`):

| netns | role | key address |
|---|---|---|
| `b4-1`, `b4-2` | customer CPEs (B4) | `2001:db8:cafe::b41` / `::b42`, LAN `10.0.1.1` / `10.0.2.1` |
| `client1`, `client2` | subscriber LAN hosts | `10.0.1.100` / `10.0.2.100` |
| `aftr` | CGNAT core (AFTR) | `2001:db8:cafe::10`, mgmt `10.99.0.1`, public pool `192.0.2.1` |
| `dhcpv6server` | provisioning (DHCPv6 + RA) | `2001:db8:cafe::1` |
| `dns-server` | ISP recursive resolver | `2001:db8:cafe::2` |
| `server`, `server-router` | public Internet server | `198.51.100.2` |
| `mgmt` | operator OAM station | `10.99.0.2` |
| `attacker` | the adversary (lazily created) | `2001:db8:cafe::13a` |

### Where everything lives in `testbed/`
- `Dockerfile`, `entrypoint.sh`, `setup.sh`, `requirements.txt` — build + boot.
- `aftr/` — the AFTR: `pcp_server.py`, `snmp_agent.py`, `nftables.conf` (the
  CGNAT rules), `monitor_nat.sh`, `subscriber_mask.py`, `traceability_logger.py`.
- `b4/` — the B4: `pcp_proxy.py`, `dhclient6*.conf`, `dhclient6-exit-hook.sh`
  (resolves the AFTR name → rebuilds the softwire).
- `dhcpv6server/`, `server/` — provisioning + public-server configs.
- `scripts/` — orchestration: `attack_lib.sh` (single source of per-attack truth),
  `run_attack_live.sh` (the narrated runner), `ds_menu.py` (menu UI),
  `capture_references.sh` (this doc's captures), `test_connectivity.sh`.
- `attack_tools/` — the actual attack programs (see §6).
- `defenses/` — the article/RFC defences + the dispatcher + verifier (see §7).
- `attack_trees/` — attack–defence trees (QuADTool `.xml`/`.prism`/`.dot` + figures).
- `reference_captures/` — baseline + per-attack + per-defence pcaps (see §8).

---

## 3. Setup & configuration (how it boots)

From the project root:

```sh
./run.sh
```

What happens:
1. **Build** — `run.sh` builds the image from `testbed/` if sources changed
   (`COPY . /testbed/`; `.dockerignore` keeps pcaps/caches/figures out).
2. **Start** — runs one privileged container (`--privileged`, 4 GB, 4 CPUs),
   bind-mounting `./pcaps` → `/testbed/pcaps` for run outputs, publishing `:8080`.
3. **`entrypoint.sh` → `setup.sh`** builds the topology: creates every namespace,
   the `br-isp`/`br-mgmt` bridges and veth pairs, assigns addresses, starts the
   softwire (ip6tnl) on each B4, applies the AFTR `nftables.conf` (CGNAT + per-B4
   conntrack zones), and launches the services (dhcpd6, radvd, dnsmasq, the PCP
   server + proxies, the SNMP agent, the public HTTP server).
4. When the log prints **`testbed is ready`**, the menu appears.

Key configuration knobs:
- `testbed/defenses/topology.env` — addresses, public pool, subscriber roster
  (data, not code; add a B4 by adding one row).
- AFTR CGNAT policy — `testbed/aftr/nftables.conf` (per-subscriber conntrack zones
  + a per-B4 connection cap meter).

### Sanity check after boot
```sh
docker exec ds-lite-lab ip netns exec client1 \
  curl -s -o /dev/null -w '%{http_code}\n' http://198.51.100.2/      # expect 200
docker exec ds-lite-lab /testbed/scripts/test_connectivity.sh         # full check
```
A healthy lab returns **200** for both client1 and client2 (subscriber IPv4
reaching the Internet through the softwire + CGNAT).

---

## 4. Running the testbed (the menu)

`./run.sh` opens a command palette:
- **Attack** — pick T1…T15; optionally tweak a curated knob; one narrated terminal
  shows the attack launch, captures at the reference points, measures the outcome,
  prints **MATCH/DIFFERS** against the stored result, and saves to `./pcaps/runs/`.
- **Watch** — open a live capture on any interface.
- **Shell** — drop into any namespace.
- **Restore** — reset to a clean vulnerable baseline (all defences off, attack
  residue cleared, health re-checked).
- **Settings** — attacker placement, connectivity test.
- **Quit** — stops the lab cleanly (a lab you only reattached to is left running).

Everything the menu does can also be driven directly:
```sh
# run one attack
docker exec -it ds-lite-lab bash /testbed/scripts/run_attack_live.sh T1
# toggle a defence
bash testbed/defenses/article_defenses.sh SAVI on
# verify every defence off/on (the honest table)
bash testbed/defenses/verify_all.sh
```

---

## 5. Monitoring (how to see what's happening)

- **Live capture** — `ip netns exec <ns> tcpdump -i <iface> -n` on any point.
  The carrier side (`b4-1 eth-isp`) shows softwire/DHCPv6/DNS/PCP/NDP; the AFTR
  public side (`aftr eth-wan`) shows the CGNAT egress as the shared IPv4.
- **CGNAT state** — `ip netns exec aftr conntrack -L` (the NAT session table);
  `ip netns exec aftr conntrack -C` (count). `aftr/monitor_nat.sh` tails it.
- **PCP** — the AFTR PCP server logs MAP/PEER/ANNOUNCE; the nft `nat pcp_dnat`
  chain holds the inbound mappings.
- **SNMP** — `snmpget/snmpwalk -v2c -c public 10.99.0.1 <oid>` reads the DSLITE-MIB.
- **The narrated runner** prints, for each attack, the surface, the exact command,
  the measured signal, and the verdict — the fastest way to *see* impact.
- **Reference captures** (§8) — open the baseline and any attack/defence pcap in
  Wireshark and compare.

---

## 6. The attacks (and their impact)

15 attacks across the DS-Lite surfaces. Each is a real program in
`testbed/attack_tools/`, driven by `attack_lib.sh` (`do_Tn`), and each has a clean
capture in `reference_captures/attacks/Tn/`.

| ID | Name | Surface | What it does | Impact (measured) |
|----|------|---------|--------------|-------------------|
| **T1** | NAT Binding-Table Exhaustion | CGNAT | floods half-open sessions to fill the shared NAT table | victim client1 200→**000**, co-subscriber stays up |
| **T2** | Shared-IPv4 Reputation Poisoning | CGNAT | one subscriber emits abuse that egresses as the shared IPv4 | all abuse sourced from `192.0.2.1` — collective blame |
| **T3** | Tunnel-Endpoint Spoofing | softwire | forges the victim B4 as the outer IPv6 source | AFTR accepts spoofed softwire packets as the victim |
| **T4** | Unencrypted-Tunnel Interception | softwire | passively reads the cleartext 4-in-6 inner traffic | victim's inner HTTP recovered in cleartext |
| **T5** | Downstream Softwire Injection | softwire | forges AFTR→B4 packets carrying a spoofed inner source | forged inner IPv4 reaches the victim LAN |
| **T6** | Softwire Reassembly Poisoning | fragment | injects offset-0 inner-IPv4 fragments sharing the victim's reassembly tuple (predictable IP-ID) | victim's fragmented flow dropped (~67% loss) |
| **T7** | PCP Port-Exhaustion DoS | PCP | floods MAP requests to drain a per-subscriber pool | a co-subscriber's legit MAP is refused |
| **T8** | Unauthorized THIRD_PARTY Forwarding | PCP | MAP with THIRD_PARTY naming a *different* subscriber | AFTR installs a DNAT pointing at a victim it doesn't own |
| **T9** | PCP ANNOUNCE Spoof (Epoch Reset) | PCP | forges a multicast ANNOUNCE with epoch=0 | one packet provokes a MAP-renewal storm |
| **T10** | Cross-Subscriber PCP PEER Enumeration | PCP | PEER (wildcard) to read another subscriber's external ports | leaked external port == victim's real port |
| **T11** | Softwire DNS-Discovery Hijack | DNS | **off-path** poisoning of the B4's AFTR-FQDN resolution (SADDNS/Kaminsky model: granted port + TXID brute in a wide window) | B4 caches `aftr… → attacker`, would rebuild the softwire to the attacker |
| **T12** | Rogue AFTR Substitution | DHCPv6 | rogue DHCPv6 hands a forged AFTR-Name (option 64) | B4 adopts the attacker's AFTR name |
| **T13** | Transparent AFTR Hijack | DHCPv6 | keeps the legit name but rebinds it to the attacker | softwire rebuilt to the attacker, name unchanged |
| **T14** | SNMP Alarm-Table Write | SNMP/MIB | SNMP SET raises an alarm threshold to its max | alarm can never fire (write succeeds: value→2147483647) |
| **T15** | SNMP MIB Information Disclosure | SNMP/MIB | SNMP walk reads the DSLITE-MIB | discloses multiple subscribers' private NAT 5-tuples |

### How to run any attack

Two ways, both do the same thing:

1. **Menu:** `./run.sh` → **Attack** → pick `Tn` → Enter (defaults) or tweak a knob.
2. **Direct (from the repo root, on the host):**
   ```sh
   docker exec -it ds-lite-lab bash /testbed/scripts/run_attack_live.sh <Tn> [knob=value ...]
   ```

What one run does, in order: resets the lab to the clean vulnerable baseline →
starts captures at the same points the reference used → launches the real attack
tool from `attack_tools/`, narrating each step → measures the outcome signal →
prints **MATCH / DIFFERS** vs the stored ground truth → saves everything
(`config.txt`, `RESULT.txt`, the pcaps) under **`./pcaps/runs/<UTC-stamp>_<Tn>/`**.
The frozen reference for comparison stays in `reference_captures/attacks/Tn/`.

**Per-attack command** (defaults shown; append `knob=value` to change a knob).
`…` below = `docker exec -it ds-lite-lab bash /testbed/scripts/run_attack_live.sh`:

| ID | Command (run on host) | Tunable knobs (default \| alt) |
|----|------------------------|--------------------------------|
| T1 | `… T1` | `intensity=fast`\|`medium`, `target=198.51.100.2` |
| T2 | `… T2` | `count=150`\|`300`, `target=198.51.100.2` |
| T3 | `… T3` | `count=8`\|`16`, `target=198.51.100.2` |
| T4 | `… T4` | `requests=6`\|`12`, `target=198.51.100.2` |
| T5 | `… T5` | `count=15`\|`30`, `spoof=203.0.113.66` |
| T6 | `… T6` | `band=60`\|`40`, `target=198.51.100.2` |
| T7 | `… T7` | `count=600`\|`1200` |
| T8 | `… T8` | `victim=10.0.2.100` |
| T9 | `… T9` | `count=10` |
| T10 | `… T10` | `trials=2`\|`3`, `flows=3` |
| T11 | `… T11` | `rounds=2`\|`4` |
| T12 | `… T12` | `fqdn=aftr-evil.attacker.example` |
| T13 | `… T13` | `fqdn=aftr.dslite.example.com` |
| T14 | `… T14` | `value=4294967295` |
| T15 | `… T15` | (none) |

Example with a knob: `… T1 intensity=medium`.

**Read the impact yourself:** after a run, read the saved `RESULT.txt` (measured
signal + MATCH/DIFFERS verdict), and open the matching capture in
`reference_captures/attacks/Tn/` — each has a `README.md` that walks the pcap
packet by packet.

---

## 7. The defences (and their impact)

Each attack has a defence that implements the **actual mechanism of a research
article** (or the canonical RFC where no deployable article exists). They are
**reversible live toggles** in one dispatcher:
`bash testbed/defenses/article_defenses.sh <ID> on|off`.

| Defence ID | Defends | Grounding | Mechanism | Off→On impact (measured) |
|---|---|---|---|---|
| **TRABELSI** | T1 | Trabelsi, *IEEE Access* 2018 | two-structure session table: collapse the half-open (invalid) timeout so floods age out, established flows keep their timeout | client1 **000 → 200** |
| **ESP_AEAD** | T4 | Degabriele & Paterson, *IEEE S&P* 2007 | authenticated AEAD (AES-GCM) ESP on the softwire | cleartext markers **20 → 0** (ESP ciphertext) |
| **SAVI** | T3, T5, T6 | Chen/Liu, *SAVI access network* | per-port source-IP↔port binding on the carrier bridge; drop spoofed sources | spoofed reaching AFTR **14 → 0** |
| **FEISTEL_IPID** | T6 | Gilad & Herzberg, *ACM TISSEC* 2013 §8.3 | rewrite inner-IPv4 IP-ID with a keyed Feistel permutation (unpredictable) at the B4 (NFQUEUE) | sequential-prediction hits **2000 → 0** |
| **PCP_OWNERSHIP** | T8, T10 | Rytilahti & Holz, *NDSS* 2020 | PCP server rejects MAP/PEER/THIRD_PARTY outside the requester's prefix | cross-sub DNAT **5 → 0** |
| **PCP_QUOTA** | T7 | RFC 6887 §16.5 / 6888 REQ-4 | per-subscriber mapping cap | co-subscriber MAP **REFUSED → OK** |
| **PCP_AUTH** | T9 | RFC 7652 | confirm a suspected epoch reset via an authenticated unicast ANNOUNCE before renewing | renewal storms **6 → 0** |
| **NAT_LOG** | T2 | RFC 6888 REQ-9 / 6302 | per-binding attribution logging (shared IP:port ↔ subscriber) | attribution records **0 → 200** |
| **SNMP_USM** | T14, T15 | *Under New Management*, WOOT 2012 | SNMPv3 USM authNoPriv (HMAC) + pinned engineID; drop v1/v2c | attacker SET=2147483647 → **dropped**, OAM reads 60 |
| **DHCPV6_AUTH** | T12, T13 | Albalawi & Aljuhani, *Sådhanå* 2020 | Ed25519-signed DHCPv6 (SA option + replay field); B4 verifies before adopting option 64 | B4 adopts **evil → legit** |
| **DNS_0X20** | T11 | Dagon et al., *ACM CCS* 2008 | DNS-0x20: randomise query-name case; accept only a reply echoing it | cache **poisoned → not poisoned** |

### How to implement (apply / remove) any defence

All defences are **one dispatcher**, run from the repo root on the host (the
script `docker exec`s into the lab itself, so you do **not** prefix it):

```sh
bash testbed/defenses/article_defenses.sh <ID> on      # apply the defence
bash testbed/defenses/article_defenses.sh <ID> off     # remove it (back to vulnerable)
```

`on` swaps in the article's mechanism live (starts a daemon, installs the
binding/nft rule, or rebinds a service); `off` reverts to the clean vulnerable
baseline. **Typical workflow:** apply the defence, then run the attack it defends
(§6) and confirm the impact is gone. (For the automatic off→on self-test of every
defence at once, use `verify_all.sh` below.)

**Per-defence command and the attack(s) it defends:**

| Defence ID | Defends | Apply | Remove |
|---|---|---|---|
| `TRABELSI` | T1 | `… TRABELSI on` | `… TRABELSI off` |
| `NAT_LOG` | T2 | `… NAT_LOG on` | `… NAT_LOG off` |
| `SAVI` | T3, T5, T6 | `… SAVI on` | `… SAVI off` |
| `ESP_AEAD` | T4 | `… ESP_AEAD on` | `… ESP_AEAD off` |
| `FEISTEL_IPID` | T6 | `… FEISTEL_IPID on` | `… FEISTEL_IPID off` |
| `PCP_QUOTA` | T7 | `… PCP_QUOTA on` | `… PCP_QUOTA off` |
| `PCP_OWNERSHIP` | T8, T10 | `… PCP_OWNERSHIP on` | `… PCP_OWNERSHIP off` |
| `PCP_AUTH` | T9 | `… PCP_AUTH on` | `… PCP_AUTH off` |
| `DNS_0X20` | T11 | `… DNS_0X20 on` | `… DNS_0X20 off` |
| `DHCPV6_AUTH` | T12, T13 | `… DHCPV6_AUTH on` | `… DHCPV6_AUTH off` |
| `SNMP_USM` | T14, T15 | `… SNMP_USM on` | `… SNMP_USM off` |

`…` = `bash testbed/defenses/article_defenses.sh`. Example end-to-end check:
```sh
bash testbed/defenses/article_defenses.sh TRABELSI on        # defend T1
docker exec -it ds-lite-lab bash /testbed/scripts/run_attack_live.sh T1   # attack -> now blocked
bash testbed/defenses/article_defenses.sh TRABELSI off       # restore vulnerable baseline
```

**Verify every defence at once (the honest table):**
```sh
bash testbed/defenses/verify_all.sh
```
It runs each defence OFF (attack succeeds) then ON (attack blocked) against the
*actual* attack and prints real numbers. The last canonical run:
`results/defense_verification/VERIFY_ALL.txt` → **11 PASS, 0 FAIL**.

Per-defence write-ups (article, mechanism, exact oracle) are in
`results/defense_verification/T*.md`.

---

## 8. Reference captures (`testbed/reference_captures/`)

Stored inside the project so they ship with it and are easy to compare against:

```
reference_captures/
  baseline/    normal operation, every communication type, NO attack
               baseline_b4-1_eth-isp.pcap   (softwire/DHCPv6/DNS/PCP/NDP)
               baseline_aftr_eth-wan.pcap   (CGNAT egress as the shared IPv4)
               baseline_aftr_mgmt.pcap      (SNMP)
               baseline_client1_eth-lan.pcap (subscriber LAN)
  attacks/Tn/  each attack run cleanly (attack SUCCEEDS) + RESULT.txt
  defenses/    <DEF>_OFF_*.pcap (attack lands) vs <DEF>_ON_*.pcap (blocked)
```

How to use them: open `baseline_*` in Wireshark to see correct DS-Lite behaviour,
then open an attack pcap to see the deviation, then the `_ON_` defence pcap to see
the deviation removed. Regenerate any time with
`bash testbed/scripts/capture_references.sh`.

**Isolation guarantee.** The capture script performs a full `lab_restore`
*before every attack* and *before and after every defence* — it restarts the PCP
server+proxies (fresh pool), restarts the SNMP agent (resets any altered alarm
threshold), restores the stock DHCPv6 + B4 resolver, flushes conntrack/NAT/NDP,
removes all defence state, and heals the softwire. So no capture inherits leftover
state or configuration from the previous one; each is a clean, independent run.

---

## 9. How to evaluate this work (a checklist for you)

1. **Boot & baseline** — `./run.sh`; confirm both clients = 200; open
   `reference_captures/baseline/*` and confirm normal softwire + CGNAT + DHCPv6 +
   DNS + PCP + SNMP traffic.
2. **Each attack works** — run T1…T15; each prints a measurable impact and
   MATCH; cross-check against `reference_captures/attacks/Tn/RESULT.txt`.
3. **Each defence works** — `bash testbed/defenses/verify_all.sh`; confirm
   11 PASS, and that the OFF/ON numbers match the table in §7.
4. **The mechanisms are real, not name-borrowed** — read any
   `results/defense_verification/T*.md`: it names the article, quotes the
   mechanism, and shows the exact off/on oracle. The implementations are in
   `testbed/defenses/` (e.g. `ipid_feistel.py`, `dhcpv6auth.py`, `snmpv3_usm.py`).
5. **Spec conformance** — `testbed/aftr/RFC-COMPLIANCE.md` maps the AFTR
   implementation to RFC 6333/6334/6887/6888/7870.

If anything does not reproduce, that is a finding — the runner and the verifier
print real numbers, so the claims here are auditable rather than asserted.
