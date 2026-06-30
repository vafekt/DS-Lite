# DS-Lite defences — per-family OFF/ON evidence

Each subdirectory is one **defence leaf** from the attack–defence trees in
[`../../attack_trees/figures/`](../../attack_trees/figures/). For every family we
run the **actual attack** twice — once with the defence **OFF** (the vulnerable
baseline, attack succeeds) and once **ON** (attack blocked) — and capture the
packets/logs that show the difference. A defence is only listed as verified when
**both** halves hold (OFF succeeds **and** ON blocks).

- Authoritative one-pass result table: [`VERIFY_ALL.txt`](VERIFY_ALL.txt)
- Reproduce the table: `bash testbed/defenses/verify_all.sh`
- Re-capture this evidence: `bash testbed/defenses/capture_defenses.sh`
  (writes to `pcaps/defcap/<FAMILY>/`, then collected here)

## Families → tree defence leaf → attacks defended

| Family (dir) | Tree defence leaf | Attacks | OFF (attack succeeds) | ON (blocked) |
|---|---|---|---|---|
| [`TRABELSI`](TRABELSI/) | Two-structure session table / early eviction | T1 | victim cut off (`client1=000`) | victim served (`client1=200`) |
| [`NAT_LOG`](NAT_LOG/) | Per-subscriber attribution log | T2 | abuse not attributable (0 records) | abuse attributed to the subscriber (200 records) |
| [`SAVI`](SAVI/) | Per-port source-address validation | T3, T5, T6 | forged-source traffic reaches the provider | forged-source traffic dropped |
| [`ESP_AEAD`](ESP_AEAD/) | Authenticated encryption on the softwire | T4 | 20 plaintext request markers readable | 0 (ciphertext only) |
| [`FEISTEL_IPID`](FEISTEL_IPID/) | Unpredictable packet identifiers | T6 (partial) | next identifier predictable (2000/2000) | prediction defeated (0 hits) |
| [`PCP_QUOTA`](PCP_QUOTA/) | Per-subscriber port-mapping limit | T7 | co-subscriber request refused | co-subscriber request served |
| [`PCP_OWNERSHIP`](PCP_OWNERSHIP/) | Ownership check on port requests | T8, T10 | 5 cross-subscriber forwardings installed | 0 (refused) |
| [`PCP_AUTH`](PCP_AUTH/) | Authenticated control messages | T9 | renewal storm triggered | no storm |
| [`DNS_0X20`](DNS_0X20/) | Query case randomization | T11 | resolver poisoned to attacker | poisoning fails |
| [`DHCPV6_AUTH`](DHCPV6_AUTH/) | Signed provisioning messages | T12, T13 | provider name = `aftr-evil.attacker.example` | provider name = `aftr.dslite.example.com` |
| [`SNMP_USM`](SNMP_USM/) | Authenticated management access | T14, T15 | default-password write succeeds | write rejected |

> **T6 defence note.** The reliable control for the reassembly-collision attack
> (T6) is **SAVI**: with per-port source validation on, the attacker's spoofed
> fragments are dropped and the victim sees no loss. **FEISTEL_IPID** is a
> secondary, article-grounded control (Gilad & Herzberg 2013) that defeats
> identifier *prediction*; it weakens but does not fully stop an on-path attacker
> that observes the live identifier and races it. Its evidence here is the
> algorithm property (`selftest.txt`); the live attack is closed by SAVI.

All eleven families verified (see `VERIFY_ALL.txt`).
