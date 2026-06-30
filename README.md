# DS-Lite Security Testbed

A reproducible Dual-Stack Lite (RFC 6333) security testbed. The whole lab runs
inside one Docker container. It builds two customer routers (B4), a provider
Address Family Transition Router (AFTR) with carrier-grade NAT, a DHCPv6 and DNS
provisioning server, an Internet-side server, and an on-path attacker. A corpus
of 15 attacks and 11 verified defenses is bundled and driven from one script.

The lab is meant for hands-on learning and research. Every attack runs end to
end against a conformant stack. Every defense can be toggled on and off so you
can watch an attack succeed, enable the matching control, and watch it fail.

## What is inside

| Component | Role |
|---|---|
| B4-1, B4-2 | Customer routers. Each builds an IPv4-in-IPv6 softwire to the AFTR and runs a DNS proxy and a PCP proxy. |
| AFTR | Provider element. Terminates the softwires, applies carrier-grade NAT onto one shared public IPv4 address, and runs the PCP server and the SNMP agent. |
| DHCPv6 / DNS server | Provisions each B4 with its AFTR name (RFC 6334) and resolves names. |
| Server | Internet-side HTTP service for end-to-end probes. |
| Attacker | On-path host on the carrier segment, or a host on a customer LAN. |

The two subscribers behind B4-1 and B4-2 let you test whether one subscriber can
affect another through the shared provider element.

## Prerequisites

You need a Linux host with:

* Docker (the lab runs in one privileged container).
* Bash.

Optional, for the nicest experience:

* Python 3 with `prompt_toolkit` for the filterable command menu. Install it with
  `pip install prompt_toolkit`. Without it the script falls back to a plain
  numbered menu.
* Wireshark and a terminal emulator if you want live packet windows.

No Python packages are required on the host to run the attacks. The container
ships everything it needs.

## Quick start

```bash
git clone https://github.com/vafekt/DS-Lite.git
cd DS-Lite
./run.sh
```

The first run builds the Docker image. This takes a few minutes. Later runs
reuse the image and start in seconds. When sources change the image rebuilds
automatically.

`run.sh` opens an interactive menu. From it you can:

1. Run any of the 15 attacks and watch the measured result.
2. Open the Defenses menu, turn a control on or off, then re-run the attack it
   closes.
3. Watch live traffic on any device, or open a shell on any device.
4. Restore the lab to a clean baseline at any time.

## The attack corpus

The 15 attacks span the three planes of the DS-Lite stack.

| ID | Attack | Surface |
|---|---|---|
| T1 | NAT binding-table exhaustion (self) | Data: NAT/CGN |
| T2 | Shared-IPv4 reputation poisoning | Data: NAT/CGN |
| T3 | Softwire endpoint spoofing and on-path interception | Data: softwire |
| T4 | Unencrypted-tunnel interception | Data: softwire |
| T5 | Downstream softwire injection | Data: softwire |
| T6 | Softwire reassembly poisoning | Data: fragmentation |
| T7 | PCP port-exhaustion denial of service | Control: PCP |
| T8 | Unauthorized THIRD_PARTY forwarding | Control: PCP |
| T9 | PCP ANNOUNCE spoof (server-restart signal) | Control: PCP |
| T10 | Cross-subscriber PCP PEER enumeration | Control: PCP |
| T11 | Softwire DNS-discovery hijack | Control: DNS |
| T12 | Rogue AFTR substitution | Control: DHCPv6 |
| T13 | Transparent AFTR hijack | Control: DHCPv6 |
| T14 | SNMP alarm-table write | Management: SNMP |
| T15 | SNMP MIB information disclosure | Management: SNMP |

## Running one attack directly

You do not need the menu. To run a single attack in one narrated terminal:

```bash
docker exec -it ds-lite-lab bash /testbed/scripts/run_attack_live.sh T1
```

Replace `T1` with any identifier from the table. The runner prints each step,
measures the effect with an independent verifier, compares it to the stored
reference, and saves the packet captures under `pcaps/runs/`.

## The defenses

Each attack has a matching control. All 11 are verified: with the control off
the attack succeeds, and with it on the attack is blocked. The reliable control
for each attack is listed below.

| Defense | Closes | Mechanism |
|---|---|---|
| `TRABELSI` | T1 | Early eviction of half-open connection state |
| `NAT_LOG` | T2 | Per-subscriber attribution logging |
| `SAVI` | T3, T5, T6 | Per-port source-address validation on the carrier |
| `ESP_AEAD` | T4 | Authenticated encryption on the softwire |
| `FEISTEL_IPID` | T6 | Unpredictable packet identifiers (secondary to SAVI) |
| `PCP_QUOTA` | T7 | Per-subscriber port-mapping limit |
| `PCP_OWNERSHIP` | T8, T10 | Ownership check on port requests |
| `PCP_AUTH` | T9 | Authenticated control messages |
| `DNS_0X20` | T11 | Query case randomization at the resolver |
| `DHCPV6_AUTH` | T12, T13 | Signed provisioning messages |
| `SNMP_USM` | T14, T15 | Authenticated management access |

Toggle a defense from the host:

```bash
bash testbed/defenses/article_defenses.sh SAVI on
bash testbed/defenses/article_defenses.sh SAVI off
```

Then re-run the attack it closes (for `SAVI` that is T3, T5, or T6) and compare.

Verify all 11 defenses in one pass:

```bash
bash testbed/defenses/verify_all.sh
```

## Reference captures

`testbed/reference_captures/` holds packet captures that ship with the project,
so you can inspect the expected behavior without running anything.

* `baseline/` is normal DS-Lite traffic with no attack.
* `attacks/Tn/` is each attack running successfully, with a `README.md` and a
  `RESULT.txt` that records the measured result.
* `defenses/` shows each control off (attack succeeds) and on (attack blocked).

Regenerate them all from the running container:

```bash
bash testbed/scripts/capture_references.sh
```

## Repository layout

```
testbed/
  attack_tools/        the 15 attack tools, grouped by surface
  defenses/            the 11 defense toggles and the verifier
  aftr/  b4/           the provider and customer-router programs
  dhcpv6server/ server/ provisioning and Internet-side services
  scripts/             the attack runner, the capture tool, helpers
  reference_captures/  bundled baseline, attack, and defense captures
  attack_trees/        per-attack attack-defense trees and figures
  Dockerfile           the one-container lab image
  WALKTHROUGH.md       a longer guided tour
run.sh                 the launcher and interactive menu
```

## Stopping the lab

Choose Quit in the menu, or stop the container directly:

```bash
docker rm -f ds-lite-lab
```

## How it works

The AFTR keys its connection state on each subscriber's softwire identity, so a
flood from one subscriber is held to that subscriber's own budget. Sharing one
public IPv4 address across many subscribers is what makes some attacks reach
beyond the attacker. The lab lets you measure exactly when an attack stays inside
one subscriber and when it crosses to a co-resident.

The default build turns on the controls the RFCs require and leaves the optional
hardening off. That is the baseline the attacks run against. Each defense is the
control that an operator would add to close its attack.

## Safety and intended use

This testbed is for education and authorized research. Everything runs inside an
isolated Docker network with documentation addresses (RFC 5737 and RFC 3849). Do
not point the attack tools at any network you do not own or have permission to
test.

## License and citation

This project is released under the GNU General Public License v3.0. See
`LICENSE`.

Authors: Viet Anh Phan and Jan Jerabek, Department of Telecommunications, Brno
University of Technology.
