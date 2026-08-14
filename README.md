# DS-Lite Security Testbed

A reproducible Dual-Stack Lite (RFC 6333) security testbed. The whole lab runs
inside one Docker container. It builds two customer routers (B4), a provider
Address Family Transition Router (AFTR) with carrier-grade NAT, a DHCPv6 and DNS
provisioning server, an Internet-side server, and an on-path attacker. A corpus
of 12 attacks and 8 verified defenses is bundled and driven from one script.

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

1. Run any of the 12 attacks and watch the measured result.
2. Open the Defenses menu, turn a control on or off, then re-run the attack it
   closes.
3. Watch live traffic on any device, or open a shell on any device.
4. Restore the lab to a clean baseline at any time.

## The attack corpus

The 12 attacks span the data, control, and management planes of the DS-Lite stack.

| ID | Attack | Surface |
|---|---|---|
| T1 | NAT binding-table exhaustion | Data: NAT/CGN |
| T2 | Softwire endpoint spoofing and on-path interception | Data: softwire |
| T3 | Unencrypted-tunnel interception | Data: softwire |
| T4 | Downstream softwire injection | Data: softwire |
| T5 | Softwire reassembly poisoning | Data: fragmentation |
| T6 | Unauthorized PCP THIRD_PARTY forwarding | Control: PCP |
| T7 | Cross-subscriber PCP PEER enumeration | Control: PCP |
| T8 | B4 DNS cache poisoning | Control: DNS |
| T9 | Rogue AFTR discovery hijack | Control: DHCPv6 |
| T10 | DS-Lite MIB unauthenticated access | Management: SNMP |
| T11 | Unauthenticated softwire decapsulation (open relay) | Data: softwire |
| T12 | Softwire identity multiplication | Data: softwire |

Three supplementary carrier-grade-NAT tools ship alongside the corpus, documented
but outside the paper's executed set: `TS1` shared-IPv4 reputation poisoning,
`TS2` PCP port-exhaustion, and `TS3` PCP ANNOUNCE (epoch) spoofing.

## Running one attack directly

You do not need the menu. To run a single attack in one narrated terminal:

```bash
docker exec -it ds-lite-lab bash /testbed/scripts/run_attack_live.sh T1
```

Replace `T1` with any identifier from the table. The runner prints each step,
measures the effect with an independent verifier, compares it to the stored
reference, and saves the packet captures under `pcaps/runs/`.

## The defenses

Each attack has a matching control. All are verified: with the control off the
attack succeeds, and with it on the attack is blocked. The reliable control for
each attack is listed below.

| Defense | Closes | Mechanism |
|---|---|---|
| `TRABELSI` | T1 | Split half-open and established session table with a per-subscriber cap |
| `SAVI` | T2, T4, T5, T12 | Source-address validation at the softwire ingress |
| `ESP_AEAD` | T3 | Authenticated encryption (IPsec ESP) on the softwire |
| `PCP_OWNERSHIP` | T6, T7 | THIRD_PARTY ownership check on port requests |
| `DNS_COOKIES` | T8 | DNS Cookies (RFC 7873) at the B4 resolver |
| `DHCPV6_AUTH` | T9 | Signed DHCPv6 provisioning messages |
| `SNMP_USM` | T10 | SNMPv3 USM authenticated management access |
| `DECAP_BIND` | T11 | Decapsulation-time provisioned-source binding (the RFC 6333 optional ingress filter) |

Toggle a defense from the host:

```bash
bash testbed/defenses/article_defenses.sh SAVI on
bash testbed/defenses/article_defenses.sh SAVI off
```

Then re-run the attack it closes (for `SAVI` that is T2, T4, T5, or T12) and compare.

Verify all defenses in one pass:

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
  attack_tools/        the attack tools, grouped by surface
  defenses/            the defense toggles and the verifier
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
