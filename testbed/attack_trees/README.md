# Attack-Defense Trees (QuADTool export)

**Formalism audit + canonical re-model (2026-06-27):** see [`ADTREE_AUDIT.md`](ADTREE_AUDIT.md) — leaves are now attacker actions only, the impact is the root goal, system-reaction/goal-restating leaves removed.

QuADTool-rendered attack-defense trees (ADTrees) for the 15-attack DS-Lite
corpus (T1-T15, see `../attack_corpus.txt`). Each tree is a Kordy-Mauw
attack-defense tree with the SAND (sequential-AND) extension for the ordered
attacker lifecycle: red ellipses are attacker actions, green ellipses are
countermeasures attached via a NOT gate to the step they neutralize, and the
blue root is the attacker goal.

## Layout

| Path | Contents |
|---|---|
| `quadtool/tN.dot`   | QuADTool `.dot` source — the attack-defense diagram (gate vocabulary incl. SAND) |
| `quadtool/tN.xml`   | QuADTool XML form of the same tree |
| `quadtool/tN.prism` | PRISM stochastic-game model — the tree converted for probabilistic model checking |
| `figures/tN.pdf`    | Rendered tree figure (QuADTool's own GUI renderer, headless) |
| `figures/tN.png`    | Same figure as PNG for quick viewing |

## Tree -> attack map (T1-T15)

| Tree | Attack |
|---|---|
| T1  | NAT Binding-Table Exhaustion (per-B4 cap; phased flood->hold siege) |
| T2  | Shared-IPv4 Reputation Poisoning |
| T3  | Softwire Endpoint Spoofing & On-Path MITM |
| T4  | Unencrypted-Tunnel Interception |
| T5  | Downstream Softwire Injection (inbound dual of T3) |
| T6  | Softwire Reassembly Poisoning |
| T7  | PCP Port-Exhaustion DoS |
| T8  | Unauthorized THIRD_PARTY Forwarding |
| T9  | PCP ANNOUNCE Spoof (Epoch Reset) |
| T10 | Cross-Subscriber PCP PEER + THIRD_PARTY |
| T11 | Softwire DNS-Discovery Hijack |
| T12 | Rogue AFTR Substitution |
| T13 | Transparent AFTR Hijack (DNS impersonation) |
| T14 | SNMP Alarm-Table Write |
| T15 | SNMP MIB Information Disclosure |

## Regeneration

The trees are defined once in `results/adtool_trees/build_trees.py` (single
source of truth). To rebuild and re-export here:

```bash
# 1. emit QuADTool .dot + PRISM from the tree definitions, render the figures
bash results/adtool_trees/render_with_quadtool.sh

# 2. refresh this export folder from the pipeline output
bash testbed/attack_trees/export.sh
```

The QuADTool model-checking bridge (QuADTool.jar, Dorfhuber et al. 2024) is
used structurally: the trees convert to PRISM/UPPAAL models and a Boolean
reachability check confirms each defense closes its attack. Leaf attributes
are uniform placeholders (the analysis is qualitative).
