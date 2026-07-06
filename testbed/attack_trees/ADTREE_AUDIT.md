# Attack–Defence Tree audit (formalism conformance)

Honest, unbiased check of the 15 DS-Lite AD-trees against the standard
attack-/AD-tree literature, and the canonical re-model applied on 2026-06-27.

## References used
- B. Schneier, *Attack Trees* (1999) — leaves are attacker actions; root is the goal.
- S. Mauw, M. Oostdijk, *Foundations of Attack Trees* (ICISC 2005) — a node is
  **refined** into the actions that achieve it; **leaves are basic actions**.
- B. Kordy, S. Mauw, S. Radomirović, P. Schweitzer, *Foundations of
  Attack–Defense Trees* (FAST 2010) — bipartite proponent/opponent nodes;
  countermeasures alternate attacker/defender.
- R. Jhawar et al., *Attack Trees with Sequential Conjunction* (IFIP SEC 2015) —
  **SAND**: ordered conjunction; each child is a step that enables the next.
- M. Dorfhuber et al., *QuADTool* (QEST+FORMATS 2024) — the tool used here;
  inherits AND/OR/SAND from ADTool, adds PAC quantitative analysis.

## What was already correct
- **SAND root for an ordered attacker lifecycle** is legitimate (Jhawar et al.;
  ADTool/QuADTool support it).
- **Bipartite typing**: red = attacker, green = defence; OR for alternative
  sub-paths, AND for conjunctive requirements.
- **Defences as countermeasures**, encoded for the verification bridge as
  `AND(step, NOT(defence))` (the Boolean "step succeeds AND defence absent"),
  which converts cleanly to the PRISM reachability check (15/15 convert).

## The defect (found 2026-06-27)
Across **all 15** trees, the SAND sequence mixed three different kinds of node as
equal siblings:
1. **attacker actions** (correct leaves) — e.g. *Flood unique 5-tuples*, *Forge
   4-in-6*, *GETNEXT walk*;
2. **system reactions** (not attacker actions) — e.g. *AFTR drops the datagram*,
   *AFTR installs DNAT*, *Clients believe the AFTR rebooted*, *Reputation service
   blocklists the address*;
3. **the goal restated as a leaf** (redundant) — e.g. *Victim's fragmented flow
   denied*, *Subscriber IPs disclosed*, *Legitimate mappings blocked*, *Inbound
   reaches the victim*.

By Mauw–Oostdijk/Kordy this is non-canonical: **leaves must be basic attacker
actions**, the **goal lives only at the root**, and **environment reactions are
not nodes**. Mixing them makes the step-by-step ambiguous — a reader cannot tell
which nodes they must *perform* versus which simply *happen* as a consequence.
(This is exactly the "looks weird / what do I apply step-by-step?" concern.)

## The fix (canonical re-model)
In `results/adtool_trees/build_trees.py` (single source of truth) every tree now
contains **only attacker actions** in its SAND; the goal stays at the root;
system-reaction and goal-restating leaves were removed; any defence that had been
attached to a removed leaf was **moved to the attacker action it actually
neutralises**.

Concrete example — **T1** (the one flagged):
- before: SAND[ vantage, **SHOCK**, *instant denial*, **SIEGE**, *durable denial* ]
- after:  SAND[ vantage, **SHOCK** (Phase 1), **SIEGE** (Phase 2) ]

So the operator playbook is unambiguous and ordered: **(1)** gain a flooding
vantage → **(2)** Phase-1 SHOCK (flood unique 5-tuples to fill the cap; gives
immediate but volatile denial) → **(3)** Phase-2 SIEGE (hold ESTABLISHED
connections so the cap stays full; makes the denial durable). Phase 1 then Phase
2. The denial itself is the **root goal**, not a step.

The same surgery was applied to T2, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14,
T15. T3 and T4 were already action-only and were left unchanged. Some trees are
now genuinely short (T2 = one action; T9/T13 = two) — that is honest: those
attacks really are few-step. Defence relocations: T9 `Authenticated ANNOUNCE` →
*Forge an ANNOUNCE*; the PCP-ownership / SAVI / ESP defences on removed reaction
leaves were already duplicated on the corresponding action leaf.

## Figure legend (put this in the caption)
- **Red** = attacker action / goal; **green** = defence (countermeasure).
- **Ellipse** = basic event (leaf action or defence); **box** = gate or goal.
- The **goal is the bottom (blue) box**; read upward.
- Gates: **`&` = AND** (all inputs needed); **`|` = OR** (any input); **`!` = NOT**
  (true when the defence is absent); the **root `&` with numbered edges 1,2,3 =
  SAND** (sequential-AND: the steps happen in that order).
- A defence is wired `green -> ! -> &`, so a defended step = `action & !defence`
  ("the step works only while the defence is off"). Enabling the defence makes
  `!defence` false, the `&` fails, and the goal becomes unreachable (the PRISM
  check). Symbols are kept glyph-consistent: every gate shows only its glyph (no
  redundant "[OR]"/"[AND]" word), with text on the goal/sub-goals only.

Example, T1 as a formula:
`SAND[ (co-located host) OR (forge source AND not SAVI),
       (Phase-1 flood) AND not eviction,
       (Phase-2 hold)  AND not eviction ]`.

## On the `AND(action, NOT(defence))` rendering — precedent
The figures draw a defended step as `&` over the action with a `!` over the green
defence, i.e. `action ∧ ¬defence`. This is the **Boolean / inhibition encoding** of
a countermeasure and is **established in the literature** (not idiosyncratic):
- **Attack-Fault-Defense Trees** (Soltani et al., *Safety-Security Analysis via
  Attack-Fault-Defense Trees*): defines the **inhibition (INH) gate** as
  `INH(w1|w2) = w1 ∧ ¬w2`, drawn as a gate with **green = the defensive/prevention
  effect** — exactly our `AND(action, NOT(defence))`. "ADTs add defenses **and
  inhibitors** to ATs."
- **Kordy, Mauw et al.** (Foundations of Attack-Defense Trees): negation `¬` is part
  of the standard semantics (De Morgan lattice); the **Boolean valuation** of a
  defended node is `attack ∧ ¬defence`. QuADTool's analysis is "correct with
  reference to standard **Boolean** valuations of attack-defense trees."
- **Aslanyan & Nielson**: an explicit **negation operator** for AD-trees (cited in
  Widel et al., *Beyond 2014*).
- **Fault-tree analysis** (IEC 61025): NOT / INHIBIT gates are standard.
Nuance: AFDT papers usually draw a single *INH* gate symbol (defence = the negated
inhibiting input); our figures show the decomposed two-gate Boolean form (`!` then
`&`) that QuADTool emits. Same function; the single-INH glyph is the textbook look
if a reviewer prefers it. The alternative is the pure Kordy-Mauw visual (green
counter-measure node + dashed edge, no gate) produced by build_trees.py's forest
renderer — kept as a preview, not shipped.

## Terminology pass (publication wording)
The node labels were rewritten to precise, standard terminology (RFC 6333/6887/7039
+ published literature), removing informal shorthand that is not used in
peer-reviewed work:
- "vantage" / "flooding vantage" → "on-path (carrier) position" / "a position that
  charges the flood to the victim's binding limit";
- "cap" → "per-subscriber NAT binding limit";
- the "SHOCK" / "SIEGE" codenames → "Phase 1 (transient): burst-flood …" /
  "Phase 2 (sustained): hold established connections …";
- "Recon" → "Reconnaissance"; "frame it in the NAT log" → "attribute it in the
  operator's NAT log"; "True MITM" → "Sustained NDP poisoning holds the AFTR cache
  (interception and denial of service)"; "in clear" → "in cleartext";
- "4-in-6" → "IPv4-in-IPv6"; "proto-4" → "IP protocol 4"; bare position codes
  "(P1)/(P2)" → spelled-out positions; "OAM" → "management agent"; "NOC" →
  "network operations centre".
RFC-standard terms are kept (softwire, AFTR, B4, AFTR, 5-tuple, FQDN, epoch, MAP/
PEER/ANNOUNCE/THIRD_PARTY, Option 64, MIB/GET/GETNEXT, NDP, SAVI, ESP). The attack
**runner** (`do_T1`) still uses the internal SHOCK/SIEGE phase identifiers in code/
logs; only the figures and paper-facing labels were reworded.

## Relation to the reference-capture READMEs
The per-attack `testbed/reference_captures/attacks/Tn/README.md` files carry a
"Mapping to the attack–defence tree" table that enumerates the **full attack
decomposition** — the attacker actions **plus** the realised impact and (for
some) the system reaction, because each README's job is to show *what the packet
capture demonstrates*, including the impact. The canonical **figure** keeps only
the attacker actions with the impact at the **root**. So a row like "Victim's
fragmented flow denied → demonstrated" in a README now corresponds to the tree's
**root goal**, not a leaf. This is intentional (evidence write-up vs. formal
action sequence); the substance — which steps and which defences — is identical.

## Regeneration
`bash results/adtool_trees/render_with_quadtool.sh && bash testbed/attack_trees/export.sh`
re-emits the `.dot`/`.prism`/`.xml` and the QuADTool-rendered `figures/tN.pdf`,
and refreshes this bundle. The PRISM reachability check still passes 15/15 (each
defence closes its attack), so the quantitative bridge is unaffected.

## Update 2026-07-04 — reviewer sharpening (DS-Lite specificity + defense de-duplication)
Two issues raised on review of the trees:
1. **Duplicate defense across SAND/AND conjuncts.** 6 trees attached the SAME defense to
   more than one *conjunctive* sibling (T1 D_trabelsi; T4 D_esp; T6 D_feistel; T11 D_0x20;
   T12 D_dhcpauth; T13 D_dhcpauth). Per Kordy et al., a countermeasure attaches to the node it
   *directly* neutralizes, and for a conjunction breaking ONE required step defeats the goal —
   so the duplicate is redundant (and, e.g. for T13, semantically wrong: signed DHCPv6 is not a
   DNS control). Fixed: each defense now sits on the single action it neutralizes
   (T1->Phase1; T4->Capture; T6->Inject; T11->Flood; T12->rogue-Advertise; T13->rogue-DHCPv6).
   Repeats across **OR-branches are kept** (T3 D_esp on the three escalate branches) — closing an
   OR *requires* the defense on every branch; that is correct, not redundant.
   Coverage matrix UNCHANGED (same defense still closes each attack), so the paper's coverage
   claims are unaffected.
2. **Too generic labels (T13).** "DHCPv6 race / rogue DNS" read as any-network. Relabeled to the
   DS-Lite mechanisms: AFTR-Name option (Option 64), the B4's AFTR provisioning, the AFTR FQDN,
   and softwire re-termination — so a reviewer sees it is unmistakably DS-Lite.
Source of truth: results/adtool_trees/build_trees.py; re-rendered via render_with_quadtool.sh;
paper fig_adtree_t13 + adtree.tex prose/caption updated; testbed figures re-exported.

## Update 2026-07-04 (b) — QuADTool-style detail + layout + tool name
Reviewer: our trees were too abstract (short SAND chains, fat nodes, wasted horizontal space)
next to the QuADTool paper's example (branching AND/OR, short labels, concrete path). Fixes:
- T13 decomposed to the concrete path: join provisioning segment -> AND(keep AFTR-Name Opt 64,
  set attacker as resolver Opt 23, win the DHCPv6 race) -> rogue resolver maps AFTR FQDN. The AND
  spreads it horizontally (aspect 2.24 -> 1.60).
- T14/T15 gained an OR for reaching the agent (P3 management network / P1 softwire-to-mgmt gap),
  both real; aspect fixed to landscape.
- T2 "obtain sending position" -> OR(co-subscriber LAN host / own subscription).
- T7, T9 kept short: they are genuinely 2 attacker actions; padding with "NO_RESOURCES returned" /
  "B4 re-MAPs" would be SYSTEM-REACTION leaves, which this audit forbids.
- Caption fixed: the tool is QuADTool (QRender drives QuADTool's GraphFrame), not ADTool.
All 15 re-rendered; aspects now 0.5-1.6 except T7 (1.98, honest 2-step). Coverage matrix unchanged.

## Correction 2026-07-04 (c) — reverted a fabricated refinement in T13
On review against the QuADTool paper's formal ADT (Def.: leaves are BASIC ATTACK STEPS / basic
events with a success valuation; OR = alternative methods; AND = distinct necessary sub-goals):
the T13 "AND(keep Opt 64, set Opt 23, win race)" I had added was NON-canonical — "keep Option 64"
and "set Option 23" are FIELDS of one crafted packet, not basic events (no independent
success/failure). Reverted to the faithful SAND chain: join segment -> win the DHCPv6 race with a
rogue Reply (Opt 64 kept, Opt 23 rogue resolver; details in the node LABEL) -> rogue resolver maps
the AFTR FQDN. The 3-step SAND still spreads horizontally (aspect 1.70), so fidelity did not cost
much layout. KEPT: T14/T15/T2 "obtain-X -> OR[alternative access/positions]" and T14/T15 separate
"authenticate" node with the USM defense — both match the QuADTool example (obtain-credentials OR;
authenticate node with the password-auth defense). Rule followed: no packet-field / system-reaction
/ goal-restating leaves; only real basic attack steps.
