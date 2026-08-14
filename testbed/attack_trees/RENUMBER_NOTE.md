# 12-attack QuADTool bundle — status

The QuADTool trees track the paper's 12-attack scheme (T1-T12) plus the
name-preserving rogue-AFTR variant (T9b) and the three supplementary CGNAT
weaknesses (TS1-TS3): 16 trees, each shipped as `.dot` (source) + `.prism`
(PRISM stochastic game) + `.xml` (UPPAAL timed automata) in `quadtool/`, with a
QuADTool-rendered figure in `figures/`.

## Reconciliation of T9-T12 (done)

Earlier the T10-T12 trees were misaligned, inherited from the pre-renumber
corpus. They are now authored to the paper's definitions
(`submission/tables/framework_table.tex`, `submission/sections/case-study.tex`):

1. **T10 — DS-Lite MIB unauthenticated access.** The two former MIB facets
   (state disclosure + alarm suppression, previously split across two trees) are
   MERGED into one, matching the paper's single attack: after reaching the agent
   and authenticating with the default community, an `AND` node performs both the
   writable operation (raise the alarm threshold to Integer32-max, blinding the
   NOC) and the readable one (walk the binding table, disclosing subscriber inner
   addresses). SNMPv3 USM on the required authenticate step closes both.

2. **T11 — Unauthenticated softwire decapsulation** (the relay). New tree: an
   unprovisioned carrier host sends IPv4-in-IPv6 under its own carrier source and
   the AFTR relays it laundered as the shared public IPv4. Closed by the
   decapsulation-time provisioning check (DECAP-BIND, the RFC 6333 §11 optional
   ingress filter) — SAVI/uRPF do not reach it, since the outer source is the
   attacker's own valid address.

3. **T12 — Softwire source spoofing** (identity multiplication). New tree: many
   forged softwire identities each draw their own per-subscriber binding budget
   and together drain the shared public-IPv4 port pool, denying co-subscribers.
   Closed by SAVI (binds the identity, closing the forgery and the exhaustion
   together).

4. **T9 / T9b.** The rogue-AFTR hijack keeps its two variant trees (T9
   name-substituting, T9b name-preserving); the source dict had a duplicate `T9`
   key that silently dropped the first variant, now fixed. The orphan
   alarm-suppression tree is gone (folded into T10).

The paper's single camera-ready ad-tree figure is `submission/fig_adtree_t9.pdf`;
this bundle is the supplementary full set.

## Regeneration

`bash testbed/attack_trees/export.sh` rebuilds the whole bundle from the source
of truth (`results/adtool_trees/build_trees.py` -> `build_quadtool.py` ->
`.dot/.prism/.xml` + QuADTool-rendered figures), writing only inside
`testbed/attack_trees/`. The Boolean reachability check
(`python3 results/adtool_trees/build_quadtool.py --verify`) confirms each
credited defense makes its goal unreachable.
