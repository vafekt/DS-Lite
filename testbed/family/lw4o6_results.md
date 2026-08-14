# lw4o6 (RFC 7596) reproduction — RESULTS (2026-08-12)

## What was built
An RFC 7596-conformant Lightweight-4over6 stack in fresh `lw*` namespaces parallel to the
DS-Lite testbed (same emulation approach/honesty bar as the paper's DS-Lite AFTR: nftables +
ip6tnl). Two lwB4s each doing EDGE NAT into an ASSIGNED disjoint port-set on a shared IPv4;
an lwAFTR holding a per-lwB4 BINDING (point-to-point softwire, NO catch-all ip6tnl0) and
validating the decapsulated inner source addr+port against the binding (RFC 7596 §5.1).
Scripts: scratchpad/lw4o6_setup.sh, lw4o6_attacks.sh.

## Baseline (legit traffic works end-to-end)
- lwcl1 -> server: PING ok, HTTP=200 (edge SNAT into 1024-2047 -> softwire -> binding-validated -> WAN).

## Attack results (the isolation breaks DS-Lite suffers, run identically here)
| Attack | DS-Lite (paper) | lw4o6 (this run) | Mechanism that blocks it |
|--------|------------------|-------------------|--------------------------|
| **T11** unprovisioned relay | AFTR relays it out as shared IPv4 (catch-all + no binding) | **BLOCKED**: ingress=20 packets reached lwAFTR, **egress=0**, catch-all ip6tnl0 rx=0 | no catch-all + no binding for the unprovisioned source |
| **T12(a)** forge 32 identities | each forged id gets its own budget -> drains shared pool | **BLOCKED**: ingress=960 reached, **egress=0** | forged sources have no binding -> not decapsulated/forwarded |
| **T12(b)** spoof real id ::101, out-of-set ports | n/a (DS-Lite has no port-set/binding) | **BLOCKED**: **40/40 dropped** by inner-source binding validation | RFC 7596 §5.1 source+port binding |
| **T1** flood isolation | holds via per-subscriber cap (RFC 6888) | **holds structurally**: disjoint port-sets lwB4-1=1024-2047, lwB4-2=2048-3071 | fixed A+P port-set partition |

## The point (for the paper)
lw4o6's decapsulation-time binding is MANDATORY (RFC 7596 §5.1) because lw4o6 is STATEFUL
(each lwB4 provisioned with a binding). DS-Lite is STATELESS (no binding) and OMITS it ->
T11/T12. This converts the paper's previously "analytical, not empirically tested"
generalization into a DEMONSTRATED cross-technology result, and gives DECAP-BIND its honest
identity: **the binding lw4o6 mandates by design, backported to stateless DS-Lite and verified.**

## Honesty / limits (state in the paper)
- The lwAFTR is an RFC 7596-conformant EMULATION (nftables/ip6tnl), same bar as the DS-Lite
  AFTR emulation — NOT an independent implementation. Describe it as such.
- Independent cross-check on a real lw4o6 impl (Snabb lwAFTR) was NOT attempted (DPDK/hugepages
  finicky); note as possible future cross-validation, analogous to the ISC AFTR check for DS-Lite.
- Magnitudes (port-set sizes, packet counts) are build-specific; the RESULT is the binding
  blocks the breaks by design, not any particular number.
- T1 on lw4o6 is structural (disjoint port-sets), argued not flood-tested (the flood test hit a
  single-thread-server backlog artifact; do NOT report a flood-based lw4o6 isolation number).
