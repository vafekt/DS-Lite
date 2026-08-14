# Independent cross-check of T11/T12 on the Snabb lwAFTR

This directory cross-validates the paper's Lightweight-4over6 generalization
(Section `sec:lw4o6`) against the **Snabb lwAFTR** (`snabb lwaftr`, version
2022.01.20), an independent RFC 7596 implementation in userspace Lua/C. It is
unrelated to the paper's own lw4o6 result, which is a same-base nftables/ip6tnl
emulation. Reproducing the outcomes here shows the isolation the binding gives
is a property of Lightweight 4over6, not of our emulation.

## What it demonstrates

The paper's claim is that Lightweight 4over6's mandatory per-subscriber
decapsulation binding (RFC 7596 Section 5.1) refuses exactly the two softwire
isolation breaks DS-Lite suffers, T11 (unprovisioned relay) and T12 (forged /
out-of-port-set identity), while forwarding a provisioned softwire. Running the
real Snabb data plane on three softwires confirms it:

| Case | softwire in | egress to Internet | drop counter |
|------|:---:|:---:|---|
| **baseline** provisioned softwire (in binding table) | 1 | **1** (decapsulated + forwarded as `178.79.150.233`) | none |
| **T11** source not in binding table | 1 | **0** | `drop-no-source-softwire-ipv6-packets = 1` |
| **T12** right IPv4 but out-of-port-set | 1 | **0** | `drop-no-source-softwire-ipv6-packets = 1` |

The `drop-no-source-softwire-ipv6-packets` counter is Snabb's own name for
"no provisioned softwire matches this decapsulated packet," i.e., the RFC 7596
Section 5.1 binding refusing the source. Evidence in `evidence/`:
`baseline_provisioned-v4out.pcap` holds the one forwarded packet;
`T11_unprovisioned-v4out.pcap` and `T12_out-of-portset-v4out.pcap` are empty;
`counters-*.lua` are the counter sets regenerated from the actual runs.

## Method

`snabb lwaftr check` is Snabb's own data-plane test harness. It pushes input
pcaps through the real lwAFTR data plane (the same code path as `snabb lwaftr
run`) and writes the output pcaps, so it exercises the genuine binding-table
validation without needing a NIC. The binding config (`no_icmp.conf`) and the
three test vectors under `inputs/` are Snabb's own test data; they model the
provisioned, unprovisioned (`-unbound`), and out-of-port-set
(`-bound-port-unbound`) cases directly.

## Reproducing

Requires Docker (privileged, for hugepages); no host root needed.

```sh
# build Snabb (userspace Lua/C; bundles LuaJIT)
docker run -d --name snabb-lw --privileged debian:bookworm-slim sleep infinity
docker exec snabb-lw bash -c 'apt-get update -qq && apt-get install -y -qq \
    build-essential git ca-certificates iproute2 iptables tcpdump procps'
docker exec snabb-lw bash -c 'cd /root && git clone --depth 1 https://github.com/snabbco/snabb.git && cd snabb && make -j$(nproc)'
docker exec snabb-lw bash -c 'echo 256 > /proc/sys/vm/nr_hugepages'    # Snabb needs hugepages

# run the three-case cross-check
docker cp snabb_lw_xcheck.sh snabb-lw:/root/
docker exec snabb-lw bash /root/snabb_lw_xcheck.sh
```

Expected: `baseline egress=1 drop=0 ; T11 egress=0 drop=1 ; T12 egress=0 drop=1`.

## Note

This is the Lightweight-4over6 analogue of `testbed/isc-xcheck/` (the ISC
reference AFTR cross-check for the DS-Lite relay). Together they place both ends
of the binding spectrum on an independent implementation: DS-Lite (no binding)
relays the unprovisioned softwire, Lightweight 4over6 (provisioned-table
binding) refuses it.

## Files

- `snabb_lw_xcheck.sh` -- the cross-check (three `snabb lwaftr check` runs).
- `inputs/` -- Snabb's binding config `no_icmp.conf` and the three softwire test
  vectors, plus `empty.pcap` and the reference `decap-ipv4.pcap`.
- `evidence/` -- output v4 pcaps (baseline holds 1 packet, T11/T12 empty) and the
  regenerated counter sets.
