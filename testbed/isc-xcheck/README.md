# Independent cross-check of T11 on the ISC reference AFTR

This directory cross-validates **T11 (unauthenticated softwire decapsulation /
relay)** against the **ISC AFTR**, the Address Family Transition Router reference
implementation for DS-Lite (RFC 6333). It is a userspace C daemon written by ISC
in 2009-2010, entirely independent of the paper's main testbed (which uses the
Linux kernel `ip6tnl` decapsulator plus `nftables` NAT and Python control-plane
daemons). Reproducing the relay here shows the attack is a property of DS-Lite,
not of our particular build.

## What it demonstrates

Driving an **unprovisioned** on-carrier host through the ISC AFTR, end to end:

1. **Acceptance by default.** The ISC AFTR ships with `use_autotunnel = 1`
   (`aftr.c`). A source inside the configured `acl6` prefix that has *no* static
   `nat` binding is served anyway: the daemon auto-creates the softwire tunnel
   and a dynamic NAT binding from the shared pool. Evidence: `aftr.log` shows
   `tunnel add 2001:0:0:5::2` and a `bucket ... 198.18.200.111 udp` for a source
   that appears in no `nat` line of `isc.conf`.
2. **Decapsulation + CGNAT.** The inner IPv4 is decapsulated and translated onto
   the shared public pool address `198.18.200.111`. Evidence: `tun0.pcap` shows
   the inbound `IP6 2001:0:0:5::2 > 2001::1: IP 10.0.5.2 > 203.0.113.9` becoming
   the outbound `IP 198.18.200.111.<port> > 203.0.113.9`.
3. **WAN egress as the shared public address.** The relayed flow leaves the
   concentrator and the external server receives it, sourced from the shared
   public IPv4 `203.0.113.1`. Evidence: `wan.pcap`, captured on the *server's*
   interface, shows `IP 203.0.113.1.<port> > 203.0.113.9.9999` and
   `server_rx.txt` holds the five `RELAY-PKT-*-from-unprovisioned-B4` payloads.

This is the "open one-way relay laundered through the carrier" of T11, egressing
as the public IPv4 the real subscribers share.

## Root cause of the earlier incomplete egress

An earlier informal run of this cross-check saw steps 1-2 (decapsulation and
translation onto the pool) but not step 3 (WAN egress). The two scenarios here
isolate why:

| scenario | `ip_forward` | decap + CGNAT on tun0 | server receives (egress) |
|----------|:---:|:---:|:---:|
| `evidence/fwd1/` | 1 | yes (5) | **yes (5)** |
| `evidence/fwd0/` | 0 | yes (5) | no (0) |

With kernel forwarding off, the ISC AFTR still decapsulates and translates the
unprovisioned softwire onto the shared pool (`fwd0/tun0.pcap`), but the packet
never leaves the box (`fwd0/wan.pcap` is empty) -- exactly the earlier
translated-but-not-egressed state. Turning forwarding on, together with the
pool-to-public egress SNAT ISC documents in `README` section 3.1 and its own
`aftr-shareone-script`, completes the relay. **The stall was host forwarding and
NAT-pool configuration, not any check inside the AFTR.**

## Reproducing

Requires Docker (privileged, for `tun`/`netns`/`iptables`); no host root needed.

```sh
# 1. fetch + build the ISC AFTR (userspace C, 2010)
curl -O https://downloads.isc.org/isc/aftr/aftr-1.0.1.tar.gz
tar xzf aftr-1.0.1.tar.gz && cd aftr-1.0.1
./configure
# 2010 code uses GNU89 inline semantics; modern gcc needs -fgnu89-inline
make CFLAGS="-g -O2 -fgnu89-inline"      # -> ./aftr

# 2. run the relay cross-check in a clean, independent container
docker run -d --name isc-aftr-xcheck --privileged -v "$PWD/..":/work debian:bookworm-slim sleep infinity
docker exec isc-aftr-xcheck bash -c 'apt-get update -qq && apt-get install -y -qq \
    build-essential iproute2 iptables tcpdump netcat-openbsd procps'
# (build /build/aftr inside the container the same way, then:)
docker exec -e FORWARD=1 isc-aftr-xcheck bash /work/isc_relay_xcheck.sh   # full egress
docker exec -e FORWARD=0 isc-aftr-xcheck bash /work/isc_relay_xcheck.sh   # diagnosis contrast
```

`isc_relay_xcheck.sh` builds the three-namespace topology (unprovisioned B4 ->
ISC AFTR + tun0 -> external server), starts the daemon with `isc.conf`
(`acl6 2001::/48`, pool `198.18.200.111`, and no `nat` line for the attacker
source), fires five relay packets, and collects the evidence above.

### Note on the softwire encapsulation

A conformant DS-Lite B4 (RFC 6333) sends plain IPv4-in-IPv6 (next-header 4).
Linux's `ip6tnl` by default adds an RFC 2473 tunnel-encapsulation-limit
destination option, which the 2010 ISC decapsulator rejects as `DR_BAD6`
(`header6 (decap)` in the log). The script therefore creates the B4 softwire with
`encaplimit none`, matching a conformant B4. This is a property of the Linux
tunnel driver, not of the AFTR or the attack.

## Files

- `isc_relay_xcheck.sh` -- the cross-check (topology, launch, relay, evidence).
- `evidence/fwd1/` -- full relay: `aftr.log`, `tun0.pcap`, `wan.pcap`,
  `server_rx.txt`, `isc.conf`, `isc-script`, `run.log`.
- `evidence/fwd0/` -- diagnosis contrast (forwarding off): same file set.
