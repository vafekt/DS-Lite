# IPv4aaS family reproduction — the softwire binding spectrum (paper §9.2)

These standalone scripts reproduce the paper's cross-technology result: the
softwire's resistance to the relay (T11) and identity-multiplication (T12)
attacks follows the per-subscriber binding the concentrator holds when it
decapsulates. They run natively on the host with network namespaces + nftables
+ ip6tnl (the same base as the DS-Lite AFTR emulation), not inside the Docker
lab, so run them as root on the host.

| Technology | Concentrator binding | Relay / identity outcome |
|---|---|---|
| DS-Lite     | none (stateless)                              | succeed (nothing screens the source) |
| MAP-E       | algorithmic, RFC 7597 §8.1 (consistency only) | arbitrary relay dropped, rule-consistent forgery accepted |
| Lightweight 4over6 | provisioned table, RFC 7596 §5.1 + RFC 8658 (AAA-synced) | refused by design |

## Run

```
sudo ./lw4o6_setup.sh      # build the Lightweight 4over6 emulation (lwB4 + lwAFTR)
sudo ./lw4o6_attacks.sh    # run the isolation attacks against it (T11/T12 refused)
sudo ./mape_setup.sh       # build the MAP-E emulation (CE + BR)
sudo ./mape.sh             # BR forward-path validation (arbitrary vs rule-consistent)
```

`lw4o6_results.md` records the measured outcomes. These emulations are
specification-conforming builds on the same base as the DS-Lite AFTR; an
independent implementation (e.g. the Snabb lwAFTR) would strengthen the
cross-check, as the ISC AFTR does for the DS-Lite data path.
