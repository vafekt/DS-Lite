# DHCPV6_AUTH — Ed25519-signed DHCPv6 (rogue AFTR provisioning)

Tree defence leaf **"Ed25519-signed DHCPv6"** — defends **T12, T13** (rogue DHCPv6
server substituting the AFTR name / poisoning its resolution to redirect the
softwire to the attacker).

## Mechanism
The B4 only accepts a DHCPv6 AFTR/DNS option carrying a valid Ed25519 signature
from the provisioning key. An unsigned (or wrongly-signed) rogue advertise is
rejected, so the B4 keeps the legitimate AFTR/DNS.

## OFF vs ON (measured)
| | result |
|---|---|
| OFF (unsigned / `--insecure`) | `OFF.pcap` + `OFF.result.txt` — B4 adopts `AFTR=aftr-evil.attacker.example.` (the rogue) |
| ON (signature verified) | `ON.pcap` + `ON.result.txt` — B4 keeps `AFTR=aftr.dslite.example.com.` (rogue rejected) |

Capture point: attacker `eth-isp`, `udp port 546 or 547`. The rogue DHCPv6 hijack
runs in both cases; OFF the B4 accepts it, ON the signed-client rejects it.

## Reproduce
`bash testbed/defenses/verify_all.sh` (DHCPV6_AUTH block).

## Recognition rule
The B4's learned AFTR name/address is the attacker's OFF and the legitimate one
ON, despite an identical rogue advertise on the wire.
