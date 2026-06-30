# ESP_AEAD — AEAD ESP on the softwire (tunnel confidentiality)

Tree defence leaf **"AEAD ESP on the softwire"** — defends **T3, T4** (on-path
read/inject of the cleartext softwire).

## Mechanism
The DS-Lite softwire (IPv4-in-IPv6, proto 4) carries the inner IPv4 in cleartext.
Wrapping it in AEAD ESP (encrypt-then-MAC) makes the inner datagram unreadable and
unforgeable to an on-path attacker — only ESP ciphertext is on the wire.

## OFF vs ON (measured)
| | result |
|---|---|
| OFF (cleartext softwire) | `OFF.pcap` — **20** cleartext HTTP markers (`GET /`, `HTTP/1`) recoverable |
| ON (ESP) | `ON.pcap` — **0** cleartext markers; only ESP ciphertext |

Capture point: B4-1 `eth-isp`, filter `ip6 proto 4 or esp`. OFF the victim's inner
HTTP is decodable; ON the same flow is opaque ESP.

## Reproduce
`bash testbed/defenses/verify_all.sh` (ESP_AEAD block).

## Recognition rule
Inner IPv4/HTTP is decodable from the proto-4 frames OFF; ON the carrier shows
only ESP with no decodable inner payload.
