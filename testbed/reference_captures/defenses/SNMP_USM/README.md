# SNMP_USM — SNMPv3 USM engineID pin (management plane)

Tree defence leaf **"SNMPv3 USM engineID pin"** — defends **T14, T15** (community-
authenticated SNMP write to suppress alarms / read to disclose subscriber state).

## Mechanism
SNMPv1/v2c authenticate with only a community string. SNMPv3 USM with engineID
pinning requires per-user authentication/privacy, so a community-only SET/GET is
rejected. (RFC 7870 §9 explicitly requires this — "SNMP versions prior to SNMPv3
did not include adequate security".)

## OFF vs ON (measured)
The attack SET targets the writable, unconstrained alarm threshold
`dsliteAFTRAlarmPortNumber = .1.3.6.1.2.1.240.1.3.1.8` (Integer32, default -1).

| | result |
|---|---|
| OFF (v2c community) | `OFF.pcap` + `OFF.readback.txt` — v2c SET accepted → threshold = **2147483647** (alarm disabled) |
| ON (SNMPv3 USM) | `ON.pcap` + `ON.readback.txt` — v2c SET **rejected** → OAM USM read = **-1** (default) |

> Note: `.240.1.3.1.6` (ConnectNumber) is range-clamped 60..90 and `.1`
> (B4AddrType) is read-only — neither is a valid USM probe; the writable
> unconstrained `.8` (PortNumber) is. T15's read disclosure (the NAT-bind subtree
> `.240.1.2.*`) is likewise blocked by USM access control.

## Reproduce
`bash testbed/defenses/verify_all.sh` (SNMP_USM block).

## Recognition rule
A community-authenticated SET of an alarm-threshold OID changes the value OFF and
is rejected ON (the OAM read stays at the legitimate default).
