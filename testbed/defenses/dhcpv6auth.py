#!/usr/bin/python3
# dhcpv6auth.py — DHCPv6Auth (Ed25519-signed DHCPv6), the mechanism proposed by
#   Albalawi & Aljuhani, "DHCPv6Auth: a mechanism to improve DHCPv6
#   authentication and privacy", Sadhana 45:33 (2020), §4.3–4.5.
#
# This is the ARTICLE's mechanism, not the RFC-7610 layer-2 filter. The paper:
#   - the DHCPv6 server holds an Ed25519 key pair (§4.1);
#   - it appends a Signature Authentication (SA) option to every server message,
#     carrying Protocol=4, Algorithm=4 (Ed25519), a Replay-Detection (RD)
#     monotonic timestamp, and the Ed25519 signature over the whole message with
#     the signature field zeroed (§4.3, §4.4);
#   - the client verifies the SA option with the server public key and rejects
#     any server message that is unsigned or fails verification, defeating the
#     rogue DHCPv6 server (§4.5); RD defeats replay.
#   - public key distribution is via the RA DPK option in the paper; the paper
#     also allows manual deployment ("the generated public key would then be
#     manually deployed"). We pin it in a provisioning file (out-of-band), which
#     is the manual-deployment variant.
#
# Adapted to DS-Lite: the signed/verified server message carries Option 64
# (AFTR-Name, RFC 6334) and Option 23 (DNS). A rogue DHCPv6 server (the T12/T13
# attack, testbed/attack_tools/infra/dhcpv6_hijack.py) cannot produce a valid SA
# option, so the verifying B4 never adopts the forged AFTR.
#
# Subcommands:
#   keygen  --out <dir>                         generate the server key pair
#   server  --iface eth-isp --key <dir> ...     legit signing DHCPv6 server
#   client  --iface eth-isp [--insecure] ...    verifying B4 acquisition client
#
# --insecure on the client reproduces the unauthenticated baseline (accept the
# first AFTR-Name seen, like stock dhclient) so the same tool gives the off/on
# oracle holding everything else constant.
import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import ed25519_pure as ed  # noqa: E402

ALL_DHCP = "ff02::1:2"           # All_DHCP_Relay_Agents_and_Servers (RFC 8415)
SRV_PORT = 547
CLI_PORT = 546

# DHCPv6 message types
SOLICIT, ADVERTISE, REQUEST, REPLY = 1, 2, 3, 7
# Options
OPT_CLIENTID, OPT_SERVERID, OPT_IA_NA, OPT_AUTH = 1, 2, 3, 11
OPT_ORO, OPT_PREF, OPT_DNS, OPT_AFTR = 6, 7, 23, 64
# SA option (DHCPv6Auth §4.3): proto=4, algo=4 (Ed25519), RDM=0
SA_PROTO, SA_ALGO, SA_RDM = 4, 4, 0
SIG_LEN = 64


# ── option codec ───────────────────────────────────────────────────────────
def opt(code, value):
    return struct.pack("!HH", code, len(value)) + value


def parse_opts(buf):
    """Return list of (code, value, absolute_offset_of_value)."""
    out, off = [], 0
    while off + 4 <= len(buf):
        code, ln = struct.unpack("!HH", buf[off:off + 4])
        val = buf[off + 4:off + 4 + ln]
        out.append((code, val, off + 4))
        off += 4 + ln
    return out


def encode_fqdn(fqdn):
    if not fqdn.endswith("."):
        fqdn += "."
    out = b""
    for label in fqdn.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def decode_fqdn(wire):
    labels, off = [], 0
    while off < len(wire):
        ln = wire[off]
        if ln == 0:
            break
        labels.append(wire[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels) + "."


# ── SA option: build / locate / verify (DHCPv6Auth §4.3-4.5) ────────────────
def build_sa_option(sig=b"\x00" * SIG_LEN, rd=None):
    if rd is None:
        rd = int(time.time())
    val = struct.pack("!BBB", SA_PROTO, SA_ALGO, SA_RDM) + struct.pack("!Q", rd) + sig
    return opt(OPT_AUTH, val)


def sign_message(msg, priv):
    """Append a zeroed SA option, sign the whole message, patch the sig in.
    (§4.4: signature field zeroed before signing, then inserted.)"""
    rd = int(time.time())
    msg_zeroed = msg + build_sa_option(b"\x00" * SIG_LEN, rd)
    sig = ed.sign(priv, msg_zeroed)
    # locate the sig field (last 64 bytes) and patch it
    return msg_zeroed[:-SIG_LEN] + sig


def verify_message(msg, pub, last_rd):
    """Return (ok, rd, reason). Verifies the trailing SA option."""
    # the SA option must be the final option and carry a 75-byte value
    opts = parse_opts(msg[4:])
    sa = [(c, v, o) for (c, v, o) in opts if c == OPT_AUTH]
    if not sa:
        return False, None, "no SA option (unsigned server message)"
    code, val, voff_rel = sa[-1]
    if len(val) != 3 + 8 + SIG_LEN:
        return False, None, "malformed SA option"
    proto, algo, rdm = struct.unpack("!BBB", val[:3])
    if proto != SA_PROTO or algo != SA_ALGO:
        return False, None, "unsupported auth proto/algo"
    rd = struct.unpack("!Q", val[3:11])[0]
    if last_rd is not None and rd <= last_rd:
        return False, rd, "replay (RD not advancing)"
    sig = val[11:]
    # rebuild the signed-over bytes: whole msg with sig field zeroed
    voff = 4 + voff_rel               # absolute offset of SA value in msg
    sigoff = voff + 11                # absolute offset of signature field
    zeroed = msg[:sigoff] + b"\x00" * SIG_LEN + msg[sigoff + SIG_LEN:]
    if not ed.verify(pub, zeroed, sig):
        return False, rd, "bad Ed25519 signature"
    return True, rd, "ok"


def get_aftr_dns(msg):
    aftr, dns = None, []
    for code, val, _ in parse_opts(msg[4:]):
        if code == OPT_AFTR and val:
            aftr = decode_fqdn(val)
        elif code == OPT_DNS:
            for i in range(0, len(val), 16):
                dns.append(socket.inet_ntop(socket.AF_INET6, val[i:i + 16]))
    return aftr, dns


# ── socket helpers ──────────────────────────────────────────────────────────
def open_socket(iface, port, join_multicast=False):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, 25, (iface + "\0").encode())  # SO_BINDTODEVICE
    s.bind(("::", port))
    ifidx = socket.if_nametoindex(iface)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                 struct.pack("I", ifidx))
    if join_multicast:
        grp = socket.inet_pton(socket.AF_INET6, ALL_DHCP)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                     grp + struct.pack("I", ifidx))
    return s, ifidx


def server_duid():
    return b"\x00\x03\x00\x01" + b"\xaa\xbb\xcc\xdd\xee\xff"  # DUID-LL


# ── server ──────────────────────────────────────────────────────────────────
def run_server(a):
    priv = open(os.path.join(a.key, "dhcpv6_ed25519.sec"), "rb").read()
    s, ifidx = open_socket(a.iface, SRV_PORT, join_multicast=True)
    sduid = server_duid()
    print(f"[dhcpv6auth-server] signing DHCPv6 on {a.iface}, "
          f"aftr={a.aftr} dns={a.dns} (Ed25519 SA option)", flush=True)
    while True:
        data, src = s.recvfrom(4096)
        if len(data) < 4:
            continue
        mtype, txid = data[0], data[1:4]
        if mtype not in (SOLICIT, REQUEST):
            continue
        cduid = b""
        ia_na = None
        for code, val, _ in parse_opts(data[4:]):
            if code == OPT_CLIENTID:
                cduid = val
            elif code == OPT_IA_NA:
                ia_na = val
        resp_type = ADVERTISE if mtype == SOLICIT else REPLY
        msg = struct.pack("!B3s", resp_type, txid)
        msg += opt(OPT_CLIENTID, cduid)
        msg += opt(OPT_SERVERID, sduid)
        if ia_na is not None:
            # echo IAID, grant a stable address from the pool
            iaid = ia_na[:4]
            addr = socket.inet_pton(socket.AF_INET6, a.offer)
            iaaddr = opt(5, addr + struct.pack("!II", 600, 1200))
            msg += opt(OPT_IA_NA, iaid + struct.pack("!II", 100, 200) + iaaddr)
        for d in a.dns.split(","):
            msg += opt(OPT_DNS, socket.inet_pton(socket.AF_INET6, d))
        msg += opt(OPT_AFTR, encode_fqdn(a.aftr))
        msg += opt(OPT_PREF, b"\xff")
        signed = sign_message(msg, priv)
        s.sendto(signed, (src[0], CLI_PORT, 0, ifidx))


# ── client (verifying B4 acquisition) ───────────────────────────────────────
def client_duid():
    return b"\x00\x03\x00\x01" + b"\x02\x00\x00\x00\x00\x01"


def run_client(a):
    pub = None
    if not a.insecure:
        pub = open(os.path.join(a.key, "dhcpv6_ed25519.pub"), "rb").read()
    s, ifidx = open_socket(a.iface, CLI_PORT, join_multicast=False)
    s.settimeout(0.4)
    cduid = client_duid()
    txid = os.urandom(3)
    iaid = b"\x00\x00\x00\x01"

    def send(mtype):
        msg = struct.pack("!B3s", mtype, txid)
        msg += opt(OPT_CLIENTID, cduid)
        msg += opt(OPT_IA_NA, iaid + struct.pack("!II", 0, 0))
        msg += opt(OPT_ORO, struct.pack("!HH", OPT_DNS, OPT_AFTR))
        s.sendto(msg, (ALL_DHCP, SRV_PORT, 0, ifidx))

    mode = "INSECURE (accept-first, unauthenticated baseline)" if a.insecure \
        else "VERIFYING (Ed25519 SA option required)"
    print(f"[dhcpv6auth-client] {a.iface} mode={mode}", flush=True)
    send(SOLICIT)
    deadline = time.time() + a.wait
    chosen = None           # (msg, rd)
    rejected = 0
    last_rd = None
    while time.time() < deadline:
        try:
            data, src = s.recvfrom(4096)
        except socket.timeout:
            continue
        if len(data) < 4 or data[0] != ADVERTISE:
            continue
        aftr, dns = get_aftr_dns(data)
        if aftr is None:
            continue
        if a.insecure:
            chosen = (data, None)
            print(f"[client] accepted (insecure) AFTR={aftr} from {src[0]}",
                  flush=True)
            break
        ok, rd, reason = verify_message(data, pub, last_rd)
        if ok:
            chosen = (data, rd)
            last_rd = rd
            print(f"[client] SA verified OK -> AFTR={aftr} from {src[0]}",
                  flush=True)
            break
        else:
            rejected += 1
            print(f"[client] REJECTED ADVERTISE from {src[0]}: {reason} "
                  f"(claimed AFTR={aftr})", flush=True)
    if chosen is None:
        print(f"[client] no acceptable ADVERTISE (rejected={rejected}); "
              f"keeping previous AFTR-Name", flush=True)
        return 2
    aftr, dns = get_aftr_dns(chosen[0])
    if a.aftr_file:
        with open(a.aftr_file, "w") as f:
            f.write(aftr + "\n")
    print(f"[client] RESULT AFTR-Name={aftr} (rejected {rejected} rogue msg)",
          flush=True)
    return 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    pk = sub.add_parser("keygen")
    pk.add_argument("--out", required=True)
    ps = sub.add_parser("server")
    ps.add_argument("--iface", required=True)
    ps.add_argument("--key", required=True)
    ps.add_argument("--aftr", default="aftr.dslite.example.com.")
    ps.add_argument("--dns", default="2001:db8:cafe::2")
    ps.add_argument("--offer", default="2001:db8:cafe::abcd")
    pc = sub.add_parser("client")
    pc.add_argument("--iface", required=True)
    pc.add_argument("--key", required=True)
    pc.add_argument("--insecure", action="store_true")
    pc.add_argument("--wait", type=float, default=3.0)
    pc.add_argument("--aftr-file", default="/var/run/ds-lite-aftr-name")
    a = p.parse_args()
    if a.cmd == "keygen":
        os.makedirs(a.out, exist_ok=True)
        sk, pubk = ed.keygen()
        open(os.path.join(a.out, "dhcpv6_ed25519.sec"), "wb").write(sk)
        open(os.path.join(a.out, "dhcpv6_ed25519.pub"), "wb").write(pubk)
        os.chmod(os.path.join(a.out, "dhcpv6_ed25519.sec"), 0o600)
        print(f"keypair written to {a.out} (pub={pubk.hex()[:16]}...)")
    elif a.cmd == "server":
        run_server(a)
    elif a.cmd == "client":
        sys.exit(run_client(a))


if __name__ == "__main__":
    main()
