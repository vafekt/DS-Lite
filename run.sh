#!/bin/bash
# Build and run the DS-Lite lab inside Docker.
# Opens a terminal window for each network device.
# Press Ctrl+C in this terminal to tear everything down.

# NOTE: `set -e` is intentionally NOT used. The script is interactive
# and contains many shell builtins (read, [, &&, ||) whose non-zero
# return values are expected control flow, not errors. We check
# critical commands explicitly.

cd "$(dirname "$0")"

# ── Output / logging ────────────────────────────────────────────────
# Clean, consistently-indented output by default; pass --debug (or set
# DS_LITE_DEBUG=1) to see the verbose build/setup/diagnostic chatter.
DS_DEBUG="${DS_LITE_DEBUG:-}"
for _a in "$@"; do case "$_a" in --debug|-d) DS_DEBUG=1 ;; esac; done
if [ -t 1 ]; then
    C_RST=$'\e[0m'; C_DIM=$'\e[2m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
    C_RED=$'\e[31m'; C_CYN=$'\e[36m'; C_BLD=$'\e[1m'
else
    C_RST=""; C_DIM=""; C_GRN=""; C_YEL=""; C_RED=""; C_CYN=""; C_BLD=""
fi
hdr()  { printf '\n%s%s%s\n' "$C_BLD$C_CYN" "$*" "$C_RST"; }   # section header
say()  { printf '  %s\n' "$*"; }                               # normal line
kv()   { printf '  %-18s %s\n' "$1" "$2"; }                    # aligned key/value
ok()   { printf '  %s✓%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_YEL" "$C_RST" "$*"; }
err()  { printf '  %s✗%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
dbg()  { [ -n "$DS_DEBUG" ] && printf '  %s· %s%s\n' "$C_DIM" "$*" "$C_RST" >&2 || true; }

IMAGE_NAME="ds-lite-lab"
CONTAINER_NAME="ds-lite-lab"
PCAP_DIR="$(pwd)/pcaps"
CORPUS_FILE="$(pwd)/testbed/attack_corpus.txt"   # menu source of truth
LAUNCH_LOG="/tmp/ds-lite-launch.log"
# When the prompt_toolkit command-palette front-end is available, the upfront
# Wireshark / device gauntlet is skipped — those are chosen on demand from the
# palette instead. Set DS_LITE_NO_PALETTE=1 to force the legacy numbered menus.
_palette_ok() { [ -z "$DS_LITE_NO_PALETTE" ] && python3 -c 'import prompt_toolkit' 2>/dev/null \
                && [ -f "$(pwd)/testbed/scripts/ds_menu.py" ]; }
mkdir -p "$PCAP_DIR"
: > "$LAUNCH_LOG"
dbg "run.sh started $(date -u +%FT%TZ) — diagnostics in $LAUNCH_LOG"

# ── X11 / sudo guard ────────────────────────────────────────────────
# When invoked via `sudo`, DISPLAY and XAUTHORITY are normally preserved
# in env_keep, but on some sudoers configurations they are not.
if [ -z "$DISPLAY" ]; then
    warn "DISPLAY is not set — device terminal windows will not open."
    dbg "via sudo? re-run: sudo --preserve-env=DISPLAY,XAUTHORITY ./run.sh"
    dbg "or add: Defaults env_keep += \"DISPLAY XAUTHORITY\"  to /etc/sudoers"
fi
if [ -n "$SUDO_USER" ] && [ -z "$XAUTHORITY" ]; then
    XAUTHORITY="/home/$SUDO_USER/.Xauthority"
    [ -f "$XAUTHORITY" ] && export XAUTHORITY
    dbg "Recovered XAUTHORITY=$XAUTHORITY"
fi

# ── Detect terminal emulator ────────────────────────────────────────
detect_terminal() {
    for t in qterminal xfce4-terminal gnome-terminal konsole xterm; do
        if command -v "$t" &>/dev/null; then echo "$t"; return; fi
    done
}
TERM_EMU=$(detect_terminal)
if [ -n "$TERM_EMU" ]; then
    dbg "terminal emulator: $TERM_EMU"
else
    warn "no graphical terminal found — device shells/captures are unavailable."
fi

# Background-launch a terminal command line, capturing stderr to the
# launch log so silent failures (no DISPLAY, missing Qt plugin, etc.)
# are visible after-the-fact.
_spawn_terminal() {
    local title="$1"; shift
    {
        echo ""
        echo "[$(date -u +%FT%TZ)] launching: $*"
    } >> "$LAUNCH_LOG"
    # IMPORTANT: redirect stdin from /dev/null. Otherwise the spawned
    # graphical terminal inherits the run.sh controlling-tty stdin; on
    # some compositors it briefly reads /dev/tty during X startup and
    # swallows the user's keystrokes, leaving the attack-menu prompt
    # in run.sh unresponsive.
    setsid "$@" </dev/null >>"$LAUNCH_LOG" 2>&1 &
    local pid=$!
    TERM_PIDS+=("$pid")
    # Give the X server a beat before launching the next one so all
    # the windows come up reliably (some compositors race when many
    # processes call XCreateWindow simultaneously).
    sleep 0.25
}

open_terminal() {
    local title="$1" ns="$2"
    local wrapper="/tmp/ds-lite-term-${ns}.sh"
    cat > "$wrapper" <<WRAPPER
#!/bin/bash
echo -ne "\\033]0;DS-Lite: $title\\007"
docker exec -it -w / -e PS1='\[\e[1;32m\]$title\[\e[0m\]@ds-lite:\w\$ ' $CONTAINER_NAME ip netns exec $ns bash --norc --noprofile
rc=\$?
if [ \$rc -ne 0 ]; then
    echo ""
    echo "[wrapper] docker exec exited with rc=\$rc (container down? namespace gone?)"
    echo "[wrapper] Press Enter to close."
    read
fi
WRAPPER
    chmod +x "$wrapper"

    case "$TERM_EMU" in
        qterminal)      _spawn_terminal "$title" qterminal -e "$wrapper" ;;
        xfce4-terminal) _spawn_terminal "$title" xfce4-terminal --title="DS-Lite: $title" --hold -e "$wrapper" ;;
        gnome-terminal) _spawn_terminal "$title" gnome-terminal --title="DS-Lite: $title" -- "$wrapper" ;;
        konsole)        _spawn_terminal "$title" konsole -p tabtitle="DS-Lite: $title" --hold -e "$wrapper" ;;
        xterm)          _spawn_terminal "$title" xterm -hold -title "DS-Lite: $title" -e "$wrapper" ;;
        *)              warn "No terminal emulator for $title"; return 1 ;;
    esac
}

open_monitor_terminal() {
    local title="$1" ns="$2" script="$3"
    local wrapper="/tmp/ds-lite-term-monitor-${ns}.sh"
    cat > "$wrapper" <<WRAPPER
#!/bin/bash
echo -ne "\\033]0;DS-Lite: $title\\007"
docker exec -it -w / $CONTAINER_NAME ip netns exec $ns bash $script
rc=\$?
if [ \$rc -ne 0 ]; then
    echo ""
    echo "[wrapper] docker exec exited with rc=\$rc"
    echo "[wrapper] Press Enter to close."
    read
fi
WRAPPER
    chmod +x "$wrapper"

    case "$TERM_EMU" in
        qterminal)      _spawn_terminal "$title" qterminal -e "$wrapper" ;;
        xfce4-terminal) _spawn_terminal "$title" xfce4-terminal --title="DS-Lite: $title" --hold -e "$wrapper" ;;
        gnome-terminal) _spawn_terminal "$title" gnome-terminal --title="DS-Lite: $title" -- "$wrapper" ;;
        konsole)        _spawn_terminal "$title" konsole -p tabtitle="DS-Lite: $title" --hold -e "$wrapper" ;;
        xterm)          _spawn_terminal "$title" xterm -hold -title "DS-Lite: $title" -e "$wrapper" ;;
        *)              warn "No terminal emulator for $title"; return 1 ;;
    esac
}

open_cmd_terminal() {
    local title="$1" ns="$2" cmd="$3"
    local id="$$-$RANDOM"
    local host_script="/tmp/ds-lite-cmd-${id}.sh"
    local cont_script="/tmp/cmd-${id}.sh"
    local wrapper="/tmp/ds-lite-wrap-${id}.sh"

    # Write command script (runs inside container namespace)
    {
        echo "#!/bin/bash"
        echo "$cmd"
        echo 'rc=$?'
        echo ""
        echo 'echo ""'
        echo 'echo "[Done, exit=$rc] Press Enter to close."'
        echo 'read'
    } > "$host_script"
    chmod +x "$host_script"
    if ! docker cp "$host_script" "${CONTAINER_NAME}:${cont_script}" 2>>"$LAUNCH_LOG"; then
        warn "docker cp failed for $title (container down?)" >&2
        return 1
    fi

    cat > "$wrapper" <<WEOF
#!/bin/bash
echo -ne "\\033]0;DS-Lite: $title\\007"
docker exec -it -w / $CONTAINER_NAME ip netns exec $ns bash $cont_script
WEOF
    chmod +x "$wrapper"

    case "$TERM_EMU" in
        qterminal)      _spawn_terminal "$title" qterminal -e "$wrapper" ;;
        xfce4-terminal) _spawn_terminal "$title" xfce4-terminal --title="DS-Lite: $title" --hold -e "$wrapper" ;;
        gnome-terminal) _spawn_terminal "$title" gnome-terminal --title="DS-Lite: $title" -- "$wrapper" ;;
        konsole)        _spawn_terminal "$title" konsole -p tabtitle="DS-Lite: $title" --hold -e "$wrapper" ;;
        xterm)          _spawn_terminal "$title" xterm -hold -title "DS-Lite: $title" -e "$wrapper" ;;
        *)              warn "No terminal emulator for $title"; return 1 ;;
    esac
}

# Open Wireshark live on a concrete interface inside a device namespace. The
# interface lives in a container netns, so we stream it out with tcpdump (-w -)
# and feed the live pcap into the host Wireshark (-k -i -). Headless fallback:
# capture to the bind-mounted pcaps directory instead.
start_wireshark() {  # <ns> <iface>
    local ns="$1" iface="$2"
    if [ -n "${DISPLAY:-}" ] && command -v wireshark >/dev/null 2>&1; then
        kv "Live capture:" "$ns / $iface → Wireshark"
        setsid sh -c \
          "docker exec '$CONTAINER_NAME' ip netns exec '$ns' tcpdump -i '$iface' -U -s0 -w - 2>/dev/null | wireshark -k -i - " \
          </dev/null >>"$LAUNCH_LOG" 2>&1 &
        TERM_PIDS+=("$!")
        ok "Wireshark opening live on $ns/$iface"
    else
        local ts cfile; ts=$(date +%H%M%S); cfile="/testbed/pcaps/${ns}-${iface}-${ts}.pcap"
        warn "no DISPLAY/Wireshark — capturing to ./testbed/pcaps/${ns}-${iface}-${ts}.pcap"
        open_cmd_terminal "Capture-$ns" "$ns" "tcpdump -ni '$iface' -U -w '$cfile'"
    fi
}

# Print a placement-aware reference for attacking by hand from the device shells.
_print_manual_cheatsheet() {
    local p="${ATTACKER_PLACEMENT:-none}"
    hdr "Manual attack reference   (attacker: $p)"
    say "Targets / ports:"
    kv "  AFTR carrier:"  "2001:db8:cafe::10   softwire = IPv4-in-IPv6 (proto 4), PCP udp/5351"
    kv "  AFTR OAM:"      "10.99.0.1           SNMP udp/161 (community 'public' until hardened)"
    kv "  Resolver:"      "2001:db8:cafe::2    DNS udp/53"
    kv "  B4-1 / host:"   "2001:db8:cafe::b41  inner 10.0.1.100   (DHCPv6 546/547)"
    kv "  B4-2 / host:"   "2001:db8:cafe::b42  inner 10.0.2.100"
    kv "  Public server:" "198.51.100.2        shared NAT pool 192.0.2.0/24"
    say "Tools in each shell: scapy, hping3, nmap, atk6-* (thc-ipv6), nc, dig, snmpget/snmpwalk, tcpdump."
    say "Reference implementations to read then craft by hand: /testbed/attack_tools/"
    case "$p" in
      isp)      say "On the carrier (src ::13a): forge 4in6 to ::10, sniff the softwire, spoof DHCPv6/PCP ANNOUNCE, inject DNS." ;;
      b4-1)     say "On B4-1 LAN (10.0.1.x): exhaust NAT toward 198.51.100.2; drive PCP through the proxy at 10.0.1.1." ;;
      b4-2)     say "On B4-2 LAN (10.0.2.x): the second subscriber's vantage (co-subscriber attacks)." ;;
      mgmt)     say "On OAM (10.99.0.50): e.g. snmpwalk -v2c -c public 10.99.0.1" ;;
      internet) say "On the public Internet (198.51.100.50): reach the shared public address / service." ;;
      none)     warn "No attacker placed — set a placement to get an attack console." ;;
    esac
}

# ── Cleanup ─────────────────────────────────────────────────────────
TERM_PIDS=()
TERM_FIFOS=()
cleanup() {
    echo ""
    for pid in "${TERM_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    for f in "${TERM_FIFOS[@]}"; do rm -f "$f" 2>/dev/null || true; done
    # NOTE: the canonical attack-defence trees in testbed/attack_trees/ are the
    # QuADTool export (regenerated via results/adtool_trees/render_with_quadtool.sh
    # + testbed/attack_trees/export.sh — see testbed/attack_trees/README.md). They
    # are NOT auto-regenerated on exit: doing so used the legacy SVG renderer (with
    # placeholder metrics) and would docker-cp the container's older copy back over
    # the freshly exported trees. Quit just tears down; the trees are managed by the
    # documented pipeline.
    # Leave a lab we only reattached to running; only tear down one we started.
    if [ "${REATTACHED:-0}" = 1 ]; then
        hdr "Detached — lab left running"
        kv "Reopen panel:" "./run.sh"
        kv "Stop the lab:" "docker rm -f $CONTAINER_NAME"
    else
        hdr "Stopping lab"
        docker stop -t 5 "$CONTAINER_NAME" >/dev/null 2>&1 || true
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
        ok "lab stopped"
    fi
    kv "Pcaps:" "$PCAP_DIR/"
    exit 0
}
trap cleanup SIGINT SIGTERM

# ── Build (only when needed) ────────────────────────────────────────
# Rebuild when the image is missing, when DS_LITE_REBUILD=1 is set, or when any
# testbed/ source is newer than the current image. Otherwise reuse the image so
# a vanished container (e.g. a cycled docker daemon) recovers in seconds instead
# of a full 2-minute rebuild.
_img_created=$(docker image inspect "$IMAGE_NAME" --format '{{.Created}}' 2>/dev/null)
NEED_BUILD=0
if [ -z "$_img_created" ] || [ -n "${DS_LITE_REBUILD:-}" ]; then
    NEED_BUILD=1
elif touch -d "$_img_created" /tmp/.dslite_img_ref 2>/dev/null \
     && [ -n "$(find testbed -type f -newer /tmp/.dslite_img_ref -print -quit 2>/dev/null)" ]; then
    NEED_BUILD=1
fi
hdr "DS-Lite lab"
if [ "$NEED_BUILD" = 1 ]; then
    say "Building image (sources changed)..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    if [ -n "$DS_DEBUG" ]; then
        docker build -t "$IMAGE_NAME" testbed/ || { err "image build failed"; exit 1; }
    else
        # Keep the build quiet; full log in $LAUNCH_LOG, shown only on failure.
        if ! docker build -t "$IMAGE_NAME" testbed/ >>"$LAUNCH_LOG" 2>&1; then
            err "image build failed — last lines:"; tail -15 "$LAUNCH_LOG" >&2; exit 1
        fi
    fi
    ok "image built"
    FRESH_IMAGE=1
else
    dbg "reusing current image (DS_LITE_REBUILD=1 to force a rebuild)"
fi

# NAT configuration is fixed: paired pools (RFC 6888 REQ-2),
# fully-random port allocation 1024-65535 (RFC 6056 §3.3.4, BCP 156),
# per-subscriber cap 2000 (RFC 6888 REQ-4 / RFC 7785).

# ── Attacker placement ──────────────────────────────────────────────
# With the command palette the lab boots with no attacker and placement is set
# lazily from the palette ("Set attacker placement"), which wires the attacker
# namespace on demand. The legacy menu still asks upfront.
if _palette_ok; then
    ATTACKER_PLACEMENT=""
else
echo ""
echo "============================================"
echo "  Attacker Placement"
echo "============================================"
echo "  1) IPv4-only network of B4-1 (10.0.1.0/24)"
echo "  2) IPv4-only network of B4-2 (10.0.2.0/24)"
echo "  3) IPv6-only ISP network     (2001:db8:cafe::/64)"
echo "  4) Public Internet / WAN     (198.51.100.0/24)"
echo "  5) OAM management network    (10.99.0.0/24) — insider with SNMP/syslog access"
echo "  6) No attacker"
echo ""
stty sane 2>/dev/null || true
read -erp "Select attacker placement [1-6] (default: 6): " ATK_CHOICE
case "${ATK_CHOICE:-6}" in
    1) ATTACKER_PLACEMENT="b4-1"     ;;
    2) ATTACKER_PLACEMENT="b4-2"     ;;
    3) ATTACKER_PLACEMENT="isp"      ;;
    4) ATTACKER_PLACEMENT="internet" ;;
    5) ATTACKER_PLACEMENT="mgmt"     ;;
    *) ATTACKER_PLACEMENT=""         ;;
esac
fi

# Attacker's primary Wireshark interface (isp → eth-isp, LAN → eth0)
ATK_WS_IFACE="eth0"
[[ "$ATTACKER_PLACEMENT" == "isp" ]] && ATK_WS_IFACE="eth-isp"

# ── Live Wireshark interface menu ────────────────────────────────────
# Define all available capture points as parallel arrays indexed 1-12.
# Entry 12 (Attacker) is only available when a placement was chosen.
WS_LABEL=( ["1"]="ISP bridge (all IPv6)"
            ["2"]="AFTR ↔ ISP (IPv6 encap)"
            ["3"]="AFTR ↔ WAN (public IPv4)"
            ["4"]="AFTR wildcard tunnel (decap IPv4)"
            ["5"]="B4-1 ↔ ISP (IPv6)"
            ["6"]="B4-1 LAN (IPv4 clients)"
            ["7"]="B4-1 tunnel (decap IPv4)"
            ["8"]="B4-2 ↔ ISP (IPv6)"
            ["9"]="B4-2 LAN (IPv4 clients)"
           ["10"]="B4-2 tunnel (decap IPv4)"
           ["11"]="Server (IPv4 dst)"
           ["12"]="Attacker ($ATTACKER_PLACEMENT)"
           ["13"]="OAM/Mgmt network (SNMP — RFC 5706)" )
WS_NS=(    ["1"]=""         ["2"]="aftr"   ["3"]="aftr"       ["4"]="aftr"
           ["5"]="b4-1"     ["6"]="b4-1"   ["7"]="b4-1"
           ["8"]="b4-2"     ["9"]="b4-2"  ["10"]="b4-2"
          ["11"]="server"  ["12"]="attacker" ["13"]="" )
WS_IF=(    ["1"]="br-isp"   ["2"]="eth-isp" ["3"]="eth-wan"   ["4"]="ds-lite-open"
           ["5"]="eth-isp"  ["6"]="eth-lan"  ["7"]="ds-lite"
           ["8"]="eth-isp"  ["9"]="eth-lan" ["10"]="ds-lite"
          ["11"]="eth0"    ["12"]="$ATK_WS_IFACE" ["13"]="br-mgmt" )

if _palette_ok; then
  WS_RAW=0   # captures are launched on demand from the command palette
else
echo ""
echo "============================================"
echo "  Live Wireshark Capture"
echo "  (select one or more, comma/space separated)"
echo "============================================"
_ws_row() { printf "  %3s)  %-44s %-14s  [%s]\n" "$1" "$2" "$3" "$4"; }
_ws_row "1"  "ISP network bridge (all IPv6 ISP traffic)"  "br-isp"        "root ns"
_ws_row "2"  "AFTR - ISP (IPv6 encapsulated traffic)"     "eth-isp"       "aftr"
_ws_row "3"  "AFTR - WAN (public IPv4 after NAT)"         "eth-wan"       "aftr"
_ws_row "4"  "AFTR wildcard tunnel (decap any-B4 IPv4)"   "ds-lite-open"  "aftr"
_ws_row "5"  "B4-1 - ISP (B4-1 IPv6 interface)"           "eth-isp"       "b4-1"
_ws_row "6"  "B4-1 LAN (IPv4 clients behind B4-1)"        "eth-lan"       "b4-1"
_ws_row "7"  "B4-1 tunnel (decap IPv4 at B4-1)"           "ds-lite"       "b4-1"
_ws_row "8"  "B4-2 - ISP (B4-2 IPv6 interface)"           "eth-isp"       "b4-2"
_ws_row "9"  "B4-2 LAN (IPv4 clients behind B4-2)"        "eth-lan"       "b4-2"
_ws_row "10" "B4-2 tunnel (decap IPv4 at B4-2)"           "ds-lite"       "b4-2"
_ws_row "11" "Server (IPv4 destination host)"              "eth0"          "server"
if [ -n "$ATTACKER_PLACEMENT" ]; then
    _ws_row "12" "Attacker (placement: $ATTACKER_PLACEMENT)" "$ATK_WS_IFACE" "attacker"
else
    printf "  %s%3s)  %-44s %-14s  [%s]%s\n" "$C_DIM" "12" "Attacker (place one first)" "-" "attacker" "$C_RST"
fi
_ws_row "13" "OAM / Mgmt network (SNMP - RFC 5706)"         "br-mgmt"       "root ns"
echo "  all)  All of the above"
echo "    0)  No live Wireshark"
echo ""
read -erp "Select interfaces [0-13/all, comma/space separated] (default: 0): " WS_RAW
fi

# Build WS_ENTRIES array of "ns:iface" pairs from the user's selection
WS_ENTRIES=()
_ws_add() {
    local n="$1"
    # Entry 12 is the attacker capture; only valid once an attacker is placed.
    if [ "$n" -eq 12 ] && [ -z "$ATTACKER_PLACEMENT" ]; then
        warn "entry 12 (Attacker) needs an attacker first — choose a placement, then re-open the capture menu"
        return
    fi
    local ns="${WS_NS[$n]}" iface="${WS_IF[$n]}"
    [ -z "$iface" ] && return
    # When the attacker is placed on a B4's LAN, setup.sh moves that B4's
    # eth-lan into a br-lan bridge and binds 10.0.1.1/10.0.2.1 (resolver +
    # PCP proxy) to br-lan. The attacker<->proxy/resolver LAN traffic then
    # rides br-lan, and eth-lan (now a bridge port to the real client) sees
    # NONE of it. Remap the LAN capture entry to br-lan for the B4 the
    # attacker sits behind so entries 6/9 actually show the attack traffic.
    if [ "$n" -eq 6 ] && [ "$ATTACKER_PLACEMENT" = "b4-1" ]; then iface="br-lan"; fi
    if [ "$n" -eq 9 ] && [ "$ATTACKER_PLACEMENT" = "b4-2" ]; then iface="br-lan"; fi
    WS_ENTRIES+=("${ns}:${iface}")
}

ws_input="${WS_RAW:-0}"
if [[ "$ws_input" == "all" ]]; then
    for n in 1 2 3 4 5 6 7 8 9 10 11 13; do _ws_add "$n"; done
    [ -n "$ATTACKER_PLACEMENT" ] && _ws_add 12
elif [[ "$ws_input" != "0" ]]; then
    # Normalise commas/slashes to spaces, then iterate
    for n in $(echo "$ws_input" | tr ',/' '  '); do
        [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le 13 ] && _ws_add "$n"
    done
fi

# ── Clean stale pcaps from previous runs ────────────────────────────
dbg "clearing stale pcap files"
rm -f "$PCAP_DIR"/*.pcap "$PCAP_DIR"/*.pcap[0-9] "$PCAP_DIR"/*.pcap[0-9][0-9] 2>/dev/null || true

# ── Run / reattach container ────────────────────────────────────────
# If a healthy container is already running (and we did not just rebuild), just
# reattach to it — the lab survives across sessions and recovers instantly if
# its menu process died. Otherwise (re)create it.
if [ -z "${FRESH_IMAGE:-}" ] && docker ps -q -f "name=^${CONTAINER_NAME}$" | grep -q .; then
    dbg "reattaching to the already-running container"
    REATTACHED=1
else
    say "Starting container..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    DOCKER_ENV_ARGS=()
    [ -n "$ATTACKER_PLACEMENT" ] && DOCKER_ENV_ARGS+=(-e "ATTACKER_PLACEMENT=$ATTACKER_PLACEMENT")
    # Resource caps:
    #   --memory   raised from 1g → 4g.   At 1g the cgroup OOM-killer triggered
    #              after ~10 minutes of attack traffic (conntrack table + pcaps
    #              grew the working set past the cap), killing the bash sessions.
    #   --cpus     raised from 1.0 → 4.0 so high-rate attacks don't starve the
    #              namespace-supervisor processes.
    # --restart unless-stopped: survive a docker-daemon restart so the lab does
    #              not silently vanish between sessions.
    docker run -d \
        --name "$CONTAINER_NAME" \
        --restart unless-stopped \
        --privileged \
        --memory=4g \
        --memory-swap=4g \
        --cpus=4.0 \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        -v "$PCAP_DIR:/testbed/pcaps" \
        -p 8080:8080 \
        "${DOCKER_ENV_ARGS[@]+"${DOCKER_ENV_ARGS[@]}"}" \
        "$IMAGE_NAME"
fi

# ── Wait until lab is ready ─────────────────────────────────────────
if [ "${REATTACHED:-0}" = 1 ]; then
    ok "lab already running"
else
    printf '  initializing'
    for i in $(seq 1 90); do
        if docker logs "$CONTAINER_NAME" 2>&1 | grep -q "testbed is ready"; then
            break
        fi
        if ! docker ps -q -f "name=$CONTAINER_NAME" | grep -q .; then
            printf '\n'; err "container exited during init — last lines:"
            docker logs "$CONTAINER_NAME" 2>&1 | tail -20 >&2
            docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
            exit 1
        fi
        [ -z "$DS_DEBUG" ] && printf '.'
        sleep 1
    done
    printf '\n'; ok "lab ready"
    # The full container setup log is verbose; show it only in debug mode.
    [ -n "$DS_DEBUG" ] && docker logs "$CONTAINER_NAME" 2>&1 | sed 's/^/    /' >&2
fi

# ── Device terminal selection menu ────────────────────────────────
if _palette_ok; then
  DEV_RAW=0   # device shells are opened on demand from the command palette
else
echo ""
echo "============================================"
echo "  Device Terminals"
echo "  (select which to open, comma/space separated)"
echo "============================================"
_dev_row() { printf "  %3s)  %-15s (%s)\n" "$1" "$2" "$3"; }
_dev_row  "1" "DHCPv6-Server"  "dhcpv6server"
_dev_row  "2" "DNS-Server"     "dns-server, 2001:db8:cafe::2"
_dev_row  "3" "B4-1"           "b4-1"
_dev_row  "4" "B4-2"           "b4-2"
_dev_row  "5" "AFTR"           "aftr"
_dev_row  "6" "Client1"        "client1"
_dev_row  "7" "Client2"        "client2"
_dev_row  "8" "Server-Router"  "server-router"
_dev_row  "9" "Server"         "server"
_dev_row "10" "AFTR-Monitor"   "live conntrack/NAT stats"
if [ -n "$ATTACKER_PLACEMENT" ]; then
    _dev_row "11" "Attacker"   "placement: $ATTACKER_PLACEMENT"
else
    printf "  %s%3s)  %-15s (%s)%s\n" "$C_DIM" "11" "Attacker" "place one first" "$C_RST"
fi
_dev_row "12" "Mgmt-Station"   "mgmt, 10.99.0.10 - SNMP attacker for T11/T12"
echo "  all)  All of the above"
echo "    0)  No terminals"
echo ""
read -erp "Select devices [0-12/all, comma/space separated] (default: all): " DEV_RAW
fi

# Map numbers to (label, ns/script) pairs
DEV_LABEL=( ["1"]="DHCPv6-Server" ["2"]="DNS-Server" ["3"]="B4-1"    ["4"]="B4-2"
            ["5"]="AFTR"          ["6"]="Client1"    ["7"]="Client2"
            ["8"]="Server-Router" ["9"]="Server"     ["10"]="AFTR-Monitor"
           ["11"]="Attacker"     ["12"]="Mgmt-Station" )
DEV_NS=(    ["1"]="dhcpv6server"  ["2"]="dns-server" ["3"]="b4-1"    ["4"]="b4-2"
            ["5"]="aftr"          ["6"]="client1"    ["7"]="client2"
            ["8"]="server-router" ["9"]="server"     ["10"]="aftr"
           ["11"]="attacker"     ["12"]="mgmt" )

# ── Open device terminals ──────────────────────────────────────────
_open_dev() {
    local n="$1"
    # Entry 11 is the attacker shell; only valid once an attacker is placed.
    if [ "$n" -eq 11 ] && [ -z "$ATTACKER_PLACEMENT" ]; then
        warn "entry 11 (Attacker) needs an attacker first — place one (p), then re-open the device menu"
        return
    fi
    local label="${DEV_LABEL[$n]}" ns="${DEV_NS[$n]}"
    if [ "$n" -eq 10 ]; then
        open_monitor_terminal "$label" "$ns" /testbed/aftr/monitor_nat.sh
    else
        open_terminal "$label" "$ns"
    fi
    # Remember that an attacker shell is open so reposition can reopen it:
    # repositioning kills every process in the attacker ns (including this
    # shell), so it must be relaunched at the new location.
    [ "$ns" = "attacker" ] && ATK_SHELL_ACTIVE=1
}

dev_input="${DEV_RAW:-all}"

if [ -n "$TERM_EMU" ]; then
    if [[ "$dev_input" == "0" ]]; then
        echo "  Skipping device terminals."
    else
        if [[ "$dev_input" == "all" ]]; then
            dev_nums="1 2 3 4 5 6 7 8 9 10 12"
            [ -n "$ATTACKER_PLACEMENT" ] && dev_nums="$dev_nums 11"
        else
            dev_nums=$(echo "$dev_input" | tr ',/' '  ')
        fi

        if [ -z "$DISPLAY" ] || [ -z "$TERM_EMU" ]; then
            warn "no graphical display — skipping device terminals (open with: docker exec -it $CONTAINER_NAME ip netns exec <ns> bash)"
        else
            echo "Opening device terminals ($TERM_EMU)..."
            for n in $dev_nums; do
                [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le 12 ] && _open_dev "$n"
            done
            sleep 1
        fi
    fi

    # ── Live Wireshark (one instance per selected interface) ─────────
    ATK_WS_PID=""
    ATK_WS_ACTIVE=0
    if [ "${#WS_ENTRIES[@]}" -gt 0 ]; then
        if ! command -v wireshark &>/dev/null; then
            echo "[!] wireshark not found on host — skipping live capture."
        else
            for entry in "${WS_ENTRIES[@]}"; do
                ws_ns="${entry%%:*}"
                ws_if="${entry##*:}"
                tcpdump_err="/tmp/ds-lite-tcpdump-${ws_ns:-root}-${ws_if}.err"
                ws_err="/tmp/ds-lite-wireshark-${ws_ns:-root}-${ws_if}.err"
                echo "Opening Wireshark on ${ws_ns:+$ws_ns/}${ws_if}  (tcpdump errors: $tcpdump_err)"
                # Feed each capture through a per-interface named pipe instead of
                # raw stdin, so Wireshark shows the interface name (e.g.
                # "aftr-eth-isp") as the capture source rather than the generic
                # "Standard input" for every window. Also tag the window title.
                ws_name="${ws_ns:-root}-${ws_if}"
                ws_fifo="/tmp/ds-lite-cap-${ws_name}"
                rm -f "$ws_fifo"; mkfifo "$ws_fifo" 2>/dev/null
                TERM_FIFOS+=("$ws_fifo")
                if [ -n "$ws_ns" ]; then
                    ( docker exec "$CONTAINER_NAME" \
                        ip netns exec "$ws_ns" \
                        tcpdump -U -i "$ws_if" -w - 2>"$tcpdump_err" > "$ws_fifo" ) &
                else
                    ( docker exec "$CONTAINER_NAME" \
                        tcpdump -U -i "$ws_if" -w - 2>"$tcpdump_err" > "$ws_fifo" ) &
                fi
                TERM_PIDS+=($!)
                wireshark -k -i "$ws_fifo" -o "gui.window_title:${ws_name}" \
                    2>"$ws_err" &
                _ws_pid=$!
                TERM_PIDS+=($_ws_pid)
                if [ "$ws_ns" = "attacker" ]; then
                    ATK_WS_PID=$_ws_pid
                    ATK_WS_ACTIVE=1
                fi
                sleep 0.25
            done
        fi
    fi
else
    echo "[!] No graphical terminal emulator found."
    echo "    Open shells manually:"
    for ns in dhcpv6server dns-server b4-1 b4-2 aftr client1 client2 server-router server mgmt; do
        echo "      docker exec -it $CONTAINER_NAME ip netns exec $ns bash"
    done
    [ -n "$ATTACKER_PLACEMENT" ] && \
        echo "      docker exec -it $CONTAINER_NAME ip netns exec attacker bash"
    echo "    AFTR Monitor:"
    echo "      docker exec -it $CONTAINER_NAME ip netns exec aftr bash /testbed/aftr/monitor_nat.sh"
fi

# ── Resolve lab IPs from running container ──────────────────────────
resolve_lab_ips() {
    local exec="docker exec $CONTAINER_NAME"
    ATK_IP4="" ATK_IP6=""
    if [ -n "$ATTACKER_PLACEMENT" ]; then
        case "$ATTACKER_PLACEMENT" in
            b4-1|b4-2)
                ATK_IP4=$($exec ip netns exec attacker ip -4 addr show eth0 2>/dev/null \
                    | grep -oP '(?<=inet )[^/]+' | head -1) ;;
            isp)
                ATK_IP6=$($exec ip netns exec attacker ip -6 addr show eth-isp scope global 2>/dev/null \
                    | grep -oP '(?<=inet6 )[^/]+' | head -1) ;;
            internet)
                ATK_IP4=$($exec ip netns exec attacker ip -4 addr show eth0 2>/dev/null \
                    | grep -oP '(?<=inet )[^/]+' | head -1) ;;
        esac
    fi
    B4_1_IP6=$($exec ip netns exec b4-1 ip -6 addr show eth-isp scope global 2>/dev/null \
        | grep -oP '(?<=inet6 )[^/]+' | head -1)
    B4_2_IP6=$($exec ip netns exec b4-2 ip -6 addr show eth-isp scope global 2>/dev/null \
        | grep -oP '(?<=inet6 )[^/]+' | head -1)
}


# ── Attacker repositioning ─────────────────────────────────────────
# Prompt the user to choose a new placement from a mini-menu, then
# rewire the attacker namespace in-place (no lab restart required).
reposition_menu() {
    echo ""
    echo "  ┌─ Reposition Attacker ─────────────────────────────────┐"
    printf "  │  Current: %-43s│\n" "${ATTACKER_PLACEMENT:-none}"
    echo "  ├───────────────────────────────────────────────────────┤"
    echo "  │  1) B4-1 LAN    IPv4  10.0.1.0/24                    │"
    echo "  │  2) B4-2 LAN    IPv4  10.0.2.0/24                    │"
    echo "  │  3) ISP         IPv6  2001:db8:cafe::/64             │"
    echo "  │  4) Internet    IPv4  198.51.100.0/24                 │"
    echo "  │  5) MGMT        IPv4  10.99.0.0/24                   │"
    echo "  │  0) Cancel                                            │"
    echo "  └───────────────────────────────────────────────────────┘"
    echo ""
    stty sane 2>/dev/null || true
    read -erp "  Select new placement [0-5]: " _p
    local target=""
    case "${_p}" in
        1) target="b4-1"     ;;
        2) target="b4-2"     ;;
        3) target="isp"      ;;
        4) target="internet" ;;
        5) target="mgmt"     ;;
        0|"") echo "  Cancelled."; return 0 ;;
        *) echo "  Invalid choice."; return 1 ;;
    esac
    move_attacker "$target"
}

_relaunch_attacker_ws() {
    [ "$ATK_WS_ACTIVE" != "1" ] && return
    command -v wireshark &>/dev/null || return
    # Kill the previous attacker Wireshark/tcpdump pair
    if [ -n "$ATK_WS_PID" ] && kill -0 "$ATK_WS_PID" 2>/dev/null; then
        kill "$ATK_WS_PID" 2>/dev/null || true
        wait "$ATK_WS_PID" 2>/dev/null || true
    fi
    ATK_WS_PID=""
    local ws_if="$ATK_WS_IFACE"
    [ -z "$ws_if" ] && return
    local tcpdump_err="/tmp/ds-lite-tcpdump-attacker-${ws_if}.err"
    local ws_err="/tmp/ds-lite-wireshark-attacker-${ws_if}.err"
    ok "Wireshark: restarting for attacker/${ws_if} ..."
    local ws_name="attacker-${ws_if}"
    local ws_fifo="/tmp/ds-lite-cap-${ws_name}"
    rm -f "$ws_fifo"; mkfifo "$ws_fifo" 2>/dev/null
    TERM_FIFOS+=("$ws_fifo")
    ( docker exec "$CONTAINER_NAME" \
        ip netns exec attacker \
        tcpdump -U -i "$ws_if" -w - 2>"$tcpdump_err" > "$ws_fifo" ) &
    TERM_PIDS+=($!)
    wireshark -k -i "$ws_fifo" -o "gui.window_title:${ws_name}" 2>"$ws_err" &
    ATK_WS_PID=$!
    TERM_PIDS+=($ATK_WS_PID)
}

# Reopen the attacker shell terminal after a reposition. _teardown_attacker_links
# kills every process in the attacker ns (including the interactive shell), so a
# fresh terminal must be opened at the new location. No-op if the user never
# opened an attacker shell.
_relaunch_attacker_shell() {
    [ "$ATK_SHELL_ACTIVE" != "1" ] && return
    [ -z "$TERM_EMU" ] && return
    ok "Reopening attacker shell at new location ..."
    open_terminal "Attacker" "attacker"
}

# Tear down all attacker network links (veth peers are auto-removed by kernel).
# Leaves the attacker netns itself intact.
_teardown_attacker_links() {
    docker exec "$CONTAINER_NAME" bash -c '
        # Kill background processes running in attacker ns (tcpdump, dhclient)
        ip netns pids attacker 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        sleep 0.2
        # Delete every non-loopback interface from attacker; the kernel removes
        # the paired veth endpoint from whichever other ns it lives in.
        # Strip @ifN suffix; exclude lo and ip6tnl0 (kernel-managed, undeletable).
        for iface in $(ip netns exec attacker ip -o link show \
                       | awk -F": " "{print \$2}" \
                       | awk -F"@" "{print \$1}" \
                       | grep -vE "^(lo|ip6tnl)"); do
            ip netns exec attacker ip link del "$iface" 2>/dev/null || true
        done
    ' 2>/dev/null
}

# Wire the attacker namespace to <placement> and configure addressing.
# Mirrors setup.sh section 14 but runs on an already-existing attacker netns.
_setup_attacker_links() {
    local plc="$1"
    docker exec "$CONTAINER_NAME" bash -c "
        PCAP_DIR=/testbed/pcaps
        case '$plc' in
        b4-1)
            # Create veth pair and join B4-1 LAN bridge
            ip link add eth0-atk type veth peer name eth-atk-b41
            ip link set eth0-atk netns attacker
            ip netns exec attacker ip link set eth0-atk name eth0
            ip link set eth-atk-b41 netns b4-1

            # br-lan may already exist if it was created during initial setup;
            # only recreate it when missing.
            if ! ip netns exec b4-1 ip link show br-lan &>/dev/null; then
                ip netns exec b4-1 ip link add br-lan type bridge
                ip netns exec b4-1 ip addr del 10.0.1.1/24 dev eth-lan 2>/dev/null || true
                ip netns exec b4-1 ip link set eth-lan master br-lan
                ip netns exec b4-1 ip addr add 10.0.1.1/24 dev br-lan
                ip netns exec b4-1 ip link set br-lan up

                # Restart dnsmasq on br-lan
                kill \$(cat /var/run/dnsmasq-b4-1.pid 2>/dev/null) 2>/dev/null || true
                sleep 0.3
                ip netns exec b4-1 dnsmasq \
                    --interface=br-lan --except-interface=lo --bind-interfaces --no-resolv \
                    --server=2001:db8:cafe::2 \
                    --address=/client1.dslite.example.com/10.0.1.100 \
                    --proxy-dnssec \
                    --log-queries --log-facility=/var/log/dnsmasq.log \
                    --dhcp-range=10.0.1.150,10.0.1.200,255.255.255.0,12h \
                    --dhcp-option=3,10.0.1.1 \
                    --dhcp-option=6,10.0.1.1 \
                    --pid-file=/var/run/dnsmasq-b4-1.pid
            fi

            ip netns exec b4-1 ip link set eth-atk-b41 master br-lan
            ip netns exec b4-1 ip link set eth-atk-b41 up

            ip netns exec attacker ip link set lo up
            ip netns exec attacker ip link set eth0 up
            ip netns exec attacker dhclient -1 \
                -pf /var/run/dhclient-attacker.pid \
                -lf /var/lib/dhcp/dhclient-attacker.leases \
                eth0 2>/dev/null || true

            mkdir -p /etc/netns/attacker
            echo 'nameserver 10.0.1.1' > /etc/netns/attacker/resolv.conf
            ;;

        b4-2)
            ip link add eth0-atk type veth peer name eth-atk-b42
            ip link set eth0-atk netns attacker
            ip netns exec attacker ip link set eth0-atk name eth0
            ip link set eth-atk-b42 netns b4-2

            if ! ip netns exec b4-2 ip link show br-lan &>/dev/null; then
                ip netns exec b4-2 ip link add br-lan type bridge
                ip netns exec b4-2 ip addr del 10.0.2.1/24 dev eth-lan 2>/dev/null || true
                ip netns exec b4-2 ip link set eth-lan master br-lan
                ip netns exec b4-2 ip addr add 10.0.2.1/24 dev br-lan
                ip netns exec b4-2 ip link set br-lan up

                kill \$(cat /var/run/dnsmasq-b4-2.pid 2>/dev/null) 2>/dev/null || true
                sleep 0.3
                ip netns exec b4-2 dnsmasq \
                    --interface=br-lan --except-interface=lo --bind-interfaces --no-resolv \
                    --server=2001:db8:cafe::2 \
                    --dhcp-range=10.0.2.150,10.0.2.200,255.255.255.0,12h \
                    --dhcp-option=3,10.0.2.1 \
                    --dhcp-option=6,10.0.2.1 \
                    --pid-file=/var/run/dnsmasq-b4-2.pid
            fi

            ip netns exec b4-2 ip link set eth-atk-b42 master br-lan
            ip netns exec b4-2 ip link set eth-atk-b42 up

            ip netns exec attacker ip link set lo up
            ip netns exec attacker ip link set eth0 up
            ip netns exec attacker dhclient -1 \
                -pf /var/run/dhclient-attacker.pid \
                -lf /var/lib/dhcp/dhclient-attacker.leases \
                eth0 2>/dev/null || true

            mkdir -p /etc/netns/attacker
            echo 'nameserver 10.0.2.1' > /etc/netns/attacker/resolv.conf
            ;;

        isp)
            ip link add eth-isp-atk type veth peer name atk-br
            ip link set eth-isp-atk mtu 1500
            ip link set atk-br     mtu 1500
            ip link set eth-isp-atk netns attacker
            ip netns exec attacker ip link set eth-isp-atk name eth-isp
            ip link set atk-br master br-isp
            ip link set atk-br up
            ip netns exec attacker ip link set lo up
            ip netns exec attacker ip link set eth-isp up
            ip netns exec attacker sysctl -qw net.ipv6.conf.eth-isp.accept_ra=1
            ip netns exec attacker ip -6 addr add 2001:db8:cafe::13a/64 dev eth-isp 2>/dev/null || true
            ip link set br-isp type bridge ageing_time 0
            bridge link set dev atk-br learning off flood on 2>/dev/null || true
            ;;

        mgmt)
            ip link add eth-mgmt-atk type veth peer name atk-mgmt-br
            ip link set eth-mgmt-atk netns attacker
            ip netns exec attacker ip link set eth-mgmt-atk name eth0
            ip link set atk-mgmt-br master br-mgmt
            ip link set atk-mgmt-br up
            ip netns exec attacker ip link set lo up
            ip netns exec attacker ip link set eth0 up
            ip netns exec attacker ip addr add 10.99.0.50/24 dev eth0 2>/dev/null || true
            ;;

        internet)
            # Ensure br-srv exists in server-router (created on first internet placement)
            if ! ip netns exec server-router ip link show br-srv &>/dev/null; then
                ip netns exec server-router ip link add br-srv type bridge
                ip netns exec server-router ip link set br-srv up
                ip netns exec server-router ip addr del 198.51.100.1/24 dev eth-srv 2>/dev/null || true
                ip netns exec server-router ip link set eth-srv master br-srv
                ip netns exec server-router ip addr add 198.51.100.1/24 dev br-srv
            fi
            ip link add eth0-atk type veth peer name eth-atk-srv
            ip link set eth0-atk netns attacker
            ip netns exec attacker ip link set eth0-atk name eth0
            ip link set eth-atk-srv netns server-router
            ip netns exec server-router ip link set eth-atk-srv master br-srv
            ip netns exec server-router ip link set eth-atk-srv up
            ip netns exec attacker ip link set lo up
            ip netns exec attacker ip link set eth0 up
            ip netns exec attacker ip addr add 198.51.100.50/24 dev eth0 2>/dev/null || true
            ip netns exec attacker ip route add default via 198.51.100.1 2>/dev/null || true
            mkdir -p /etc/netns/attacker
            echo 'nameserver 198.51.100.2' > /etc/netns/attacker/resolv.conf
            ;;
        esac

    " 2>&1
    # Restart pcap from the outer shell so the background process is fully
    # detached from the docker exec session (avoids rc=143 from SIGTERM).
    docker exec "$CONTAINER_NAME" bash -c '
        pkill -f "attacker.pcap" 2>/dev/null || true
        sleep 0.2
        ATK_IFACE=$(ip netns exec attacker ip -o link show \
            | awk -F": " "{print \$2}" | awk -F"@" "{print \$1}" \
            | grep -v "^lo$" | head -1)
        [ -n "$ATK_IFACE" ] && nohup ip netns exec attacker \
            tcpdump -U -Z root -i "$ATK_IFACE" \
            -w /testbed/pcaps/attacker.pcap >/dev/null 2>&1 &
    ' 2>/dev/null &
}

move_attacker() {
    local target="$1"
    if [ "$target" = "$ATTACKER_PLACEMENT" ]; then
        echo "  Attacker is already on '$target' — nothing to do."
        return 0
    fi
    # Lazy boot: the attacker namespace is created by setup.sh only when a
    # placement is chosen at boot. When placement is set later from the palette
    # the namespace may not exist yet, so create it (with loopback up) before
    # wiring links into it.
    docker exec "$CONTAINER_NAME" sh -c 'ip netns list | grep -qw attacker \
        || { ip netns add attacker && ip netns exec attacker ip link set lo up; }' 2>/dev/null
    say "Repositioning attacker: ${ATTACKER_PLACEMENT:-none} → $target ..."
    _teardown_attacker_links
    _setup_attacker_links "$target"
    # Verify success by checking a non-loopback interface appeared in attacker ns.
    local iface
    iface=$(docker exec "$CONTAINER_NAME" ip netns exec attacker ip -o link show \
            | awk -F': ' '/eth/{print $2; exit}' | awk -F'@' '{print $1}')
    if [ -z "$iface" ]; then
        warn "Reposition to '$target' failed — no interface in attacker ns."
        return 1
    fi
    ATTACKER_PLACEMENT="$target"
    case "$target" in
        isp) ATK_WS_IFACE="eth-isp" ;;
        *)   ATK_WS_IFACE="eth0" ;;
    esac
    _relaunch_attacker_ws
    _relaunch_attacker_shell
    ATK_IP4="" ATK_IP6=""
    sleep 1
    resolve_lab_ips
    ok "Attacker repositioned to: $target  (interface: $iface)"
    [ -n "$ATK_IP4" ] && kv "IPv4:" "$ATK_IP4"
    [ -n "$ATK_IP6" ] && kv "IPv6:" "$ATK_IP6"
    return 0
}


# Number-to-attack-id map, rebuilt each time the menu is rendered from the
# corpus manifest. The dispatch keys on the id, never the menu number, so the
# menu stays in sync with the testbed corpus automatically.
declare -A MENU_IDS
MENU_COUNT=0

show_attack_menu() {
    local _plc="${ATTACKER_PLACEMENT:-none}"
    MENU_IDS=(); MENU_COUNT=0
    local total
    total=$(grep -cvE '^\s*#|^\s*$' "$CORPUS_FILE" 2>/dev/null || echo 0)
    echo "============================================"
    echo "  Attack Menu  (${total}-attack corpus)"
    printf "  Attacker: %-30s[p] reposition\n" "$_plc"
    echo "============================================"
    local id group name vantage last_group=""
    while IFS='|' read -r id group name vantage; do
        case "$id" in ''|\#*) continue ;; esac
        MENU_COUNT=$((MENU_COUNT + 1))
        MENU_IDS[$MENU_COUNT]="$id"
        if [ "$group" != "$last_group" ]; then
            echo ""; echo "  $group"; last_group="$group"
        fi
        printf "  %3s)  %-7s %-46s [%s]\n" "$MENU_COUNT" "[$id]" "$name" "$vantage"
    done < "$CORPUS_FILE"
    echo ""
    echo "  Utilities"
    echo "   p)  Reposition attacker (currently: ${ATTACKER_PLACEMENT:-none})"
    echo "   v)  Victim Monitor (Client1 -> http://198.51.100.2)"
    echo "   m)  AFTR Monitor (live connection table / address-translation stats)"
    echo "   t)  Run connectivity tests"
    echo "   s)  Sample traffic (one visible exchange of every protocol)"
    echo "   g)  Generate attack trees from collected results"
    echo "   r)  Show attack results summary"
    echo "   d)  Defenses on/off  (run an attack, enable its defense, re-run)"
    echo "   0)  Exit menu (keep lab running, Ctrl+C to stop)"
}

# ── Defenses submenu: lets a user toggle each verified defense on/off so the
#    attack -> defend -> re-attack loop works from the menu, no shell needed.
#    Each row names the attack(s) the control closes, so the mapping is obvious.
DEF_IDS=(TRABELSI NAT_LOG SAVI ESP_AEAD FEISTEL_IPID PCP_QUOTA PCP_OWNERSHIP PCP_AUTH DNS_0X20 DHCPV6_AUTH SNMP_USM)
DEF_CLOSES=("T1" "T2" "T3,T5,T6" "T4" "T6" "T7" "T8,T10" "T9" "T11" "T12,T13" "T14,T15")
DEF_NAME=("Half-open early eviction" "Per-binding attribution log" "SAVI source binding" "AEAD ESP on softwire" "Feistel IP-ID randomization" "Per-subscriber PCP quota" "PCP ownership binding" "Authenticated PCP ANNOUNCE" "DNS-0x20 randomization" "Ed25519-signed DHCPv6" "SNMPv3 USM + engineID pin")
defense_menu() {
    local DEFSH="$(pwd)/testbed/defenses/article_defenses.sh"
    if [ ! -f "$DEFSH" ]; then echo "  (defense script not found: $DEFSH)"; return; fi
    while true; do
        echo ""
        echo "============================================"
        echo "  Defenses  (toggle a control, then re-run the attack it closes)"
        echo "============================================"
        local i
        for i in "${!DEF_IDS[@]}"; do
            printf "  %3s)  %-16s closes %-9s  %s\n" "$((i+1))" "${DEF_IDS[$i]}" "${DEF_CLOSES[$i]}" "${DEF_NAME[$i]}"
        done
        echo ""
        echo "   a)  Turn ALL defenses OFF (clean attack baseline)"
        echo "   0)  Back to attack menu"
        echo ""
        local pick
        read -erp "  Toggle which defense [1-${#DEF_IDS[@]}], a=all-off, 0=back: " pick
        case "$pick" in
            0|"") return ;;
            a|A)
                echo "  Turning all defenses off ..."
                for i in "${!DEF_IDS[@]}"; do bash "$DEFSH" "${DEF_IDS[$i]}" off >/dev/null 2>&1; done
                echo "  ✓ all defenses off"
                ;;
            *)
                if [[ "$pick" =~ ^[0-9]+$ ]] && [ "$pick" -ge 1 ] && [ "$pick" -le "${#DEF_IDS[@]}" ]; then
                    local did="${DEF_IDS[$((pick-1))]}" state
                    read -erp "  ${did}: turn [on/off]? " state
                    case "$state" in
                        on|ON|off|OFF)
                            echo "  ${did} ${state,,} ..."
                            bash "$DEFSH" "$did" "${state,,}" 2>&1 | sed 's/^/    /'
                            echo "  Now re-run ${DEF_CLOSES[$((pick-1))]} from the attack menu to see the effect."
                            ;;
                        *) echo "  (cancelled — type on or off)" ;;
                    esac
                else
                    echo "  Invalid selection: $pick"
                fi
                ;;
        esac
    done
}


# ── reset_aftr_state: clear cross-attack residue before each attack ──
# Several attacks leave persistent state that breaks later attacks:
#   * T15 (PCP port-exhaust) makes pcp_server install forward-chain DROP
#     rules (comment "PCP-EXHAUST") that block ALL b4 -> eth-wan data flows.
#   * T7/T8/T10 push entries into chain ip nat pcp_dnat that persist.
#   * Any flood leaves conntrack entries and per_b4_connlimit meter counts.
#   * T10 leaves a poisoned dnsmasq cache; T13/T14 leave the cached
#     AFTR-Name in /var/run/ds-lite-aftr-name.
# Running, e.g., T15 then T1 would make T1 silently fail (every packet
# dropped by the leftover PCP-EXHAUST rule), so this runs before each attack.
reset_aftr_state() {
    local dx="docker exec $CONTAINER_NAME"
    # (a0) re-assert the static softwire-local B4 addresses. A prior DHCPv6
    #      hijack (T12/T13) flushes eth-isp and drops ::b41/::b42, after which
    #      the B4 tunnel cannot source its outer packets and the subscriber's
    #      whole data path is dead. Re-adding here heals the lab before the next
    #      attack so a leftover hijack never silently breaks unrelated runs.
    $dx ip netns exec b4-1 ip -6 addr add 2001:db8:cafe::b41/64 dev eth-isp >/dev/null 2>&1
    $dx ip netns exec b4-2 ip -6 addr add 2001:db8:cafe::b42/64 dev eth-isp >/dev/null 2>&1
    # (a) delete PCP-EXHAUST forward-chain DROP rules (handle-based)
    $dx ip netns exec aftr bash -c '
        nft -a list chain ip filter forward 2>/dev/null \
          | grep PCP-EXHAUST | grep -oE "handle [0-9]+" | awk "{print \$2}" \
          | while read h; do nft delete rule ip filter forward handle "$h" 2>/dev/null; done' \
        >/dev/null 2>&1
    # (b) flush PCP DNAT chain
    $dx ip netns exec aftr nft flush chain ip nat pcp_dnat >/dev/null 2>&1
    # (c) restart PCP server + both B4 proxies so in-memory pools start empty.
    #     setsid + </dev/null detaches them so they survive `docker exec` exit.
    $dx ip netns exec aftr pkill -9 -f /testbed/aftr/pcp_server.py >/dev/null 2>&1
    $dx ip netns exec b4-1 pkill -9 -f /testbed/b4/pcp_proxy.py >/dev/null 2>&1
    $dx ip netns exec b4-2 pkill -9 -f /testbed/b4/pcp_proxy.py >/dev/null 2>&1
    sleep 0.4
    # `docker exec -d` runs the daemon detached so it survives this function.
    # IMPORTANT: the B4 proxies MUST be restarted with --passthrough-third-party,
    # exactly as setup.sh launches them. Without it the proxy strips/ignores the
    # client-supplied THIRD_PARTY option, so T8/T10 PEER requests are not
    # forwarded to the AFTR and silently find nothing (the proxy log stays empty).
    # PCP_POOL_SIZE must match setup.sh (env PCP_POOL_SIZE=1024). Without it the
    # server defaults to the full 1024-65534 range, so T15 port-exhaustion can
    # never deplete the pool in a trial window and silently looks DEFENDED.
    docker exec -d "$CONTAINER_NAME" ip netns exec aftr env PCP_POOL_SIZE="${PCP_POOL_SIZE:-1024}" python3 /testbed/aftr/pcp_server.py >/dev/null 2>&1
    docker exec -d "$CONTAINER_NAME" ip netns exec b4-1 python3 /testbed/b4/pcp_proxy.py \
        --lan-ip 10.0.1.1 --b4-ip6 2001:db8:cafe::b41 --aftr-ip6 2001:db8:cafe::10 --passthrough-third-party >/dev/null 2>&1
    docker exec -d "$CONTAINER_NAME" ip netns exec b4-2 python3 /testbed/b4/pcp_proxy.py \
        --lan-ip 10.0.2.1 --b4-ip6 2001:db8:cafe::b42 --aftr-ip6 2001:db8:cafe::10 --passthrough-third-party >/dev/null 2>&1
    # (d) flush conntrack
    $dx ip netns exec aftr conntrack -F >/dev/null 2>&1
    # (e) kill stray helper flows left in subscriber/server namespaces
    local ns
    for ns in client1 client2 server b4-1 b4-2; do
        $dx ip netns exec "$ns" pkill -9 -f 'ncat|curl|dig|nslookup' >/dev/null 2>&1
    done
    # Victim-fixture processes (T6 ping flood, T10 http.server + PCP refresh) live
    # only in subscriber namespaces. Scope this to client1/client2 — the `server`
    # ns runs a legitimate single-threaded python http.server (its -c script also
    # matches "http.server"), and killing it would break T4/T11.
    for ns in client1 client2; do
        $dx ip netns exec "$ns" pkill -9 -f 'python3 -m http.server|ping -s' >/dev/null 2>&1
    done
    # (e2) kill any attack-tool process that survived a previous run. A
    #      surviving flood re-saturates the per_b4_connlimit meter and makes
    #      the next attack falsely look DEFENDED. The pattern deliberately
    #      excludes the infra daemons pcp_server.py / pcp_proxy.py.
    $dx pkill -9 -f 'nat_exhaustion|nat_hold|fragment_attack|tunnel_spoof|t5_softwire_inject|dns_cache_poison|reputation_poisoning|pcp_attack\.py|snmp_attack|dhcpv6_hijack|t10_peer_crosssub' >/dev/null 2>&1
    # (f) the per_b4_connlimit dynamic meter counts live conntrack entries
    #     (`ct count over 2000`); it has no standalone name to flush, and
    #     `nft delete meter` is a syntax error on this build. Flushing
    #     conntrack in (d) drops the entries, so the meter drains on its own.
    # (f2) remove the stateless ISP ACL that the T7/T8 fragment tools install on
    #      the AFTR to demonstrate the bypass. That table drops every
    #      encapsulated TCP SYN (inner proto 6, SYN flag), so if the attack is
    #      interrupted before its own teardown runs (e.g. Ctrl+C, timeout) it
    #      leaves ALL subscriber TCP through the softwire black-holed while ICMP
    #      and UDP still work. Deleting it here restores the data plane.
    $dx ip netns exec aftr nft delete table ip6 stateless_fw >/dev/null 2>&1
    # (g) flush B4 dnsmasq cache (clears T10 cache poison); (h) clear T13/T14
    #     AFTR-Name; (h2) clear T10's NDP hijack. T10 --hijack-upstream installs
    #     a PERMANENT neighbour entry on the victim B4 that maps the upstream
    #     resolver (and gateway/AFTR) to the attacker MAC. `ip neigh flush` does
    #     NOT remove PERMANENT entries, so without an explicit delete the victim
    #     B4's DNS path stays black-holed for every later attack and for normal
    #     traffic until a full rebuild. Delete the infra entries so the kernel
    #     re-resolves them on the next packet.
    local b4
    for b4 in b4-1 b4-2; do
        # Restore the AFTR-name cache to its legitimate post-boot value (NOT
        # delete it): the dhclient exit hook only rebuilds the tunnel when a
        # PRIOR name is present to compare against, so wiping the file makes the
        # next renewal look like first boot and the T13/T14 hijack silently
        # no-ops. Writing the legit name back puts the B4 in clean post-boot
        # state so AFTR-hijack attacks are reproducible after a reset.
        $dx ip netns exec "$b4" bash -c 'pkill -HUP dnsmasq 2>/dev/null;
            echo "aftr.dslite.example.com." > /var/run/ds-lite-aftr-name 2>/dev/null;
            for a in 2001:db8:cafe::2 2001:db8:cafe::10 2001:db8:cafe::1; do
                ip -6 neigh del "$a" dev eth-isp 2>/dev/null || true
            done; true' >/dev/null 2>&1
    done
    # (i) restore each B4 softwire to the legit AFTR. T13/T14 repoint the
    #     tunnel to the attacker (and change the B4's tunnel local), so just
    #     clearing the cached name leaves the data plane broken for the next
    #     attack — the AFTR only decapsulates the canonical (local,remote) pair.
    #     `ip tunnel change` resets the link MTU to the ip6tnl default (1460), so
    #     restore the configured 1500 explicitly or the next fragment-class
    #     attack runs against a silently different MTU.
    $dx ip netns exec b4-1 ip -6 tunnel change ds-lite local 2001:db8:cafe::b41 remote 2001:db8:cafe::10 >/dev/null 2>&1
    $dx ip netns exec b4-2 ip -6 tunnel change ds-lite local 2001:db8:cafe::b42 remote 2001:db8:cafe::10 >/dev/null 2>&1
    $dx ip netns exec b4-1 ip link set ds-lite mtu 1500 >/dev/null 2>&1
    $dx ip netns exec b4-2 ip link set ds-lite mtu 1500 >/dev/null 2>&1
    # (j) clear the stand-in RBL block T3 leaves on the server-router
    #     (drop rule on the shared public IPv4) so it does not black-hole
    #     subscriber traffic for the next attack.
    $dx ip netns exec server-router nft flush chain ip filter forward >/dev/null 2>&1
    sleep 1
}

# ── restore_lab: user-facing "reset to clean baseline" (no restart) ──
# Turns OFF every defense, clears all attack residue (reset_aftr_state), heals the
# management plane, and verifies health — so you can keep experimenting without
# Ctrl-C + rebuild. Safe to run any time; idempotent.
restore_lab() {
    local dx="docker exec $CONTAINER_NAME"
    hdr "Restoring lab to clean baseline"
    # 1. turn off every mitigation (idempotent; covers manual toggles). The PCP
    #    defenses (PCP_OWNERSHIP/PCP_QUOTA/PCP_AUTH) are cleared by reset_aftr_state
    #    below, which restarts the PCP server + proxies with no defense env, so
    #    they are not swept here (avoids a redundant triple PCP restart).
    say "Disabling all defenses ..."
    local d
    for d in SAVI FEISTEL_IPID DNS_0X20 TRABELSI ESP_AEAD NAT_LOG SNMP_USM DHCPV6_AUTH; do
        CONTAINER_NAME="$CONTAINER_NAME" bash "$AP_HOST" "$d" off >/dev/null 2>&1
    done
    # 2. clear all attack residue (PCP pool, conntrack, poisoned caches, tunnels,
    #    attack tools, stateless_fw, AFTR-name, ::b4N addresses ...)
    say "Clearing attack residue ..."
    reset_aftr_state
    # 3. heal the management plane (state not covered by reset_aftr_state)
    say "Healing management + services ..."
    $dx ip netns exec aftr nft flush table bridge savi >/dev/null 2>&1
    $dx ip netns exec aftr sh -c 'nft -a list chain inet mgmt_acl input 2>/dev/null \
        | awk "/10.99.0.0\/24/{for(i=1;i<=NF;i++) if(\$i==\"handle\") print \$(i+1)}" \
        | xargs -r -n1 nft delete rule inet mgmt_acl input handle' >/dev/null 2>&1
    # restart the SNMP agent if it died, and reset the alarm threshold to default 60
    $dx ip netns exec aftr sh -c 'ss -ulnp 2>/dev/null | grep -q ":161 " \
        || (python3 -u /testbed/aftr/snmp_agent.py --host 10.99.0.1 --port 161 --community public >/var/log/snmp-agent.log 2>&1 &)' >/dev/null 2>&1
    sleep 1
    $dx ip netns exec mgmt snmpset -v2c -c public -t1 10.99.0.1 1.3.6.1.2.1.240.1.3.1.1 u 60 >/dev/null 2>&1
    # ensure the public HTTP + DNS test services are alive
    $dx ip netns exec server  sh -c 'ss -tlnp 2>/dev/null | grep -q ":80 " || true' >/dev/null 2>&1
    # 4. report health
    local c1 c2
    c1=$($dx ip netns exec client1 sh -c "curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://198.51.100.2/ 2>/dev/null")
    c2=$($dx ip netns exec client2 sh -c "curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://198.51.100.2/ 2>/dev/null")
    kv "Defenses:" "all off"
    kv "client1:"  "HTTP ${c1:-???}"
    kv "client2:"  "HTTP ${c2:-???}"
    if [ "$c1" = 200 ] && [ "$c2" = 200 ]; then ok "lab restored to clean baseline"
    else warn "subscribers not both 200 — run 'Settings → connectivity test' for detail"; fi
}

# ── Run one attack in a single narrated terminal ───────────────────────────
# All per-attack logic lives in ONE place now: testbed/scripts/attack_lib.sh
# (sourced by run_attack_live.sh). This streams the narration into THIS
# terminal, captures at the reference points, saves to ./pcaps/runs/, and
# prints a MATCH/DIFFERS verdict against the stored ground truth in
# ./pcaps/per_attack/<id>/. No extra windows are opened.
run_attack() {
    local id="$1"; shift
    # The in-container banner (run_attack_live.sh) already prints the attack name,
    # the save path, and the ground-truth path, so no wrapper header is printed
    # here (it would only duplicate that, sometimes with a drifted name).
    docker exec -it "$CONTAINER_NAME" bash /testbed/scripts/run_attack_live.sh "$id" "$@"
    echo
    read -erp "  Press Enter to continue " _
}

# Ask for an attack's knobs; echoes "key=val ..." (empty = run with defaults).
# Knob specs come from attack_lib.sh so run.sh never duplicates a parameter.
# Ask for an attack's knobs with plain prompts (the palette has already exited to
# the normal terminal here). Prompts go to /dev/tty; only the resolved
# "key=val ..." string is printed to stdout (empty = run with defaults).
_resolve_knobs() {
    local id="$1" kspec
    kspec=$(docker exec "$CONTAINER_NAME" bash -c "source /testbed/scripts/attack_lib.sh; knobs_$id 2>/dev/null" 2>/dev/null)
    [ -z "$(printf '%s' "$kspec" | tr -d ' ')" ] && return 0   # this attack has no knobs
    stty sane 2>/dev/null || true
    local yn=""
    printf '\n  %s — Enter to run with proven defaults, or type c to customize: ' "$id" >/dev/tty
    read -r yn </dev/tty || true
    case "$yn" in c|C|custom*) : ;; *) return 0 ;; esac
    local out="" OIFS="$IFS" kv kn kvals def alts val
    IFS=';'
    for kv in $kspec; do
        IFS=':' read -r kn kvals <<EOF
$kv
EOF
        kn=$(printf '%s' "$kn" | tr -d ' '); [ -z "$kn" ] && { IFS=';'; continue; }
        def="${kvals%%|*}"
        alts=""; [ "$kvals" != "$def" ] && alts="  (options: $(printf '%s' "$kvals" | tr '|' '/'))"
        printf '    %s [%s]%s: ' "$kn" "$def" "$alts" >/dev/tty
        IFS= read -r val </dev/tty || true
        val="${val:-$def}"
        out="$out $kn=$val"
        IFS=';'
    done
    IFS="$OIFS"
    printf '%s' "$out"
}

# ── Resolve IPs and show lab info ──────────────────────────────────
resolve_lab_ips
hdr "Lab ready"
kv "Attacker:" "${ATTACKER_PLACEMENT:-none}"
[ -n "$ATK_IP4" ] && kv "Attacker IPv4:" "$ATK_IP4"
[ -n "$ATK_IP6" ] && kv "Attacker IPv6:" "$ATK_IP6"
[ -n "$B4_1_IP6" ] && kv "B4-1 IPv6:" "$B4_1_IP6"
[ -n "$B4_2_IP6" ] && kv "B4-2 IPv6:" "$B4_2_IP6"
kv "Web (host):" "http://localhost:8080"
kv "Pcaps:" "$PCAP_DIR/"

# article_defenses.sh is the single defense dispatcher (each toggle implements the
# attack's grounding-article mechanism, or the RFC where no article exists).
# restore_lab uses it to force every mitigation OFF (the lab's vulnerable
# baseline). The interactive Defense menu has been removed.
AP_HOST="$(pwd)/testbed/defenses/article_defenses.sh"

# ── Interactive attack menu ────────────────────────────────────────
# Make doubly sure terminal echo + canonical mode are on. Some prior
# processes (notably tcpdump bursts, scapy raw sockets) can leave the
# tty in raw mode, in which case `read` sees no echo and the user
# thinks the prompt is unresponsive.
stty sane 2>/dev/null || true
stty echo icanon 2>/dev/null || true

if [ -n "$TERM_EMU" ]; then
    dbg "type into THIS terminal; if keys don't echo, click here to refocus"

    # ── Command-palette front-end (ds_menu.py) ──────────────────────────
    PY_MENU="$(pwd)/testbed/scripts/ds_menu.py"
    # Use the palette only when (a) it is not disabled by DS_LITE_NO_PALETTE,
    # (b) prompt_toolkit and the menu script are present, and (c) a controlling
    # terminal exists. The palette reads from /dev/tty, so without a real tty
    # (piped stdin, CI, nohup) it would fail with "/dev/tty: No such device";
    # in that case we fall back to the legacy numbered menu, which is EOF-safe.
    _have_palette() { [ -z "$DS_LITE_NO_PALETTE" ] && ( exec </dev/tty ) 2>/dev/null \
                      && python3 -c 'import prompt_toolkit' 2>/dev/null && [ -f "$PY_MENU" ]; }
    # Open the right live-monitor window for a surface token.
    _open_monitor() {
        case "$1" in
            nat)      open_monitor_terminal "Monitor-NAT"      aftr       /testbed/aftr/monitor_nat.sh ;;
            softwire) open_cmd_terminal     "Monitor-Softwire" aftr       "echo 'AFTR softwire (IPv4-in-IPv6, proto 4) on eth-isp:'; tcpdump -ni eth-isp 'ip6 proto 4'" ;;
            frag)     open_cmd_terminal     "Monitor-Frag"     aftr       "watch -n1 \"grep -E 'Ip6Reasm|Ip6Frag' /proc/net/snmp6\"" ;;
            pcp)      open_cmd_terminal     "Monitor-PCP"      aftr       "echo 'AFTR PCP control (udp/5351) on eth-isp + live mappings:'; tcpdump -ni eth-isp 'udp port 5351'" ;;
            dns)      open_cmd_terminal     "Monitor-DNS"      dns-server "echo 'Resolver DNS on eth-isp:'; tcpdump -ni eth-isp 'udp port 53'" ;;
            dhcp)     open_cmd_terminal     "Monitor-DHCPv6"   b4-1       "echo 'B4-1 DHCPv6 (546/547) on eth-isp:'; tcpdump -ni eth-isp '(udp port 546 or udp port 547)'" ;;
            snmp)     open_cmd_terminal     "Monitor-SNMP"     aftr       "echo 'AFTR SNMP (OAM, udp/161):'; tcpdump -ni any 'udp port 161'" ;;
            victim)   open_cmd_terminal     "Monitor-Victim"   client1    "python3 /testbed/attack_tools/victim_test.py" ;;
            *)        say "No monitor selected." ;;
        esac
    }

    # Pick a device + interface, then open a Wireshark capture on it.
    _capture_wireshark() {
        local cdev cif iflist
        cdev=$(python3 "$PY_MENU" shell "${ATTACKER_PLACEMENT:-none}" </dev/tty | tr ' ' '\n' | grep -vx '__all__' | head -1)
        [ -z "$cdev" ] && { say "No device selected."; return; }
        iflist=$(docker exec "$CONTAINER_NAME" ip netns exec "$cdev" ip -br link 2>/dev/null \
                 | awk '$1!="lo"{split($1,a,"@"); print a[1]}')
        cif=$(printf 'any\tall interfaces\n%s\n' "$iflist" | python3 "$PY_MENU" choose "Interface on $cdev")
        if [ -n "$cif" ]; then start_wireshark "$cdev" "$cif"; else say "No interface selected."; fi
    }

    # Open every device shell at once (the hands-on workbench).
    _open_workbench() {
        hdr "Workbench - all device shells"
        if [ -z "$ATTACKER_PLACEMENT" ]; then
            say "No attacker placed - choose where the attack console sits:"
            local wp; wp=$(python3 "$PY_MENU" placement "none" </dev/tty)
            case "$wp" in ""|none) say "continuing without an attacker console" ;; *) move_attacker "$wp" ;; esac
        fi
        for d in aftr b4-1 b4-2 client1 client2 dns-server mgmt; do open_terminal "$d" "$d"; done
        [ -n "$ATTACKER_PLACEMENT" ] && open_terminal "attacker (attack console)" "attacker"
        _print_manual_cheatsheet
        ok "workbench open - attack by hand from the attacker window"
    }

    if _have_palette; then
        dbg "palette: type to filter | Up/Dn move | Enter select | Esc back"
        while true; do
            action=$(python3 "$PY_MENU" main "${ATTACKER_PLACEMENT:-none}" "" </dev/tty)
            case "$action" in
                attack)
                    aid=$(python3 "$PY_MENU" attacks "${ATTACKER_PLACEMENT:-none}" </dev/tty)
                    if [ -n "$aid" ]; then
                        knobs=$(_resolve_knobs "$aid")
                        run_attack "$aid" $knobs
                    fi ;;
                defenses)
                    did=$(python3 "$PY_MENU" defenses "${ATTACKER_PLACEMENT:-none}" </dev/tty)
                    case "$did" in
                        "") : ;;
                        __alloff__)
                            hdr "Defenses"
                            say "Turning all defenses off (vulnerable baseline) ..."
                            for _D in TRABELSI NAT_LOG SAVI ESP_AEAD FEISTEL_IPID PCP_QUOTA \
                                      PCP_OWNERSHIP PCP_AUTH DNS_0X20 DHCPV6_AUTH SNMP_USM; do
                                bash "$AP_HOST" "$_D" off >/dev/null 2>&1
                            done
                            ok "all defenses off"
                            read -erp "  Press Enter to continue " _ ;;
                        *)
                            st=$(python3 "$PY_MENU" onoff "$did" </dev/tty)
                            case "$st" in
                                on|off)
                                    hdr "Defense: $did $st"
                                    bash "$AP_HOST" "$did" "$st" 2>&1 | sed 's/^/  /'
                                    ok "now re-run the matching attack from the Attack menu to see the effect"
                                    read -erp "  Press Enter to continue " _ ;;
                                *) : ;;
                            esac ;;
                    esac ;;
                watch)
                    sel=$(python3 "$PY_MENU" watch "${ATTACKER_PLACEMENT:-none}" </dev/tty)
                    case "$sel" in
                        "")        : ;;
                        wireshark) hdr "Wireshark capture"; _capture_wireshark; read -erp "  Press Enter to continue " _ ;;
                        *)         hdr "Live monitor"; _open_monitor "$sel" ;;
                    esac ;;
                shell)
                    nslist=$(python3 "$PY_MENU" shell "${ATTACKER_PLACEMENT:-none}" </dev/tty)
                    case " $nslist " in
                        *" __all__ "*)
                            _open_workbench
                            read -erp "  Press Enter to continue " _ ;;
                        *)
                            for ns in $nslist; do open_terminal "$ns" "$ns"; done ;;
                    esac ;;
                restore)
                    restore_lab
                    read -erp "  Press Enter to continue " _ ;;
                settings)
                    s=$(python3 "$PY_MENU" settings "${ATTACKER_PLACEMENT:-none}" </dev/tty)
                    case "$s" in
                        placement)
                            p=$(python3 "$PY_MENU" placement "${ATTACKER_PLACEMENT:-none}" </dev/tty)
                            case "$p" in ""|none) : ;; *) move_attacker "$p" ;; esac ;;
                        conntest)
                            hdr "Connectivity test"
                            docker exec "$CONTAINER_NAME" /testbed/scripts/test_connectivity.sh
                            read -erp "  Press Enter to continue " _ ;;
                    esac ;;
                quit|"") break ;;
            esac
        done
    else
    # ── legacy numbered menu (prompt_toolkit unavailable) ───────────────
    while true; do
        echo ""
        show_attack_menu
        echo ""
        read -erp "  Select [1-${MENU_COUNT}, p/d/v/m/t/s/g/r, 0=exit]: " ATK_CHOICE
        # (d = Defenses submenu; handled in the case below)
        # If read returns EOF (stdin closed or piped from an exited subshell),
        # don't loop forever printing the menu — exit cleanly.
        if [ $? -ne 0 ] && [ -z "$ATK_CHOICE" ]; then
            echo "  [stdin closed — exiting attack menu]"
            break
        fi
        case "$ATK_CHOICE" in
            0|q|Q) break ;;
            p|P)
                reposition_menu
                ;;
            d|D)
                defense_menu
                ;;
            v|V)
                dbg "Launching Victim Monitor..."
                open_cmd_terminal "Victim-Monitor" client1 \
                    "python3 /testbed/attack_tools/victim_test.py"
                ;;
            m|M)
                dbg "Launching AFTR Monitor..."
                open_monitor_terminal "AFTR-Monitor" aftr /testbed/aftr/monitor_nat.sh
                ;;
            t|T)
                echo "  Running connectivity tests..."
                docker exec "$CONTAINER_NAME" /testbed/scripts/test_connectivity.sh
                ;;
            s|S)
                echo "  Generating sample traffic across every protocol..."
                docker exec "$CONTAINER_NAME" bash /testbed/scripts/sample-traffic.sh
                ;;
            g|G)
                echo "  The canonical attack-defence trees are the QuADTool export in"
                echo "  testbed/attack_trees/ (figures/ + quadtool/), with the verified"
                echo "  article-grounded defences. Regenerate them on the host with:"
                echo "    bash results/adtool_trees/render_with_quadtool.sh   # render"
                echo "    bash testbed/attack_trees/export.sh                 # export here"
                echo "  (Tree structure + defences: results/adtool_trees/build_trees.py)"
                ;;
            r|R)
                echo "  Per-run attack results are saved under ./pcaps/runs/<UTC>_<Tn>/"
                echo "  (each holds RESULT.txt with the measured signal + MATCH/DIFFERS"
                echo "  verdict, plus the per-point pcaps). Latest runs:"
                ls -1dt "$(pwd)"/pcaps/runs/*_T* 2>/dev/null | head -10 | sed 's|.*/pcaps|    pcaps|' \
                    || echo "    (no runs yet — launch an attack first)"
                ;;
            "")  continue ;;
            *)
                if [[ "$ATK_CHOICE" =~ ^[0-9]+$ ]] && [ "$ATK_CHOICE" -ge 1 ] \
                   && [ "$ATK_CHOICE" -le "$MENU_COUNT" ]; then
                    run_attack "${MENU_IDS[$ATK_CHOICE]}" || true
                else
                    echo "  Invalid selection: $ATK_CHOICE"
                fi
                ;;
        esac
    done
    fi
fi

# The menu loop exits only on an explicit Quit (or stdin close). In both cases
# the user is done, so clean up immediately — stop the lab if we started it,
# leave it running if we merely reattached — and exit. (No "press Ctrl+C" wait:
# Quit means quit.) cleanup() ends with `exit 0`.
cleanup
