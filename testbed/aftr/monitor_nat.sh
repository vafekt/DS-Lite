#!/bin/bash
# ================================================================
# AFTR NAT Monitor – DS-Lite / RFC 6333
# Runs inside the AFTR namespace.
# Shows current NAT state, press Enter to refresh, Ctrl+C to exit.
# ================================================================

# ── Colors ──────────────────────────────────────────────────────
C='\033[0;36m'; G='\033[0;32m'; Y='\033[1;33m'
R='\033[0;31m'; B='\033[1m'; D='\033[2m'; N='\033[0m'

# ── Build softwire-ID maps once (tunnels don't change at runtime) ─
declare -A TNL_TO_B4
for tnl_raw in $(ip -o link show type ip6tnl 2>/dev/null | awk -F': ' '{print $2}'); do
    tnl="${tnl_raw%%@*}"
    rv6=$(ip -6 tunnel show "$tnl" 2>/dev/null | grep -oP 'remote \K[0-9a-f:]+')
    [[ -z "$rv6" || "$rv6" == "::" ]] && continue
    TNL_TO_B4["$tnl"]="$rv6"
done

# Fixed ct marks for named tunnels (set by ip mangle table)
declare -A MARK_TO_B4
for tnl in "${!TNL_TO_B4[@]}"; do
    case "$tnl" in
        ds-lite-b4-1) MARK_TO_B4[1]="${TNL_TO_B4[$tnl]}" ;;
        ds-lite-b4-2) MARK_TO_B4[2]="${TNL_TO_B4[$tnl]}" ;;
    esac
done

# Detect IPv6 prefix from known B4 tunnels for reconstructing
# outer IPv6 from the last-32-bits stored in ct mark.
IPV6_PREFIX=""
for v6 in "${TNL_TO_B4[@]}"; do
    IPV6_PREFIX=$(echo "$v6" | sed 's/::[^:]*$/::/; s/:[0-9a-f]*$/:/')
    break
done

# Resolve Softwire-ID from ct mark
#   mark 1/2  = named tunnel -> known B4 IPv6
#   mark 3    = ds-lite-open, no outer IPv6 captured
#   mark > 3  = last 32 bits of outer IPv6 src (captured by ip6 mangle)
lookup_softwire() {
    local ip="$1" mark="$2"
    if [ -n "$mark" ] && [ "$mark" != "0" ] && [ -n "${MARK_TO_B4[$mark]+_}" ]; then
        echo "${MARK_TO_B4[$mark]}"
        return
    fi
    if [ -n "$mark" ] && [ "$mark" -gt 3 ] 2>/dev/null; then
        local hi=$(( (mark >> 16) & 0xffff ))
        local lo=$(( mark & 0xffff ))
        printf "%s%x:%x" "$IPV6_PREFIX" "$hi" "$lo"
        return
    fi
    local dev
    dev=$(ip route get "$ip" 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    if [ -n "$dev" ] && [ -n "${TNL_TO_B4[$dev]+_}" ]; then
        echo "${TNL_TO_B4[$dev]}"
    elif [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|192\.0\.0\.) ]]; then
        echo "ds-lite-open"
    fi
}

CT_MAX=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 65536)

# ── Render one frame ───────────────────────────────────────────
render() {
    clear

    printf "${B}  AFTR NAT Monitor  (DS-Lite / RFC 6333)       $(date '+%H:%M:%S')${N}\n\n"

    # -- 1. Conntrack summary --
    CT_DUMP=$(conntrack -L -o extended 2>/dev/null)
    CT_COUNT=$(echo "$CT_DUMP" | grep -c '^' 2>/dev/null || echo 0)
    [ "$CT_COUNT" -eq 0 ] && CT_COUNT=$(conntrack -C 2>/dev/null || echo 0)
    CT_MAX_NOW=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo "$CT_MAX")
    if [ "$CT_MAX_NOW" -gt 0 ] 2>/dev/null; then CT_PCT=$((CT_COUNT*100/CT_MAX_NOW)); else CT_PCT=0; fi
    if   [ "$CT_PCT" -ge 90 ]; then CC="$R"
    elif [ "$CT_PCT" -ge 70 ]; then CC="$Y"
    else CC="$G"; fi

    BAR_W=30; FILLED=$((CT_PCT * BAR_W / 100))
    BAR=$(printf "%${FILLED}s" | tr ' ' '#')$(printf "%$((BAR_W - FILLED))s" | tr ' ' '.')
    printf "  ${C}Conntrack${N}  ${CC}${CT_COUNT}${N} / ${CT_MAX_NOW}  ${CC}[${BAR}] ${CT_PCT}%%${N}\n"

    TCP_CT=$(echo "$CT_DUMP" | grep -c 'tcp' 2>/dev/null); TCP_CT=${TCP_CT:-0}
    UDP_CT=$(echo "$CT_DUMP" | grep -c 'udp' 2>/dev/null); UDP_CT=${UDP_CT:-0}
    ESTAB=$(echo "$CT_DUMP" | grep -c 'ESTABLISHED' 2>/dev/null); ESTAB=${ESTAB:-0}
    SYN=$(echo "$CT_DUMP" | grep -c 'SYN_SENT' 2>/dev/null); SYN=${SYN:-0}
    UNREP=$(echo "$CT_DUMP" | grep -c 'UNREPLIED' 2>/dev/null); UNREP=${UNREP:-0}
    TW=$(echo "$CT_DUMP" | grep -c 'TIME_WAIT' 2>/dev/null); TW=${TW:-0}
    printf "  TCP ${TCP_CT}  UDP ${UDP_CT}    ${G}ESTAB=${ESTAB}${N}  ${Y}SYN=${SYN}${N}  ${R}UNREP=${UNREP}${N}  TW=${TW}\n"

    # Alerts
    [ "$CT_PCT" -ge 90 ] && printf "\n  ${R}[!] Conntrack near full (${CT_PCT}%%) -- T1 NAT exhaustion${N}\n"
    [ "$ESTAB" -gt 100 ] 2>/dev/null && printf "  ${R}[!] High ESTABLISHED (${ESTAB}) -- T4 Slowloris / T1-Hold${N}\n"
    [ "$UNREP" -gt 500 ] 2>/dev/null && printf "  ${R}[!] High UNREPLIED (${UNREP}) -- UDP flood / T8 fragment${N}\n"
    echo ""

    # -- 2. Top sources --
    printf "  ${C}Top Sources${N}\n"
    TOP_SRC=$(echo "$CT_DUMP" | awk '{
        ip=""; mark=""
        match($0,/src=[0-9.]+/); ip=substr($0,RSTART+4,RLENGTH-4)
        if (match($0,/mark=[0-9]+/)) mark=substr($0,RSTART+5,RLENGTH-5)
        if (ip != "") print ip, mark
    }' | sort | uniq -c | sort -rn | head -5)
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        cnt=$(echo "$line" | awk '{print $1}')
        sip=$(echo "$line" | awk '{print $2}')
        smk=$(echo "$line" | awk '{print $3}')
        sw=$(lookup_softwire "$sip" "$smk")
        [ -z "$sw" ] && sw="-"
        if [ "$cnt" -gt 50 ] 2>/dev/null; then
            printf "  ${R}%6d  %-15s  %s${N}\n" "$cnt" "$sip" "$sw"
        else
            printf "  %6d  %-15s  %s\n" "$cnt" "$sip" "$sw"
        fi
    done <<< "$TOP_SRC"
    echo ""

    # -- 3. NAT Bindings (last 15) --
    printf "  ${C}NAT Bindings${N}  ${D}(last 15)${N}\n"
    printf "  ${D}Softwire-ID              Inner-Src       P   SPort  -> Outside         DPort  TTL    State${N}\n"
    TAIL_CT=$(echo "$CT_DUMP" | tail -15)
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        proto=$(echo "$line" | awk '{print $3}')
        timeout=$(echo "$line" | awk '{print $5}')
        state=$(echo "$line" | grep -oE 'ESTABLISHED|SYN_SENT|SYN_RECV|TIME_WAIT|CLOSE_WAIT|FIN_WAIT|UNREPLIED|ASSURED|CLOSE' | head -1)
        src=$(echo "$line"  | grep -oP 'src=\K[0-9.]+' | head -1)
        sport=$(echo "$line" | grep -oP 'sport=\K[0-9]+' | head -1)
        rdst=$(echo "$line"  | grep -oP 'dst=\K[0-9.]+' | tail -1)
        rdport=$(echo "$line" | grep -oP 'dport=\K[0-9]+' | tail -1)
        cmk=$(echo "$line" | grep -oP 'mark=\K[0-9]+' | head -1)
        sw=$(lookup_softwire "$src" "$cmk")
        [ -z "$sw" ] && sw="(?)"
        p=$(echo "$proto" | tr 'a-z' 'A-Z')
        case "$state" in
            ESTABLISHED) sc="${G}" ;; UNREPLIED) sc="${R}" ;; SYN_SENT|SYN_RECV) sc="${Y}" ;; *) sc="" ;;
        esac
        printf "  %-24s %-15s %-3s %5s  -> %-15s %5s  %5ss  ${sc}%s${N}\n" \
            "$sw" "$src" "$p" "$sport" "$rdst" "$rdport" "$timeout" "${state:--}"
    done <<< "$TAIL_CT"
    echo ""

    # -- 4. nftables counters --
    NFT_RAW=$(nft list ruleset 2>/dev/null | grep 'counter packets')
    HAS_NFT=0
    NFT_BUF=""
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        pkts=$(echo "$line" | grep -oP 'packets \K[0-9]+' || echo 0)
        [ "${pkts:-0}" -eq 0 ] && continue
        label=$(echo "$line" | grep -oP 'prefix "\K[^"]+')
        bytes=$(echo "$line" | grep -oP 'bytes \K[0-9]+' || echo 0)
        bytesh=$(numfmt --to=iec "$bytes" 2>/dev/null || echo "${bytes}B")
        HAS_NFT=1
        if echo "$label" | grep -q 'DROP\|EXCESS'; then
            NFT_BUF+="$(printf "  ${R}%-32s  pkts=%-8s  %s${N}" "$label" "$pkts" "$bytesh")"$'\n'
        else
            NFT_BUF+="$(printf "  %-32s  pkts=%-8s  %s" "$label" "$pkts" "$bytesh")"$'\n'
        fi
    done <<< "$NFT_RAW"
    if [ "$HAS_NFT" -eq 1 ]; then
        printf "  ${C}nftables Counters${N}  ${D}(non-zero only)${N}\n"
        while IFS= read -r nline; do
            [ -n "$nline" ] && printf '%b\n' "$nline"
        done <<< "$NFT_BUF"
        echo ""
    fi

    # -- 5. PCP + Fragments --
    PCP_N=$(nft list chain ip nat pcp_dnat 2>/dev/null | grep -c 'dnat' || echo 0)
    FRAG_OK=$(awk '/Ip6ReasmOKs/{print $2}' /proc/net/snmp6 2>/dev/null || echo 0)
    FRAG_FAIL=$(awk '/Ip6ReasmFails/{print $2}' /proc/net/snmp6 2>/dev/null || echo 0)

    EXTRA=""
    [ "$PCP_N" -gt 0 ] && EXTRA+="PCP-DNAT=${PCP_N}  "
    [ "${PCP_N:-0}" -gt 100 ] 2>/dev/null && EXTRA+="${R}[!PCP]${N}  "
    [ "$FRAG_OK" -gt 0 ] || [ "$FRAG_FAIL" -gt 0 ] && \
        EXTRA+="Frag: ${G}OK=${FRAG_OK}${N} ${R}Fail=${FRAG_FAIL}${N}  "
    [ "${FRAG_FAIL:-0}" -gt 100 ] 2>/dev/null && EXTRA+="${R}[!T8]${N}  "
    [ -n "$EXTRA" ] && printf "  ${C}Services${N}  ${EXTRA}\n"

    printf "\n  ${D}Press Enter to refresh  |  Ctrl+C to exit${N}\n"
}

# ── Main: show once, then refresh on Enter ─────────────────────
render
while read -r; do
    render
done
