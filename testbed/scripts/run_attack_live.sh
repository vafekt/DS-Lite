#!/bin/bash
# run_attack_live.sh — run ONE DS-Lite attack in ONE narrated terminal.
#
# Usage (host):  docker exec -it ds-lite-lab \
#                  bash /testbed/scripts/run_attack_live.sh T1 intensity=fast target=198.51.100.2
#
# Sources attack_lib.sh (the single per-attack registry), captures at the same
# points the reference used, narrates each step, measures the outcome signal,
# compares to the stored ground truth, and saves the run under pcaps/runs/.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=attack_lib.sh
source "$HERE/attack_lib.sh"

ID="${1:-}"; [ $# -gt 0 ] && shift
if [ -z "$ID" ] || ! declare -f "do_$ID" >/dev/null 2>&1; then
    echo "usage: run_attack_live.sh <T1..T15> [knob=value ...]"
    echo "unknown or missing attack id: '${ID:-}'"
    exit 2
fi

# ── resolve knobs: defaults from knobs_<ID>, then KEY=VAL overrides ─────────
if declare -f "knobs_$ID" >/dev/null 2>&1; then
    kspec="$("knobs_$ID")"
    OIFS="$IFS"; IFS=';'
    for kv in $kspec; do
        IFS=':' read -r kn kdv <<EOF
$kv
EOF
        kn="$(echo "$kn" | tr -d ' ')"; [ -z "$kn" ] && continue
        up="$(echo "$kn" | tr '[:lower:]' '[:upper:]')"
        export "KNOB_$up=${kdv%%|*}"
    done
    IFS="$OIFS"
fi
for arg in "$@"; do
    [ "$arg" = "${arg#*=}" ] && continue
    up="$(echo "${arg%%=*}" | tr '[:lower:]' '[:upper:]')"
    export "KNOB_$up=${arg#*=}"
done

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="/testbed/pcaps/runs/${TS}_${ID}"
mkdir -p "$OUT"
RESULT="$OUT/RESULT.txt"

VERDICT_PASS=0; REF_LINE=""; RUN_LINE=""; CMDS_RUN=""

reset_state
resolve_runtime   # discover live addresses (DHCP/softwire may differ from refs)

# Stream everything below to the terminal AND to RESULT.txt simultaneously.
exec > >(tee "$RESULT") 2>&1

echo "================================================================"
echo "  DS-Lite live attack  $ID  —  $(attack_name "$ID")"
echo "  saving to  ./${OUT#/testbed/}/"
echo "  ground truth (reference) in  ./pcaps/per_attack/$ID/"
echo "================================================================"
echo

"do_$ID" "$OUT"

echo
echo "  --------------------------------------------------------------"
printf '  %-10s %s\n' "reference:" "$REF_LINE"
printf '  %-10s %s\n' "this run:"  "$RUN_LINE"
if [ "${VERDICT_PASS:-0}" = 1 ]; then
    printf '  %-10s MATCH   (attack reproduced the stored result)\n' "verdict:"
else
    printf '  %-10s DIFFERS (did not reproduce — compare numbers above)\n' "verdict:"
fi
echo "  --------------------------------------------------------------"
echo "  saved: ./${OUT#/testbed/}/  (pcaps + config.txt + RESULT.txt)"

write_config "$OUT" "$ID"

# Leave the lab clean and source-validation back on.
urpf on >/dev/null 2>&1
reset_state >/dev/null 2>&1

# let the tee child flush before the shell exits
sync; sleep 0.4
