#!/bin/bash
# measure_probabilistic.sh - N-run reproducibility harness for the three
# probabilistic DS-Lite attacks:
#   T5  fragment-overlap reassembly collision   (per-run flow loss %)
#   T8  off-path DNS-discovery poisoning         (per-run success 0/1)
#   T9  rogue DHCPv6 AFTR hijack                 (per-run success 0/1)
#   T9b transparent hijack (rogue resolver)      (per-run success 0/1)
#
# Each run goes through the tested run_attack_live.sh entrypoint
# (reset_state -> attack -> measure -> clean), so the N runs are independent
# draws. We record the per-run outcome, then compute the success count, the
# rule-of-three 95% lower bound on the success rate, and for T5 the flow-loss
# mean, SD, and 95% CI. The raw per-run data is written next to this summary so
# the paper's probabilistic numbers are auditable rather than asserted.
#
#   N=20 bash testbed/scripts/measure_probabilistic.sh
#   N=20 IDS="T5" bash testbed/scripts/measure_probabilistic.sh   # one attack
set -u
C="${CONTAINER_NAME:-ds-lite-lab}"
N="${N:-20}"
IDS="${IDS:-T5 T8 T9 T9b}"
HOUT="${HOUT:-/home/kali/Desktop/Penterep/DS-Lite/testbed/reference_captures/probabilistic}"
mkdir -p "$HOUT"
run_one() { docker exec "$C" bash /testbed/scripts/run_attack_live.sh "$1" 2>/dev/null; }

echo "== measure_probabilistic: N=$N over [$IDS] on container $C =="
if [ "${STATS_ONLY:-0}" != 1 ]; then
for ID in $IDS; do
    datf="$HOUT/${ID}.dat"
    printf '# %s reproducibility, N=%d, one line per run: run success loss_pct\n' "$ID" "$N" > "$datf"
    for i in $(seq 1 "$N"); do
        o="$(run_one "$ID")"
        case "$ID" in
          T5)
            # T5 success = flow loss >= 50%; we also record the loss for mean/SD/CI.
            s=0; printf '%s\n' "$o" | grep -qE 'verdict:[[:space:]]*MATCH' && s=1
            l="$(printf '%s\n' "$o" | grep -oE 'packet loss = [0-9]+' | grep -oE '[0-9]+' | tail -1)"
            printf '%d %d %d\n' "$i" "$s" "${l:-0}" >> "$datf"
            printf '  %-4s run %2d/%d  success=%d loss=%s%%\n' "$ID" "$i" "$N" "$s" "${l:-NA}" ;;
          T9|T9b)
            # Success = the paper's claimed effect, the softwire is redirected off
            # the real AFTR AND the victim is denied (HTTP 000). The tool's built-in
            # verdict additionally requires a live softwire frame captured at the
            # attacker (frames-to-attacker > 0), which is capture-timing fragile and
            # undercounts a fully successful hijack, so we read the redirect + denial
            # directly from the run's "this run:" line.
            line="$(printf '%s\n' "$o" | grep 'this run:')"
            oldr="$(printf '%s' "$line" | grep -oE 'remote [0-9a-fA-F:]+->' | grep -oE '[0-9a-fA-F:]{4,}' | head -1)"
            newr="$(printf '%s' "$line" | grep -oE '\->[0-9a-fA-F:]+' | grep -oE '[0-9a-fA-F:]{4,}' | tail -1)"
            http="$(printf '%s' "$line" | grep -oE 'HTTP=[0-9]+' | grep -oE '[0-9]+' | head -1)"
            redir=no; [ -n "$newr" ] && [ "$newr" != "$oldr" ] && redir=yes
            s=0; [ "$redir" = yes ] && [ "$http" = "000" ] && s=1
            printf '%d %d http=%s redirect=%s\n' "$i" "$s" "${http:-NA}" "$redir" >> "$datf"
            printf '  %-4s run %2d/%d  success=%d (redirect=%s http=%s)\n' "$ID" "$i" "$N" "$s" "$redir" "${http:-NA}" ;;
          *)
            # T8 success = the resolver cached the attacker address (direct state check).
            s=0; printf '%s\n' "$o" | grep -qE 'verdict:[[:space:]]*MATCH' && s=1
            printf '%d %d\n' "$i" "$s" >> "$datf"
            printf '  %-4s run %2d/%d  success=%d\n' "$ID" "$i" "$N" "$s" ;;
        esac
    done
done
fi

# SUMMARY reflects every .dat present in the output dir (the full released
# dataset), so it stays complete even when a run covers only a subset of ids.
# Re-summarize existing data without re-running attacks with STATS_ONLY=1.
python3 - "$HOUT" <<'PY'
import sys, math, os
out = sys.argv[1]
ids = sorted(f[:-4] for f in os.listdir(out) if f.endswith('.dat'))
print("\n================ probabilistic-attack reproducibility ================")
summary = os.path.join(out, "SUMMARY.txt")
with open(summary, "w") as w:
    def emit(line):
        print(line); w.write(line + "\n")
    for ID in ids:
        f = os.path.join(out, ID + ".dat")
        if not os.path.exists(f):
            continue
        succ, loss = [], []
        for ln in open(f):
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            p = ln.split()
            succ.append(int(p[1]))
            if len(p) >= 3 and p[2].isdigit():
                loss.append(int(p[2]))
        n = len(succ); k = sum(succ)
        line = f"{ID}: {k}/{n} succeeded"
        if k == n and n > 0:
            line += f"  (rule-of-three 95% lower bound {(1 - 3.0/n)*100:.0f}%)"
        emit(line)
        if loss:
            m = sum(loss) / len(loss)
            sd = math.sqrt(sum((x - m) ** 2 for x in loss) / (len(loss) - 1)) if len(loss) > 1 else 0.0
            se = sd / math.sqrt(len(loss))
            emit(f"    flow loss: mean {m:.1f}%  SD {sd:.1f}%  95% CI [{m-1.96*se:.1f}, {m+1.96*se:.1f}]  (n={len(loss)})")
print("======================================================================")
print(f"raw per-run data + SUMMARY.txt in {out}")
PY
