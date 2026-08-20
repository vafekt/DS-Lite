#!/bin/bash
# measure_isolation_load.sh - co-resident isolation under CONTINUOUS LOAD.
# Beyond the 1 Hz liveness probe of verify_all.sh, this drives a co-resident
# subscriber (client2, behind a second B4) with back-to-back requests and
# reports success rate and latency, during the shared-pool drain (T12) with
# source validation OFF then ON, plus a no-attack baseline. Run from the host:
#   CONTAINER_NAME=ds-lite-lab bash testbed/defenses/measure_isolation_load.sh
set -u
C="${CONTAINER_NAME:-ds-lite-lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"
AP="$HERE/article_defenses.sh"
CP=2001:db8:cafe; AFTR=$CP::10; ATK6=$CP::13a; SRV=198.51.100.2; T=/testbed/attack_tools
dx(){ docker exec "$C" "$@"; }
nse(){ docker exec "$C" ip netns exec "$@"; }

prov_attacker(){ nse attacker ip link show eth-isp >/dev/null 2>&1 || dx sh -c '
  ip netns add attacker 2>/dev/null
  ip link add eth-isp-atk type veth peer name atk-br 2>/dev/null
  ip link set eth-isp-atk netns attacker 2>/dev/null
  ip netns exec attacker ip link set eth-isp-atk name eth-isp 2>/dev/null
  ip link set atk-br master br-isp 2>/dev/null; ip link set atk-br up 2>/dev/null
  ip netns exec attacker ip link set lo up 2>/dev/null
  ip netns exec attacker ip link set eth-isp up 2>/dev/null
  ip netns exec attacker ip -6 addr add '"$ATK6"'/64 dev eth-isp 2>/dev/null'; }
hub_bridge(){ dx ip link set br-isp type bridge ageing_time 0 2>/dev/null
  dx sh -c 'for p in b41-br b42-br aftr-br atk-br dns-br dhcp6s-br; do bridge link set dev $p flood on mcast_flood on 2>/dev/null; done'; }
pool(){ nse aftr conntrack -L 2>/dev/null | grep -c "dst=$SRV.*dport=80"; }
reset(){ nse aftr conntrack -F >/dev/null 2>&1; nse attacker pkill -9 -f nat_exhaustion 2>/dev/null; sleep 1.5; }
flood(){ nse attacker sh -c "timeout 60 python3 $T/nat/nat_exhaustion.py eth-isp --tunnel --src-ip6-prefix ${CP}:dead::/64 --fixed-dport 80 --proto tcp --dst-ip4 $SRV --aftr-ip6 $AFTR --inner-src-prefix 10.90.0.0/16 --threads 8 --batch 256 >/dev/null 2>&1" & }
measure(){ for i in $(seq 1 20); do nse client2 curl -s -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 2 http://$SRV/ 2>/dev/null; done; }
stats(){ python3 -c '
import sys,statistics as st
codes=[];times=[]
for l in sys.stdin:
  p=l.split()
  if len(p)==2: codes.append(p[0]); times.append(float(p[1])*1000)
ok=sum(1 for c in codes if c=="200"); n=len(codes) or 1
ts=sorted(times); med=st.median(times) if times else 0; p95=ts[min(int(0.95*len(ts)),len(ts)-1)] if ts else 0
print(f"  n={len(codes)}  success={100*ok/n:.0f}%  median={med:.0f}ms  p95={p95:.0f}ms")'; }

prov_attacker; hub_bridge
nse aftr sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done' 2>/dev/null

echo "== Baseline (no attack) =="; bash "$AP" SAVI off >/dev/null 2>&1; reset; measure | stats
echo "== T12 shared-pool drain, SAVI OFF (isolation break) =="; reset; flood
for i in $(seq 1 12); do sleep 2.5; [ "$(pool)" -gt 60000 ] && break; done
echo "  co-resident under load at pool=$(pool):"; measure | stats; reset
echo "== T12 shared-pool drain, SAVI ON (restored) =="; bash "$AP" SAVI on >/dev/null 2>&1; reset; flood; sleep 20
echo "  co-resident under load at pool=$(pool):"; measure | stats; reset
bash "$AP" SAVI off >/dev/null 2>&1
