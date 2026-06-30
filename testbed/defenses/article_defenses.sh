#!/bin/bash
# article_defenses.sh — enable/disable a defense that implements the ACTUAL
# mechanism proposed by its grounding research article, adapted to DS-Lite.
#
# This replaces the old apply_defense.sh, where every entry was an RFC/generic
# control (rp_filter, community swap, nft filters, env quotas) with an article
# name only in the comment. Here each defense runs the article's own algorithm.
#
# Each defense supports:  article_defenses.sh <ID> on|off
# and a self-verifying oracle:  article_defenses.sh <ID> oracle   (off-attack-on)
#
# ── Defense registry (ID -> article -> mechanism -> attacks) ─────────────────
#  DHCPV6_AUTH  Albalawi & Aljuhani, "DHCPv6Auth", Sadhana 45:33 (2020)
#               Ed25519-signed DHCPv6 server messages carrying a Signature
#               Authentication (SA) option + Replay-Detection field; the B4
#               verifies the signature before adopting Option 64 (AFTR-Name).
#               -> T12 (Rogue AFTR Substitution), T13 (Transparent AFTR Hijack)
#
#  PCP_OWNERSHIP  Müller & Rytilahti et al., "Peeking Behind NAT Gateways",
#               NDSS 2020 (§Potential Remediations). PCP server enforces
#               ownership binding: a client may only MAP/PEER/THIRD_PARTY an
#               internal address inside its own delegated prefix.
#               -> T8 (Unauthorized THIRD_PARTY Forwarding); T10 (cross-subscriber PEER enumeration)
#
#  (more migrated from apply_defense.sh as each article mechanism is built)
set -u
C="${CONTAINER_NAME:-ds-lite-lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${TOPOLOGY_ENV:-$HERE/topology.env}"
dx()  { docker exec "$C" "$@"; }
dxd() { docker exec -d "$C" "$@"; }
nse() { docker exec "$C" ip netns exec "$@"; }
nsd() { docker exec -d "$C" ip netns exec "$@"; }

if ! docker ps -q -f "name=^${C}$" | grep -q .; then
  echo "article_defenses: container '$C' is not running" >&2; exit 3
fi

KEYDIR=/testbed/defenses/keys
DEF="$1"; STATE="${2:-on}"
AFTR_LEGIT="${AFTR_LEGIT:-aftr.dslite.example.com.}"
AFTR_FILE=/var/run/ds-lite-aftr-name
ISP_IFACE="${ISP_IFACE:-eth-isp}"

# ── DHCPV6_AUTH (T12/T13): Ed25519-signed DHCPv6 (DHCPv6Auth, Sadhana 2020) ──
dhcpv6_auth() {
  case "$1" in
  on)
    dx test -f "$KEYDIR/dhcpv6_ed25519.sec" || \
      dx python3 /testbed/defenses/dhcpv6auth.py keygen --out "$KEYDIR" >/dev/null
    # Replace the unauthenticated acquisition path with the signed one:
    # stop ISC dhcpd6 (legit) + dhclient (B4), start the Ed25519 signing
    # server in the provider and the verifying client on each B4.
    dx pkill -9 -f 'dhcpd -6' 2>/dev/null
    dx pkill -9 -f 'dhcpv6auth.py server' 2>/dev/null; sleep 0.3
    nsd dhcpv6server python3 /testbed/defenses/dhcpv6auth.py server \
        --iface "$ISP_IFACE" --key "$KEYDIR" --aftr "$AFTR_LEGIT" --dns "${DNS_IP6:-2001:db8:cafe::2}"
    sleep 0.5
    _verify_one() {  # <b4ns> ...
      nse "$1" pkill -9 -f "dhclient.*$1" 2>/dev/null
      dx pkill -9 -f "dhclient6-$1" 2>/dev/null
      nse "$1" python3 /testbed/defenses/dhcpv6auth.py client \
          --iface "$ISP_IFACE" --key "$KEYDIR" --wait 4 --aftr-file "$AFTR_FILE" 2>&1 | sed "s/^/[$1] /"
    }
    for_each_b4 _verify_one
    echo "DHCPV6_AUTH on (Ed25519 SA option; rogue DHCPv6 rejected)"
    ;;
  off)
    dx pkill -9 -f 'dhcpv6auth.py server' 2>/dev/null
    # restore the stock unauthenticated ISC dhcpd6 baseline. Kill any existing
    # dhcpd6 first so repeated "off" calls (e.g. restore_lab) stay idempotent
    # and do not stack duplicate dhcpd6 instances.
    dx pkill -9 -f 'dhcpd -6' 2>/dev/null; sleep 0.3
    nsd dhcpv6server /usr/sbin/dhcpd -6 -cf /etc/dhcp/dhcpd6.conf \
        -lf /var/lib/dhcp/dhcpd6.leases -pf /var/run/dhcpd6.pid "$ISP_IFACE" 2>/dev/null
    echo "DHCPV6_AUTH off (stock unauthenticated DHCPv6 restored)"
    ;;
  esac
}

# ── PCP_OWNERSHIP (T8/T10): ownership binding in pcp_server (NDSS 2020) ──────
pcp_ownership() {
  dx ip netns exec aftr pkill -9 -f pcp_server.py 2>/dev/null
  _kill_proxy() { dx ip netns exec "$1" pkill -9 -f pcp_proxy.py 2>/dev/null; }
  for_each_b4 _kill_proxy; sleep 0.5
  local env=""; [ "$1" = on ] && env="T10_THIRD_PARTY_OWNERSHIP_CHECK=1"
  dxd ip netns exec aftr env PCP_POOL_SIZE="${PCP_POOL_SIZE:-1024}" $env python3 /testbed/aftr/pcp_server.py
  _start_proxy() {  # <ns> <lan_ip4> <b4_ip6> ...
    dxd ip netns exec "$1" python3 /testbed/b4/pcp_proxy.py \
        --lan-ip "$2" --b4-ip6 "$3" --aftr-ip6 "$AFTR_IP6" --passthrough-third-party
  }
  for_each_b4 _start_proxy; sleep 2
  echo "PCP_OWNERSHIP $1 (ownership binding: THIRD_PARTY/PEER restricted to requester's prefix)"
}

# ── SNMP_USM (T14/T15): SNMPv3 USM authNoPriv + engineID pinning ────────────
#    Under New Management (WOOT'12): authenticate every request, pin engineID.
snmp_usm() {
  dx ip netns exec aftr pkill -9 -f snmp_agent.py 2>/dev/null; sleep 0.4
  if [ "$1" = on ]; then
    dxd ip netns exec aftr env T_SNMP_USM=1 SNMP_SECRET="${SNMP_SECRET}" \
        SNMP_USM_USER="${SNMP_USM_USER:-oamuser}" \
        python3 -u /testbed/aftr/snmp_agent.py --host "$AFTR_MGMT_IP4" --port "$SNMP_PORT"
    echo "SNMP_USM on (SNMPv3 USM authNoPriv; SNMPv1/v2c dropped; OAM uses snmpv3_client.py)"
  else
    dxd ip netns exec aftr \
        python3 -u /testbed/aftr/snmp_agent.py --host "$AFTR_MGMT_IP4" --port "$SNMP_PORT" \
        --community "${SNMP_PUBLIC:-public}"
    echo "SNMP_USM off (stock SNMPv2c community baseline restored)"
  fi
  sleep 1
}

# ── SAVI (T3/T5/T6): per-port source-address binding on the carrier bridge ──
#    Mechanism from Chen, Liu et al., "SAVI-based IPv6 source address validation
#    implementation of the access network": build a binding (source-IP <-> MAC
#    <-> switch port) and drop packets whose source does not match the binding
#    for the ingress port. The access network is "the best location" to validate.
#    Adapted to DS-Lite: each carrier-bridge port is bound to the softwire/infra
#    source it legitimately owns; a port emitting any OTHER carrier-prefix global
#    source is dropped. This kills the outer-source spoof that T3 (MITM), T5
#    (downstream injection) and T6 (inner-fragment overlap injection) all rely on.
#    Bindings are configured from the provisioned roster here (RFC 7039 permits
#    configured bindings for stable infrastructure); a dynamic deployment would
#    learn them by snooping DHCPv6/ND exactly as the paper describes.
savi() {
  dx nft delete table bridge savi 2>/dev/null
  if [ "$1" != on ]; then
    echo "SAVI off (carrier-bridge source binding removed)"; return
  fi
  # The paper's mechanism is purely the source<->port BINDING enforced at the
  # access switch (here the carrier bridge). No rp_filter: that is RFC uRPF, a
  # different control; keeping SAVI pure lets the off/on oracle attribute the
  # block to the binding alone.
  dx nft add table bridge savi
  dx nft "add chain bridge savi pre { type filter hook prerouting priority -300 ; policy accept ; }"
  local e
  for e in "${B4S[@]}"; do set -- $e
    case "$1" in
      b4-1) _savi_bind b41-br "$3" ;;
      b4-2) _savi_bind b42-br "$3" ;;
    esac
  done
  _savi_bind aftr-br   "$AFTR_IP6"
  _savi_bind dns-br    "$DNS_IP6"
  _savi_bind dhcp6s-br "$DHCP_SERVER_GLOBAL"
  _savi_bind atk-br    "$ATTACKER_IP6"     # access port under test: only its own addr
  echo "SAVI on (per-port carrier-source binding; spoofed outer source dropped)"
}
_savi_bind() {  # <bridge-port> <bound-global-addr>
  dx nft "add rule bridge savi pre iifname $1 ip6 saddr ${CARRIER_PREFIX}::/64 ip6 saddr != $2 counter drop"
}

# ── FEISTEL_IPID (T6): in-path Feistel IP-ID randomisation at the B4 ─────────
#    Gilad & Herzberg 2013 §8.3. nft sends the subscriber's outbound inner-IPv4
#    (about to be encapsulated) to NFQUEUE; feistel_b4.py rewrites the IP-ID with
#    a keyed 3-round Feistel permutation and accepts (in-path, conntrack kept).
feistel_ipid() {
  local st="$1" qn=0 e
  for e in "${B4S[@]}"; do set -- $e
    local ns="$1" net="${2%.*}.0/24" q="$qn"; qn=$((qn+1))
    # pkill scans /proc globally and ignores the netns set by `ip netns exec`,
    # so match the exact per-queue daemon to avoid killing a sibling B4's daemon
    # started in a previous loop iteration (that left only the last B4 protected).
    dx ip netns exec "$ns" pkill -9 -f "feistel_b4.py --queue $q" 2>/dev/null
    dx ip netns exec "$ns" nft delete table ip feistel 2>/dev/null
    if [ "$st" = on ]; then
      dxd ip netns exec "$ns" python3 /testbed/defenses/feistel_b4.py --queue "$q"
      sleep 1.2
      dx ip netns exec "$ns" nft add table ip feistel
      dx ip netns exec "$ns" nft "add chain ip feistel forward { type filter hook forward priority -1 ; policy accept ; }"
      # 'bypass' = if the rewriter daemon is not attached, ACCEPT (never
      # black-hole the subscriber's traffic) instead of dropping.
      dx ip netns exec "$ns" nft "add rule ip feistel forward iifname eth-lan oifname ds-lite ip saddr $net counter queue num $q bypass"
    fi
  done
  echo "FEISTEL_IPID $st (in-path Feistel IP-ID randomisation at each B4)"
}

# ── ESP_AEAD (T4): authenticated-encryption ESP on the softwire ─────────────
#    Degabriele & Paterson, "Attacking the IPsec Standards in Encryption-only
#    Configurations" (IEEE S&P 2007) show ESP WITHOUT integrity (encryption-only)
#    is broken. Their mandate: use AUTHENTICATED encryption. We key transport-mode
#    ESP with AEAD AES-GCM (rfc4106(gcm(aes))) between each B4 and the AFTR, so
#    the 4-in-6 softwire payload is confidential AND integrity-protected — an
#    on-path attacker sees only ESP ciphertext (T4 passive read defeated).
esp_aead() {
  local A="$AFTR_IP6" e
  local KO=0x0123456789abcdef0123456789abcdef11111111   # b4->aftr (16B key+4B salt)
  local KI=0xfedcba9876543210fedcba987654321022222222   # aftr->b4
  _esp_clear() {
    dx ip netns exec aftr ip xfrm policy flush 2>/dev/null
    dx ip netns exec aftr ip xfrm state flush 2>/dev/null
    for e in "${B4S[@]}"; do set -- $e
      dx ip netns exec "$1" ip xfrm policy flush 2>/dev/null
      dx ip netns exec "$1" ip xfrm state flush 2>/dev/null
    done
  }
  _esp_pair() {  # <b4ns> <b4addr> <ospi> <ispi>
    local b4ns=$1 b4=$2 ospi=$3 ispi=$4
    dx ip netns exec aftr ip xfrm state add src "$b4" dst "$A" proto esp spi "$ospi" mode transport aead 'rfc4106(gcm(aes))' "$KO" 128
    dx ip netns exec aftr ip xfrm state add src "$A" dst "$b4" proto esp spi "$ispi" mode transport aead 'rfc4106(gcm(aes))' "$KI" 128
    dx ip netns exec aftr ip xfrm policy add src "$A" dst "$b4" dir out tmpl proto esp mode transport
    dx ip netns exec aftr ip xfrm policy add src "$b4" dst "$A" dir in  tmpl proto esp mode transport
    dx ip netns exec "$b4ns" ip xfrm state add src "$b4" dst "$A" proto esp spi "$ospi" mode transport aead 'rfc4106(gcm(aes))' "$KO" 128
    dx ip netns exec "$b4ns" ip xfrm state add src "$A" dst "$b4" proto esp spi "$ispi" mode transport aead 'rfc4106(gcm(aes))' "$KI" 128
    dx ip netns exec "$b4ns" ip xfrm policy add src "$b4" dst "$A" dir out tmpl proto esp mode transport
    dx ip netns exec "$b4ns" ip xfrm policy add src "$A" dst "$b4" dir in  tmpl proto esp mode transport
  }
  _esp_clear
  if [ "$1" = on ]; then
    for e in "${B4S[@]}"; do set -- $e
      _esp_pair "$1" "$3" "0x${6}001" "0x${6}002"
    done
    echo "ESP_AEAD on (AES-GCM authenticated-encryption ESP on each softwire)"
  else
    echo "ESP_AEAD off (softwire cleartext restored)"
  fi
}

# ── TRABELSI (T1/T7): two-structure session table + early eviction (IEEE Access'18) ─
#    Proactively collapses the half-open (invalid) conntrack timeout so a state-
#    exhaustion flood of UNREPLIED entries ages out in seconds and cannot fill
#    the shared NAT table; ESTABLISHED flows keep their normal timeout.
trabelsi() {
  dx ip netns exec aftr pkill -9 -f trabelsi_guard 2>/dev/null; sleep 0.3
  if [ "$1" = on ]; then
    dxd ip netns exec aftr python3 /testbed/defenses/trabelsi_guard.py \
        --threshold "${TRABELSI_THRESHOLD:-1200}" --dos-timeout "${TRABELSI_TIMEOUT:-1}"
    echo "TRABELSI on (half-open invalid-entry timeout collapsed; established flows intact)"
  else
    # restore kernel defaults (pkill -9 skips the daemon's finally restore)
    dx ip netns exec aftr sysctl -qw \
       net.netfilter.nf_conntrack_tcp_timeout_syn_sent=60 \
       net.netfilter.nf_conntrack_tcp_timeout_syn_recv=60 \
       net.netfilter.nf_conntrack_udp_timeout=30 >/dev/null 2>&1
    echo "TRABELSI off (default conntrack timeouts restored)"
  fi
}

# ── DNS_0X20 (T11): DNS-0x20 case randomisation at the B4 resolver (Dagon CCS'08) ─
#    Runs the 0x20-validating forwarder as the B4's recursive resolver for the
#    AFTR-FQDN path. on = enforce 0x20 (random-case query + reply case-check);
#    off = no 0x20 (vulnerable baseline). Production equivalent: unbound
#    use-caps-for-id. The off-path poisoner is dns_offpath_poison.py.
dns_0x20() {
  # The T11 resolver (dns_0x20_forwarder) is brought up by the attack itself
  # (do_T11), with the silent-upstream window the off-path SADDNS attack needs.
  # This toggle just records whether 0x20 case-randomisation must be enforced;
  # do_T11 reads /run/t11-0x20-mode on each B4 and starts the forwarder with it.
  local v=0; [ "$1" = on ] && v=1
  local e
  for e in "${B4S[@]}"; do set -- $e
    dx ip netns exec "$1" sh -c "echo $v > /run/t11-0x20-mode"
  done
  echo "DNS_0X20 $1 (Dagon 0x20 case-randomisation at the B4 resolver: mode=$v)"
}

# ═══════════════════════════════════════════════════════════════════════════
# RFC-GROUNDED defenses (no deployable research-article mechanism exists for the
# attack; the canonical control is the RFC). Kept honest + distinct from the
# article-grounded ones above.
# ═══════════════════════════════════════════════════════════════════════════

# ── PCP_QUOTA (T7): per-subscriber PCP mapping quota (RFC 6887 §16.5 / 6888 REQ-4) ─
pcp_quota() {
  dx ip netns exec aftr pkill -9 -f pcp_server.py 2>/dev/null
  _kill_proxy() { dx ip netns exec "$1" pkill -9 -f pcp_proxy.py 2>/dev/null; }
  for_each_b4 _kill_proxy; sleep 0.5
  local q=""; [ "$1" = on ] && q="T_PCP_QUOTA=${PCP_QUOTA_N:-50}"
  dxd ip netns exec aftr env PCP_POOL_SIZE="${PCP_POOL_SIZE:-1024}" $q python3 /testbed/aftr/pcp_server.py
  _start_proxy() { dxd ip netns exec "$1" python3 /testbed/b4/pcp_proxy.py \
      --lan-ip "$2" --b4-ip6 "$3" --aftr-ip6 "$AFTR_IP6" --passthrough-third-party; }
  for_each_b4 _start_proxy; sleep 2
  echo "PCP_QUOTA $1 (per-subscriber mapping cap; one B4 cannot drain the shared pool)"
}

# ── PCP_AUTH (T9): authenticated ANNOUNCE confirmation (RFC 7652) ────────────
#    On a suspected epoch reset the B4 proxy confirms via an integrity-protected
#    unicast ANNOUNCE to the AFTR before renewing; a forged multicast ANNOUNCE is
#    not confirmed by the real server -> no renewal storm.
pcp_auth() {
  dx ip netns exec aftr pkill -9 -f pcp_server.py 2>/dev/null
  _kill_proxy() { dx ip netns exec "$1" pkill -9 -f pcp_proxy.py 2>/dev/null; }
  for_each_b4 _kill_proxy; sleep 0.5
  local a=""; [ "$1" = on ] && a="T_PCP_AUTH=1"
  dxd ip netns exec aftr env PCP_POOL_SIZE="${PCP_POOL_SIZE:-1024}" $a python3 /testbed/aftr/pcp_server.py
  _start_proxy() { dxd ip netns exec "$1" env $a python3 /testbed/b4/pcp_proxy.py \
      --lan-ip "$2" --b4-ip6 "$3" --aftr-ip6 "$AFTR_IP6" --passthrough-third-party; }
  for_each_b4 _start_proxy; sleep 2
  echo "PCP_AUTH $1 (RFC 7652 authenticated ANNOUNCE confirmation; forged epoch reset ignored)"
}

# ── NAT_LOG (T2): per-binding attribution logging (RFC 6888 REQ-9 / RFC 6302) ─
#    Shared-IPv4 reputation poisoning cannot be prevented (shared-fate), but each
#    NAT binding is logged (inner subscriber IP <-> shared public IP:port + time)
#    so abuse on the shared address is attributable + actionable.
nat_log() {
  local LOG="${NAT_LOG_FILE:-/var/log/aftr-bindings.log}"
  dx pkill -9 -f 'conntrack -E' 2>/dev/null
  if [ "$1" = on ]; then
    dx sh -c "touch $LOG"
    dxd ip netns exec aftr sh -c \
      "conntrack -E -e NEW -o timestamp,extended 2>/dev/null | grep --line-buffered 'dst=${PUBLIC_POOL}.' >> $LOG"
    echo "NAT_LOG on (per-binding attribution: shared-IP abuse traceable to the subscriber)"
  else
    echo "NAT_LOG off (no attribution logging)"
  fi
}

case "$DEF" in
  DHCPV6_AUTH)   dhcpv6_auth   "$STATE" ;;
  PCP_OWNERSHIP) pcp_ownership "$STATE" ;;
  SNMP_USM)      snmp_usm      "$STATE" ;;
  SAVI)          savi          "$STATE" ;;
  FEISTEL_IPID)  feistel_ipid  "$STATE" ;;
  DNS_0X20)      dns_0x20      "$STATE" ;;
  TRABELSI)      trabelsi      "$STATE" ;;
  ESP_AEAD)      esp_aead      "$STATE" ;;
  PCP_QUOTA)     pcp_quota     "$STATE" ;;   # T7  (RFC 6887)
  PCP_AUTH)      pcp_auth      "$STATE" ;;   # T9  (RFC 7652)
  NAT_LOG)       nat_log       "$STATE" ;;   # T2  (RFC 6888)
  *) echo "unknown defense: $DEF" >&2; exit 2 ;;
esac
