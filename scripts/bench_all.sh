#!/usr/bin/env bash
#
# bench_all.sh — run every flux-core benchmark with one consistent protocol and
# print a markdown summary table on stdout.
#
# Consistent protocol means the same discipline in every harness:
#   * a warm-up before any measurement,
#   * interleaved rounds (target A, target B, target A, ...) so machine drift
#     cancels instead of penalising whichever target ran last,
#   * median of N rounds reported, with min/max so variance is visible,
#   * real verified payload bytes only (byte-compared on receipt), for
#     loopback on this machine, with the machine profile printed.
#
# Progress goes to stderr; only the markdown report goes to stdout, so
#   ./scripts/bench_all.sh > RESULTS.md
# yields a file you can paste into a README.
#
# Usage:
#   scripts/bench_all.sh [options]
#
# Options:
#   --rounds N        interleaved rounds per measurement (default 5)
#   --mb N            TCP payload MB per measurement (default 300)
#   --conc-mb N       payload MB per concurrency level (default 256)
#   --wg-mb N         payload MB for the WireGuard profile (default 64)
#   --udp-count N     UDP datagrams per measurement (default 20000)
#   --levels a,b,c    concurrency levels (default 1,64,512,2048)
#   --quick           small, fast run (rounds 2, small payloads) for a smoke test
#   --no-singbox      skip the sing-box comparison
#   --no-build        do not build before running
#   --out DIR         directory for the raw per-benchmark logs
#   -h, --help        this text
#
# Exit status is 0 if every benchmark that was asked for ran; a failed benchmark
# is reported as "failed" in the table and makes the script exit non-zero.

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT" || exit 1

ROUNDS=5
MB_TCP=300
MB_CONC=256
MB_WG=64
UDP_COUNT=20000
LEVELS="1,64,512,2048"
WITH_SINGBOX=1
DO_BUILD=1
OUT_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --rounds) ROUNDS="$2"; shift 2 ;;
        --mb) MB_TCP="$2"; shift 2 ;;
        --conc-mb) MB_CONC="$2"; shift 2 ;;
        --wg-mb) MB_WG="$2"; shift 2 ;;
        --udp-count) UDP_COUNT="$2"; shift 2 ;;
        --levels) LEVELS="$2"; shift 2 ;;
        --quick)
            ROUNDS=2
            MB_TCP=64
            MB_CONC=64
            MB_WG=16
            UDP_COUNT=5000
            shift ;;
        --no-singbox) WITH_SINGBOX=0; shift ;;
        --no-build) DO_BUILD=0; shift ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        -h|--help) sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$OUT_DIR" ]; then
    OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bench_all.XXXXXX")
else
    mkdir -p "$OUT_DIR"
fi
RESULTS="$OUT_DIR/results.tsv"
: > "$RESULTS"

log() { printf '%s\n' "$*" >&2; }
hr()  { log "----------------------------------------------------------------------"; }

# ---------------------------------------------------------------------------
# Machine profile (printed in the report; a run on a busy box is not the same
# run as a run on an idle one, and the numbers below should say which it was).
# ---------------------------------------------------------------------------
LOAD_START=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "?")
NPROC=$(nproc 2>/dev/null || echo "?")
KERNEL=$(uname -sr)
CPU_MODEL=$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo "unknown")
MEM_MIB=$(awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo "?")

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
if [ "$DO_BUILD" -eq 1 ]; then
    log "building release examples + binary (this is what the numbers below measure)"
    if ! cargo build --release -p flux-core --examples 2> "$OUT_DIR/build.log"; then
        log "build failed; see $OUT_DIR/build.log"
        tail -20 "$OUT_DIR/build.log" >&2
        exit 1
    fi
    # The harnesses spawn ./target/release/flux-core, so it must match the tree.
    if ! cargo build --release -p flux-core 2>> "$OUT_DIR/build.log"; then
        log "binary build failed; see $OUT_DIR/build.log"
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
declare -A STATUS
BENCH_ORDER=()

# run_bench <name> <log-name> -- <command...>
run_bench() {
    local name="$1"; shift
    local logname="$1"; shift
    [ "$1" = "--" ] && shift
    BENCH_ORDER+=("$name")
    local logfile="$OUT_DIR/$logname.log"
    local t0 t1
    t0=$(date +%s)
    log "running $name ..."
    if "$@" > "$logfile" 2>&1; then
        STATUS["$name"]="ok"
    else
        rc=$?
        STATUS["$name"]="failed"
        log "  $name FAILED (exit $rc), log: $logfile"
    fi
    t1=$(date +%s)
    STATUS["$name:secs"]=$((t1 - t0))
    # Collect the machine-readable lines the harnesses emit.
    grep '^@@RESULT|' "$logfile" 2>/dev/null | sed 's/^@@RESULT|//' >> "$RESULTS"
    local nres
    nres=$(grep -c '^@@RESULT|' "$logfile" 2>/dev/null)
    log "  $name done in $((t1 - t0))s (${nres:-0} results)"
}

SINGBOX_FLAG=""
[ "$WITH_SINGBOX" -eq 0 ] && SINGBOX_FLAG="--no-singbox"

FLUX_EX="$ROOT/target/release/examples"

hr
run_bench "native-tcp" "native" -- \
    "$FLUX_EX/bench_native" --rounds "$ROUNDS" --mb "$MB_TCP" $SINGBOX_FLAG
run_bench "udp" "udp" -- \
    "$FLUX_EX/bench_udp" --rounds "$ROUNDS" --count "$UDP_COUNT"
run_bench "concurrency" "concurrency" -- \
    "$FLUX_EX/bench_concurrency" --rounds "$ROUNDS" --mb "$MB_CONC" \
    --levels "$LEVELS" $SINGBOX_FLAG
run_bench "tls" "tls" -- \
    "$FLUX_EX/bench_tls" --rounds "$ROUNDS" --mb "$MB_TCP"
run_bench "wireguard" "wireguard" -- \
    "$FLUX_EX/bench_wireguard" --rounds "$ROUNDS" --mb "$MB_WG"
hr

LOAD_END=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "?")

# ---------------------------------------------------------------------------
# Helpers for reading the collected results
# ---------------------------------------------------------------------------
val() { # val <profile> <level> <target> <metric>
    awk -F'|' -v p="$1" -v l="$2" -v t="$3" -v m="$4" \
        '$1==p && $2==l && $3==t && $4==m {print $5; found=1; exit}
         END {if (!found) print ""}' "$RESULTS"
}

# Unique "<level>|<target>" pairs for a profile, in first-seen order.
pairs() {
    awk -F'|' -v p="$1" '$1==p {print $2"|"$3}' "$RESULTS" | awk -F'|' '!seen[$0]++'
}

pct() { # pct <value> <baseline>  -> "+x.y%" or "-"
    if [ -z "${1:-}" ] || [ -z "${2:-}" ]; then printf '%s' "-"; return; fi
    awk -v a="$1" -v b="$2" 'BEGIN {
        if (b + 0 == 0) { print "-"; exit }
        printf "%+.1f%%", (a / b - 1) * 100
    }'
}

num() { # num <value> <printf-fallback>
    if [ -n "${1:-}" ]; then printf '%s' "$1"; else printf '%s' "-"; fi
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
cat <<EOF
# flux-core benchmark report

Generated \`$(date -u '+%Y-%m-%d %H:%M:%SZ')\` by \`scripts/bench_all.sh\`.

**Profile:** loopback (127.0.0.1) on a single machine, no NIC, no WAN.
${NPROC} logical CPUs (${CPU_MODEL}), ${MEM_MIB} MiB RAM, ${KERNEL}.
1-minute load average ${LOAD_START} at start, ${LOAD_END} at end.
${ROUNDS} interleaved rounds per measurement, median reported with min/max;
warm-up before every target; every received byte is byte-compared against the
pattern that was sent (a truncated or corrupted stream is reported, never
extrapolated).

Reading the numbers: loopback has no physical link, so absolute MB/s is a
*ceiling* for this CPU, not a prediction for a real network. What transfers is
the **relative** cost of each layer and the CPU seconds per GB, which is what the
proxy controls.

EOF

# ---- headline ----
HL_FLUX=$(val concurrency 64 flux-core agg_mbs)
HL_DIRECT=$(val concurrency 64 direct agg_mbs)
HL_SING=$(val concurrency 64 sing-box agg_mbs)
HL_TLS=$(val tls 1 vless/tls mbs)
HL_PLAIN=$(val tls 1 vless/tcp mbs)
HL_TLS_CPU=$(val tls 1 vless/tls cpu_s_per_gb)
HL_PLAIN_CPU=$(val tls 1 vless/tcp cpu_s_per_gb)
HL_WG=$(val wireguard 1 wireguard mbs)
HL_WG_CPU=$(val wireguard 1 wireguard cpu_s_per_gb)
HL_RELAY=$(val wireguard 1 "flux direct" mbs)
HL_REALITY_STATE=$(val tls 1 vless/reality integrity)

cat <<EOF
## Headline

| question | answer |
|---|---|
| 64 concurrent streams, flux-core vs direct loopback | $(num "$HL_FLUX") vs $(num "$HL_DIRECT") MB/s ($(pct "$HL_FLUX" "$HL_DIRECT")) |
| 64 concurrent streams, flux-core vs sing-box | $(num "$HL_FLUX") vs $(num "$HL_SING") MB/s ($(pct "$HL_FLUX" "$HL_SING")) |
| TLS layer cost, same framing (tls vs plain) | $(pct "$HL_TLS" "$HL_PLAIN") throughput, $(awk -v a="$HL_TLS_CPU" -v b="$HL_PLAIN_CPU" 'BEGIN { if (a=="" || b=="") print "-"; else printf "%+.2f CPU s/GB", a-b }') |
| WireGuard userspace tunnel vs kernel relay | $(num "$HL_WG") vs $(num "$HL_RELAY") MB/s ($(pct "$HL_WG" "$HL_RELAY")), $(num "$HL_WG_CPU") CPU s/GB |
| payload integrity on the REALITY path | ${HL_REALITY_STATE:-unknown} |

EOF

# ---- 1. single-stream TCP (bench_native: text table, parsed) ----
cat <<'EOF'
## 1. Single-stream TCP throughput and CPU cost

Pipelined echo over one connection; the same payload shape for every target so
the proxy's cost is what differs.

| target | MB/s (median) | min | max | CPU s/GB | vs direct |
|---|---:|---:|---:|---:|---:|
EOF

NATIVE_LOG="$OUT_DIR/native.log"
if [ -s "$NATIVE_LOG" ]; then
    awk '
        {
            label = substr($0, 1, 32)
            sub(/^ +/, "", label); sub(/ +$/, "", label)
            if (label != "Direct TCP loopback (baseline)" && label != "flux-core" && label != "sing-box") next
            rest = substr($0, 33)
            c = split(rest, a, " ")
            if (c < 3) next
            n++; L[n] = label; MED[n] = a[1] + 0; MIN[n] = a[2] + 0; MAX[n] = a[3] + 0
            CPU[n] = (c >= 6 && a[6] != "-") ? sprintf("%.2f", a[6] + 0) : "-"
            if (label == "Direct TCP loopback (baseline)") base = MED[n]
        }
        END {
            for (i = 1; i <= n; i++) {
                if (base > 0 && L[i] != "Direct TCP loopback (baseline)")
                    vs = sprintf("%+.1f%%", (MED[i] / base - 1) * 100)
                else
                    vs = (L[i] == "Direct TCP loopback (baseline)") ? "+0.0%" : "-"
                printf "| %s | %.1f | %.1f | %.1f | %s | %s |\n", L[i], MED[i], MIN[i], MAX[i], CPU[i], vs
            }
        }' "$NATIVE_LOG"
else
    echo "| failed | - | - | - | - | - |"
fi
echo

# ---- 2. UDP ----
cat <<'EOF'
## 2. UDP relay (SOCKS5 UDP ASSOCIATE)

| path | datagrams/s | payload Mbit/s (@1200 B) | µs per round trip |
|---|---:|---:|---:|
EOF
UDP_LOG="$OUT_DIR/udp.log"
if [ -s "$UDP_LOG" ]; then
    awk '
        /^Direct UDP echo \(baseline\)|^flux-core \(SOCKS5 UDP relay\)/ {
            label = substr($0, 1, 34); sub(/ +$/, "", label)
            v = substr($0, 35) + 0
            if (v > 0) printf "| %s | %d | %.1f | %.1f |\n", label, v, v * 1200 * 8 / 1e6, 1e6 / v
        }' "$UDP_LOG"
else
    echo "| failed | - | - | - |"
fi
echo

# ---- 3. concurrency matrix ----
cat <<'EOF'
## 3. Concurrency matrix (simultaneous TCP streams)

Aggregate MB/s is measured from the instant *all* streams are established, so
connection setup appears separately as `setup ms`. `p50`/`p99` are per-stream
MB/s across the N streams (they can exceed aggregate/N because streams finish at
different times). `CPU s/GB` is the proxy process' CPU per GB carried; `fds` and
`threads` are peaks sampled at 100 Hz from `/proc`.

| streams | target | agg MB/s | min | max | p50 MB/s | p99 MB/s | setup ms | CPU s/GB | RSS MiB | threads | fds | vs direct | integrity |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|
EOF
if [ -s "$RESULTS" ]; then
    CUR_LVL=""
    pairs concurrency | sort -t'|' -k1,1n | while IFS='|' read -r lvl target; do
        if [ "$lvl" != "$CUR_LVL" ]; then
            BASE=$(val concurrency "$lvl" direct agg_mbs)
            CUR_LVL="$lvl"
        fi
        fmt() { v=$(val concurrency "$lvl" "$target" "$1"); if [ -n "$v" ]; then printf '%s' "$v"; else printf '%s' "-"; fi; }
        if [ "$target" = "direct" ]; then VS="+0.0%"; else VS=$(pct "$(fmt agg_mbs)" "$BASE"); fi
        TR=$(fmt truncated_streams)
        if [ -z "$TR" ] || [ "$TR" = "-" ] || [ "$TR" = "0" ]; then INT="ok"; else INT="TRUNCATED ${TR}/${lvl}"; fi
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$lvl" "$target" "$(fmt agg_mbs)" "$(fmt agg_min_mbs)" "$(fmt agg_max_mbs)" \
            "$(fmt p50_mbs)" "$(fmt p99_mbs)" "$(fmt setup_ms)" "$(fmt cpu_s_per_gb)" \
            "$(fmt rss_mib)" "$(fmt threads)" "$(fmt fds)" "$VS" "$INT"
    done
else
    echo "| - | failed | - | - | - | - | - | - | - | - | - | - |"
fi
echo

# ---- 4. TLS layer ----
cat <<'EOF'
## 4. Security-layer cost: plain TCP vs VLESS vs VLESS+TLS vs VLESS+REALITY

Same inbound/outbound/framing/payload for all tunnel rows; only the security
layer changes, so the deltas isolate it. `vless/tcp` is the control: the step
from `flux direct` to `vless/tcp` is protocol framing plus the second hop, and
`vless/tls` minus `vless/tcp` is the TLS layer itself. `integrity` is the result
of byte-comparing everything received against what was sent.

| target | MB/s (median) | min | max | setup p50/p99 ms | CPU s/GB | RSS MiB | vs direct | integrity |
|---|---:|---:|---:|---:|---:|---:|---:|---|
EOF
if [ -s "$RESULTS" ]; then
    TLS_BASE=$(val tls 1 direct mbs)
    pairs tls | while IFS='|' read -r lvl target; do
        fmt() { v=$(val tls "$lvl" "$target" "$1"); if [ -n "$v" ]; then printf '%s' "$v"; else printf '%s' "-"; fi; }
        if [ "$target" = "direct" ]; then VS="+0.0%"; else VS=$(pct "$(fmt mbs)" "$TLS_BASE"); fi
        printf '| %s | %s | %s | %s | %s/%s | %s | %s | %s | %s |\n' \
            "$target" "$(fmt mbs)" "$(fmt mbs_min)" "$(fmt mbs_max)" \
            "$(fmt setup_p50_ms)" "$(fmt setup_p99_ms)" "$(fmt cpu_s_per_gb)" \
            "$(fmt rss_mib)" "$VS" "$(fmt integrity)"
    done
else
    echo "| failed | - | - | - | - | - | - | - | - |"
fi
echo

# ---- 5. WireGuard ----
cat <<'EOF'
## 5. WireGuard (userspace Noise + smoltcp) vs kernel TCP

`RTT` is a 64-byte request/response round trip through the established path
(userspace-stack cost per packet); `setup` is TCP connect to first echoed byte;
`CPU s/GB` is the sum of both tunnel processes (client + server).

| target | MB/s (median) | min | max | RTT p50/p99 µs | setup p50/p99 ms | CPU s/GB | RSS MiB | vs direct | integrity |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
EOF
if [ -s "$RESULTS" ]; then
    WG_BASE=$(val wireguard 1 direct mbs)
    pairs wireguard | while IFS='|' read -r lvl target; do
        fmt() { v=$(val wireguard "$lvl" "$target" "$1"); if [ -n "$v" ]; then printf '%s' "$v"; else printf '%s' "-"; fi; }
        if [ "$target" = "direct" ]; then VS="+0.0%"; else VS=$(pct "$(fmt mbs)" "$WG_BASE"); fi
        printf '| %s | %s | %s | %s | %s/%s | %s/%s | %s | %s | %s | %s |\n' \
            "$target" "$(fmt mbs)" "$(fmt mbs_min)" "$(fmt mbs_max)" \
            "$(fmt rtt_p50_us)" "$(fmt rtt_p99_us)" "$(fmt setup_p50_ms)" "$(fmt setup_p99_ms)" \
            "$(fmt cpu_s_per_gb)" "$(fmt rss_mib)" "$VS" "$(fmt integrity)"
    done
else
    echo "| failed | - | - | - | - | - | - | - | - | - |"
fi
echo

# ---- 6. run status ----
cat <<'EOF'
## Run status

| benchmark | status | wall time |
|---|---|---:|
EOF
for name in "${BENCH_ORDER[@]:-}"; do
    [ -z "$name" ] && continue
    printf '| %s | %s | %ss |\n' "$name" "${STATUS[$name]:-unknown}" "${STATUS[$name:secs]:-?}"
done
echo

cat <<EOF
Raw harness output, including the per-round samples and the full min/max spread,
is in \`${OUT_DIR}\`.

Notes on honesty:
* Loopback only: no NIC, no shaping, no MTU discovery, no packet loss. These are
  upper bounds for this CPU, not WAN predictions.
* The harness also pays for verification (a memcmp of every received byte), so
  the client side is not free; the CPU s/GB figures are the *proxy's* CPU from
  \`/proc/<pid>/stat\`, not the harness'.
* Any row whose \`integrity\` is not \`ok\` moved every byte it claimed to move but
  did not preserve them: treat its throughput number as an upper bound on a
  broken path, not as a capability.
EOF

for name in "${BENCH_ORDER[@]:-}"; do
    [ "${STATUS[$name]:-}" = "failed" ] && exit 1
done
exit 0