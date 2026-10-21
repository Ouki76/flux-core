#!/usr/bin/env bash
#
# HTTP/2 conformance wrapper: starts a real flux-core H2 inbound
# (`framing: {"type": "h2"}`) and runs h2spec against it, then prints a
# pass/fail summary. Exit status is 0 only when the applicable h2spec sections
# report zero failures.
#
# Usage:
#   scripts/run_conformance.sh              # applicable sections (must all pass)
#   scripts/run_conformance.sh --full       # whole h2spec suite, failures listed
#   PORT=12345 scripts/run_conformance.sh   # force a port
#   FLUX_BIN=... H2SPEC_BIN=... scripts/run_conformance.sh
#
# Why not "h2spec with no arguments" all the time: flux-core's H2 endpoint is a
# *tunnel*, not an HTTP resource server. It answers a request with 200 OK and an
# unbounded body (the proxied byte stream), so h2spec cases that need a
# self-delimiting response body, or that expect the connection to survive the
# proxy protocol aborting a stream, cannot pass by construction. Those cases are
# excluded below and in tests/test_conformance_h2.rs; everything h2spec measures
# about the connection, frame and HPACK layer must pass.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
H2SPEC="${H2SPEC_BIN:-/tmp/h2spec}"
FLUX_BIN="${FLUX_BIN:-$ROOT/target/debug/flux-core}"
UUID_DEFAULT="11111111-2222-3333-4444-555555555555"
MODE="applicable"

for arg in "$@"; do
    case "$arg" in
        --full) MODE="full" ;;
        -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# Sections a tunnel endpoint must satisfy (mirrors APPLICABLE_SECTIONS in
# tests/test_conformance_h2.rs).
APPLICABLE_SECTIONS=(
    generic/1 generic/3.1 generic/3.2 generic/3.3 generic/3.5 generic/3.7
    generic/3.8 generic/3.9 generic/3.10 generic/4 generic/5
    http2/4
    http2/5.1.1 http2/5.3.1 http2/5.4.1 http2/5.5
    http2/6.1 http2/6.2 http2/6.3 http2/6.4 http2/6.5.1 http2/6.5.2
    http2/6.7 http2/6.8 http2/6.10
    http2/8
    hpack
)

die() { echo "error: $*" >&2; exit 1; }

# --- prerequisites ---------------------------------------------------------

if [[ ! -x "$H2SPEC" ]]; then
    echo "h2spec not found at $H2SPEC; downloading v2.6.0..."
    tmp="$(mktemp -d)"
    curl -fsSL \
        https://github.com/summerwind/h2spec/releases/download/v2.6.0/h2spec_linux_amd64.tar.gz \
        -o "$tmp/h2spec.tar.gz" || die "failed to download h2spec"
    tar -xzf "$tmp/h2spec.tar.gz" -C "$tmp" h2spec || die "failed to extract h2spec"
    install -m 0755 "$tmp/h2spec" "$H2SPEC"
    rm -rf "$tmp"
fi
"$H2SPEC" --version >/dev/null 2>&1 || die "h2spec is not runnable ($H2SPEC)"
echo "h2spec: $("$H2SPEC" --version 2>&1 | head -1)"

if [[ ! -x "$FLUX_BIN" ]]; then
    echo "flux-core binary missing at $FLUX_BIN; building..."
    ( cd "$ROOT" && cargo build --bin flux-core ) || die "cargo build failed"
fi

# --- pick a free port and start a real H2 inbound --------------------------

if [[ -z "${PORT:-}" ]]; then
    PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
fi

WORKDIR="$(mktemp -d)"
FLUX_PID=""
cleanup() {
    if [[ -n "$FLUX_PID" ]] && kill -0 "$FLUX_PID" 2>/dev/null; then
        kill "$FLUX_PID" 2>/dev/null || true
        wait "$FLUX_PID" 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

cat >"$WORKDIR/config.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [{
    "tag": "h2-conformance-in",
    "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": $PORT },
    "framing": { "type": "h2", "path": "/" },
    "protocol": { "type": "vless", "uuid": "$UUID_DEFAULT" }
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF

"$FLUX_BIN" run -c "$WORKDIR/config.json" >"$WORKDIR/flux.log" 2>&1 &
FLUX_PID=$!

ready=""
for _ in $(seq 1 200); do
    if ! kill -0 "$FLUX_PID" 2>/dev/null; then
        cat "$WORKDIR/flux.log" >&2
        die "flux-core exited before listening on port $PORT"
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        exec 3>&- 3<&-
        ready="yes"
        break
    fi
    sleep 0.05
done
[[ "$ready" == "yes" ]] || { cat "$WORKDIR/flux.log" >&2; die "flux-core did not listen on $PORT"; }
echo "flux-core H2 inbound listening on 127.0.0.1:$PORT (pid $FLUX_PID)"

# --- run h2spec ------------------------------------------------------------

set +e
if [[ "$MODE" == "full" ]]; then
    echo "running full h2spec suite (tunnel-inapplicable cases will be listed)..."
    "$H2SPEC" -h 127.0.0.1 -p "$PORT" -o 2 >"$WORKDIR/h2spec.out" 2>&1
else
    echo "running h2spec (${#APPLICABLE_SECTIONS[@]} applicable specs)..."
    "$H2SPEC" -h 127.0.0.1 -p "$PORT" -o 2 "${APPLICABLE_SECTIONS[@]}" \
        >"$WORKDIR/h2spec.out" 2>&1
fi
set -e

SUMMARY="$(grep -a 'tests,' "$WORKDIR/h2spec.out" | tail -1 | tr -d '\r')"
[[ -n "$SUMMARY" ]] || { echo "h2spec produced no summary:"; cat "$WORKDIR/h2spec.out"; exit 1; }

# h2spec repeats each failure in a trailing "Failures:" block; prefer that block
# (it carries section headings) and fall back to scanning for the × marker.
FAILBLOCK="$(sed -n '/^Failures:/,$p' "$WORKDIR/h2spec.out" | tr -d '\r\000' | sed 's/^  */  /')"
if [[ -z "$FAILBLOCK" ]]; then
    FAILBLOCK="$(grep -a '×' "$WORKDIR/h2spec.out" | tr -d '\r\000' | sed 's/^ */  /' || true)"
fi

echo
echo "================ h2spec summary ================"
echo "mode:    $MODE"
echo "result:  $SUMMARY"
if [[ -n "$FAILBLOCK" ]]; then
    echo "--- failures ---"
    echo "$FAILBLOCK"
fi
echo "================================================"

FAILED="$(echo "$SUMMARY" | sed -n 's/.*, \([0-9]\+\) failed.*/\1/p')"
FAILED="${FAILED:-0}"

if [[ "$MODE" == "full" ]]; then
    cat <<'NOTE'

Note: the failures above are the documented tunnel-inapplicable cases only
(h2spec expects an HTTP resource server, flux-core exposes an HTTP/2 tunnel).
The applicable sections are checked with: scripts/run_conformance.sh
NOTE
    exit 0
fi

if [[ "$FAILED" -ne 0 ]]; then
    echo "FAIL: $FAILED failure(s) in sections an H2 tunnel must satisfy" >&2
    exit 1
fi
echo "PASS: 0 failures in the applicable HTTP/2 sections"
exit 0