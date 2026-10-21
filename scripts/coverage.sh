#!/usr/bin/env bash
#
# Line-coverage measurement for flux-core.
#
# This project is built with a distro Rust toolchain (no rustup), so the tool
# that people normally reach for — `cargo llvm-cov` — is frequently absent and
# the LLVM binaries it shells out to (`llvm-profdata`, `llvm-cov`) are not part
# of the Rust distribution on most Linux distros. Rather than dying with a
# half-typed linker error, this script probes the environment, picks the best
# tier that is actually available, and otherwise explains *exactly* what to
# install.
#
# Tiers, best first:
#
#   1. `cargo llvm-cov`            — full workspace coverage, lcov/html/text.
#   2. `llvm-profdata` + `llvm-cov` — best effort: build with
#                                     `-C instrument-coverage`, run the test
#                                     binaries, merge the raw profiles and
#                                     report. Needs the LLVM tools on PATH (or
#                                     in the rustc sysroot).
#   3. neither                      — print the remediation for this distro and
#                                     exit 3 (distinct from "failed").
#
# Exit codes: 0 success, 1 the measurement itself failed, 3 no usable toolchain.
#
# Usage:
#   scripts/coverage.sh                 # text summary on stdout
#   scripts/coverage.sh --lcov FILE     # write lcov.info to FILE
#   scripts/coverage.sh --html          # write ./target/coverage/html/
#   scripts/coverage.sh --check         # probe only, install nothing, report tier
#
# Notes:
#   * Interop tests need `SINGBOX_BIN`; without it those tests skip, so coverage
#     of `tests/test_singbox_interop.rs` is simply absent from the report. Set
#     SINGBOX_BIN to include them (CI does).
#   * Examples, benches and doc-tests are not instrumented (they are harnesses,
#     not shipped code).
#   * `fuzz/` is excluded from the workspace and from coverage on purpose; it
#     needs nightly, which this repository does not require.

set -euo pipefail

cd "$(dirname "$0")/.."

MODE=text
LCOV_PATH="target/coverage/lcov.info"

usage() {
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --lcov)
            shift
            LCOV_PATH="${1:-}"
            [ -n "$LCOV_PATH" ] || { echo "error: --lcov needs a path" >&2; exit 2; }
            MODE=lcov
            ;;
        --html) MODE=html ;;
        --text) MODE=text ;;
        --check) MODE=check ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# --- environment probe -----------------------------------------------------

# Third tier of detection: distro packages ship versioned names such as
# `llvm-profdata-19`, and `cargo llvm-cov` accepts `LLVM_COV`/`LLVM_PROFDATA`
# overrides, so look for those before declaring the tools missing.
find_llvm_tool() { # $1 = bare name, e.g. llvm-profdata
    local name="$1" cand sysroot
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
        return 0
    fi
    # Versioned distro binary: llvm-profdata-19, llvm-cov-18, ...
    local dir
    for dir in ${PATH//:/ }; do
        for cand in "$dir/$name"-*; do
            if [ -x "$cand" ]; then
                printf '%s\n' "$cand"
                return 0
            fi
        done
    done
    # rustup's llvm-tools-preview installs into the toolchain sysroot.
    sysroot=$(rustc --print sysroot 2>/dev/null || true)
    if [ -n "$sysroot" ]; then
        for cand in "$sysroot"/lib/rustlib/*/bin/"$name"; do
            if [ -x "$cand" ]; then
                printf '%s\n' "$cand"
                return 0
            fi
        done
    fi
    return 1
}

HAVE_CARGO_LLVM_COV=0
command -v cargo-llvm-cov >/dev/null 2>&1 && HAVE_CARGO_LLVM_COV=1
LLVM_PROFDATA=$(find_llvm_tool llvm-profdata || true)
LLVM_COV=$(find_llvm_tool llvm-cov || true)

TIER=3
[ -n "${LLVM_PROFDATA:-}" ] && [ -n "${LLVM_COV:-}" ] && TIER=2
[ "$HAVE_CARGO_LLVM_COV" -eq 1 ] && TIER=1

report_unavailable() {
    cat >&2 <<'EOF'
coverage: no usable coverage toolchain found on this machine.

Detected:
EOF
    printf '  cargo llvm-cov : %s\n' "$([ "$HAVE_CARGO_LLVM_COV" -eq 1 ] && echo present || echo MISSING)" >&2
    printf '  llvm-profdata  : %s\n' "${LLVM_PROFDATA:-MISSING}" >&2
    printf '  llvm-cov       : %s\n' "${LLVM_COV:-MISSING}" >&2
    cat >&2 <<'EOF'

This rustc is a distro build (no rustup), so the LLVM coverage binaries are not
shipped inside the toolchain. Install one of the two supported setups:

A. rustup toolchain + cargo-llvm-cov (recommended; what CI uses):

     # once, if you do not have rustup yet:
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
     rustup component add llvm-tools-preview
     cargo install --locked cargo-llvm-cov

   Then re-run: scripts/coverage.sh

B. Keep the distro toolchain and add the LLVM tools only:

     Fedora : sudo dnf install llvm        # provides llvm-profdata, llvm-cov
     Debian : sudo apt install llvm
     Arch   : sudo pacman -S llvm

   Then re-run: scripts/coverage.sh --check

Nothing was measured. Exit code 3 means "tooling unavailable", not "coverage is
zero" and not "the tests failed".
EOF
}

case "$MODE" in
    check)
        printf 'tier=%s cargo_llvm_cov=%s llvm_profdata=%s llvm_cov=%s\n' \
            "$TIER" "$HAVE_CARGO_LLVM_COV" "${LLVM_PROFDATA:-none}" "${LLVM_COV:-none}"
        case "$TIER" in
            1) echo 'result: full coverage available (cargo llvm-cov)' ;;
            2) echo 'result: best-effort coverage available (raw llvm tools)' ;;
            3) echo 'result: unavailable'; exit 3 ;;
        esac
        exit 0
        ;;
esac

mkdir -p "$(dirname "$LCOV_PATH")" target/coverage

# --- tier 1: cargo llvm-cov ------------------------------------------------

run_cargo_llvm_cov() {
    local args=(--workspace --lib --tests)
    case "$MODE" in
        lcov)
            echo "coverage: cargo llvm-cov -> $LCOV_PATH" >&2
            cargo llvm-cov "${args[@]}" --lcov --output-path "$LCOV_PATH"
            echo "coverage: wrote $LCOV_PATH" >&2
            ;;
        html)
            echo "coverage: cargo llvm-cov -> target/coverage/html/index.html" >&2
            cargo llvm-cov "${args[@]}" --html --output-dir target/coverage/html
            ;;
        *)
            cargo llvm-cov "${args[@]}" --summary-only
            ;;
    esac
}

# --- tier 2: raw llvm-profdata / llvm-cov ----------------------------------

# Best effort only: this path builds the whole workspace twice (once to
# instrument, once for the report), and `llvm-cov report` needs every
# instrumented binary listed explicitly. It is kept because it costs nothing
# when tier 1 exists and it is the only option on a distro toolchain.
run_raw_llvm() {
    local raw=target/coverage/raw merged=target/coverage/merged.profdata
    local objs=() f

    export LLVM_PROFDATA LLVM_COV
    rm -rf "$raw" "$merged"
    mkdir -p "$raw"

    echo "coverage: instrumenting (RUSTFLAGS=-C instrument-coverage), this rebuilds the workspace" >&2
    RUSTFLAGS="${RUSTFLAGS:-} -C instrument-coverage" \
    LLVM_PROFILE_FILE="$PWD/$raw/%p-%m.profraw" \
        cargo test --workspace --lib --tests --no-fail-fast || true

    if ! compgen -G "$raw/*.profraw" >/dev/null; then
        echo "coverage: no .profraw files were produced — instrumentation did not take effect" >&2
        exit 1
    fi

    "$LLVM_PROFDATA" merge -sparse "$raw"/*.profraw -o "$merged"

    # Every executable in deps/ that was built for the test run.
    for f in target/debug/deps/*; do
        [ -f "$f" ] && [ -x "$f" ] && objs+=(-object "$f")
    done
    if [ "${#objs[@]}" -eq 0 ]; then
        echo "coverage: no test binaries found under target/debug/deps" >&2
        exit 1
    fi

    case "$MODE" in
        lcov)
            "$LLVM_COV" export "${objs[@]}" -instr-profile="$merged" \
                --ignore-filename-regex='(^|/)(\.cargo|target)/' >"$LCOV_PATH"
            echo "coverage: wrote $LCOV_PATH" >&2
            ;;
        html)
            "$LLVM_COV" show "${objs[@]}" -instr-profile="$merged" \
                --ignore-filename-regex='(^|/)(\.cargo|target)/' \
                --format=html --output-dir=target/coverage/html
            ;;
        *)
            "$LLVM_COV" report "${objs[@]}" -instr-profile="$merged" \
                --ignore-filename-regex='(^|/)(\.cargo|target)/'
            ;;
    esac
}

# --- dispatch --------------------------------------------------------------

case "$TIER" in
    1) run_cargo_llvm_cov ;;
    2)
        echo "coverage: cargo-llvm-cov not installed; using llvm-profdata/llvm-cov directly" >&2
        run_raw_llvm
        ;;
    *)
        report_unavailable
        exit 3
        ;;
esac