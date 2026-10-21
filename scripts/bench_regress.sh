#!/usr/bin/env bash
#
# Throughput regression gate for flux-core.
#
# Runs `examples/bench_native.rs` (flux-core SOCKS5 -> direct, interleaved
# rounds, median) and compares the flux-core median against the stored baseline
# in `benches/baseline.json`.
#
# Policy — see docs/quality.md §5 for the reasoning:
#   * Every run *reports* numbers: flux-core median/min/max, the direct-loopback
#     baseline, flux-core as a percentage of direct, and the delta against the
#     stored baseline. GitHub step summaries get the same table, and the raw
#     JSON is uploaded as a build artefact, so a trend is visible without ever
#     failing a build.
#   * The job fails (exit 1) only when the flux-core median drops more than
#     `policy.max_regression_pct` (25 %) below the stored baseline.
#   * The gate is *armed* only when the baseline was recorded on a runner of the
#     same class (`provisional: false`). A baseline measured on a developer
#     machine is not comparable to a shared CI runner, so while it is
#     provisional the script warns loudly and exits 0 instead of inventing a
#     regression. Dispatch the Benchmarks workflow with `update_baseline: true`
#     to record a runner-class baseline (see docs/quality.md §5).
#
# Why no sing-box comparison: the CI runner has no sing-box, and comparing
# against a third-party binary makes the regression check depend on a moving
# external target. `--no-singbox` keeps the measurement self-contained.
#
# Usage:
#   scripts/bench_regress.sh                    # run the benchmark and compare
#   scripts/bench_regress.sh --log FILE         # compare an existing log
#   scripts/bench_regress.sh --update-baseline  # rewrite benches/baseline.json
#   scripts/bench_regress.sh --no-gate          # report only, never fail
#
# Exit codes:
#   0  ok, or the gate is not armed, or --no-gate/--update-baseline
#   1  regression beyond the threshold on an armed baseline
#   2  bad usage, missing tooling, or unparsable benchmark output

set -euo pipefail

cd "$(dirname "$0")/.."

BASELINE="benches/baseline.json"
OUT_DIR="target/bench-results"
ROUNDS=5
MB=300
STREAMS=1
THRESHOLD=""
LOG_IN=""
UPDATE_BASELINE=0
NO_GATE=0
RUNNER_CLASS="${RUNNER_CLASS:-local-dev}"

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --log)
            shift
            LOG_IN="${1:-}"
            [ -n "$LOG_IN" ] || { echo "error: --log needs a path" >&2; exit 2; }
            ;;
        --baseline) shift; BASELINE="${1:?--baseline needs a path}" ;;
        --out) shift; OUT_DIR="${1:?--out needs a directory}" ;;
        --rounds) shift; ROUNDS="${1:?--rounds needs a number}" ;;
        --mb) shift; MB="${1:?--mb needs a number}" ;;
        --streams) shift; STREAMS="${1:?--streams needs a number}" ;;
        --threshold) shift; THRESHOLD="${1:?--threshold needs a percent}" ;;
        --runner-class) shift; RUNNER_CLASS="${1:?--runner-class needs a value}" ;;
        --update-baseline) UPDATE_BASELINE=1 ;;
        --no-gate) NO_GATE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

for tool in cargo awk python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: '$tool' is required by $0 (python3 only parses/writes the baseline JSON)" >&2
        exit 2
    }
done

mkdir -p "$OUT_DIR"
STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
SHA="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
LOG="$OUT_DIR/bench_native-$STAMP-$SHA.log"
PAIRS="$OUT_DIR/bench-pairs-$STAMP-$SHA.txt"
SUMMARY="$OUT_DIR/bench-summary-$STAMP-$SHA.txt"
RESULT_JSON="$OUT_DIR/bench-result-$STAMP-$SHA.json"

# --- measure ---------------------------------------------------------------

if [ -n "$LOG_IN" ]; then
    [ -f "$LOG_IN" ] || { echo "error: log not found: $LOG_IN" >&2; exit 2; }
    cp "$LOG_IN" "$LOG"
    echo "bench: reusing existing log $LOG_IN" >&2
else
    if [ ! -x target/release/flux-core ]; then
        echo "bench: building release binaries first" >&2
        cargo build --release --locked --bin flux-core
    fi
    echo "bench: rounds=$ROUNDS mb=$MB streams=$STREAMS (sing-box comparison disabled)" >&2
    cargo run --release --locked --example bench_native -- \
        --no-singbox --rounds "$ROUNDS" --mb "$MB" --streams "$STREAMS" 2>&1 | tee "$LOG"
fi

# --- parse -----------------------------------------------------------------
#
# Two shapes are understood, both emitted by examples/bench_native.rs:
#
#   "  round 3: direct  1841.8  flux  1660.3  (MB/s)"          <- per-round pairs
#   "flux-core vs direct baseline: -13.8%  (1757.4 MB/s of 2038.5 MB/s)"
#
# The per-round pairs are preferred: they give min/median/max for both paths and
# let python3 compute the median the same way the harness does. The summary line
# is the fallback for truncated logs.

awk '
    /^[[:space:]]*round / {
        d = ""; f = "";
        for (i = 1; i <= NF; i++) {
            if ($i == "direct") d = $(i + 1);
            if ($i == "flux")   f = $(i + 1);
        }
        if (d != "" && f != "") { print f, d }
    }
' "$LOG" >"$PAIRS"

if [ ! -s "$PAIRS" ]; then
    rm -f "$PAIRS"
    echo "bench: no per-round lines found, falling back to the summary line" >&2
fi

# --- compare / record ------------------------------------------------------

set +e
python3 - "$BASELINE" "$PAIRS" "$LOG" "$THRESHOLD" "$NO_GATE" "$RESULT_JSON" \
         "$UPDATE_BASELINE" "$ROUNDS" "$MB" "$STREAMS" "$RUNNER_CLASS" >"$SUMMARY" <<'PY'
import datetime
import json
import os
import platform
import re
import statistics
import subprocess
import sys

(baseline_path, pairs_path, log_path, threshold_s, no_gate_s, result_path,
 update_s, rounds_s, mb_s, streams_s, runner_class) = sys.argv[1:12]

no_gate = no_gate_s == "1"
update = update_s == "1"


def git(*args):
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True,
                              check=False).stdout.strip()
    except Exception:
        return ""


def machine_info():
    return (f"{platform.system()} {platform.machine()}, "
            f"{os.cpu_count() or 0} logical CPUs, kernel {platform.release()}")


def load_baseline(path):
    try:
        with open(path) as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, f"baseline file not found: {path}"
    except json.JSONDecodeError as exc:
        return None, f"baseline file is not valid JSON ({path}): {exc}"


def read_pairs(path):
    flux, direct = [], []
    if not path or not os.path.exists(path):
        return flux, direct
    with open(path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                f, d = float(parts[0]), float(parts[1])
            except ValueError:
                continue
            flux.append(f)
            direct.append(d)
    return flux, direct


def read_summary_fallback(path):
    """Last-resort parse of the 'flux-core vs direct baseline' line."""
    pattern = re.compile(
        r"flux-core vs direct baseline:.*\(([0-9.]+) MB/s of ([0-9.]+) MB/s\)")
    flux = direct = None
    if not os.path.exists(path):
        return flux, direct
    with open(path, errors="replace") as fh:
        for line in fh:
            m = pattern.search(line)
            if m:
                flux, direct = float(m.group(1)), float(m.group(2))
    return flux, direct


flux_samples, direct_samples = read_pairs(pairs_path)
if flux_samples and direct_samples:
    flux = statistics.median(flux_samples)
    direct = statistics.median(direct_samples)
    flux_min, flux_max = min(flux_samples), max(flux_samples)
    source = f"{len(flux_samples)} interleaved rounds"
else:
    flux, direct = read_summary_fallback(log_path)
    flux_min = flux_max = flux
    source = "summary line only"
    if flux is None or direct is None:
        print("### Throughput")
        print()
        print("**error**: could not find a flux-core throughput figure in the log. "
              "Expected `round N: direct X flux Y` lines or the "
              "`flux-core vs direct baseline` summary line.")
        sys.exit(2)

# The header the harness prints is authoritative about the parameters, so a
# replayed log (`--log`) records what was actually measured rather than whatever
# the command line defaults happen to be.
header = re.compile(r"median of (\d+) interleaved rounds, (\d+) MB / (\d+) stream")
if os.path.exists(log_path):
    with open(log_path, errors="replace") as fh:
        for line in fh:
            m = header.search(line)
            if m:
                rounds_s, mb_s, streams_s = m.group(1), m.group(2), m.group(3)
                break

results = {
    "schema": 1,
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "commit": git("rev-parse", "HEAD") or None,
    "runner_class": runner_class,
    "machine": machine_info(),
    "benchmark": {
        "name": "bench_native",
        "rounds": int(rounds_s),
        "mb_per_measurement": int(mb_s),
        "streams": int(streams_s),
        "singbox_compared": False,
        "source": source,
    },
    "throughput_mbps": {
        "flux_core": round(flux, 3),
        "flux_core_min": round(flux_min, 3) if flux_min is not None else None,
        "flux_core_max": round(flux_max, 3) if flux_max is not None else None,
        "direct_loopback": round(direct, 3),
        "flux_pct_of_direct": round(flux / direct * 100.0, 3) if direct else None,
    },
}

if update:
    baseline = {
        "schema": 1,
        "comment": "Throughput baseline for the Benchmarks workflow. Regenerate with "
                   "`scripts/bench_regress.sh --update-baseline` (on the runner, so the "
                   "measurement matches the runner class).",
        "recorded_at": results["recorded_at"],
        "recorded_on": results["machine"],
        "runner_class": runner_class,
        "provisional": runner_class == "local-dev",
        "benchmark": results["benchmark"],
        "throughput_mbps": results["throughput_mbps"],
        "policy": {
            "max_regression_pct": 25,
            "compare": "flux_core median MB/s against throughput_mbps.flux_core",
            "on_regression": "fail the Benchmarks workflow",
            "armed_when": "provisional == false (runner_class matches the runner)",
        },
    }
    with open(baseline_path, "w") as fh:
        json.dump(baseline, fh, indent=2)
        fh.write("\n")
    print("### Baseline recorded")
    print()
    print(f"`{baseline_path}`: flux-core **{flux:.1f} MB/s**, direct {direct:.1f} MB/s "
          f"({source}), runner class `{runner_class}`, "
          f"provisional={baseline['provisional']}.")
    print()
    if baseline["provisional"]:
        print("This baseline was recorded outside the CI runner class, so the 25 % gate "
              "stays dormant. Re-run with `--runner-class github-actions-ubuntu-latest` "
              "on the runner to arm it.")
    else:
        print("This baseline is armed: the 25 % gate now applies to this runner class.")
    results["baseline"] = {"path": baseline_path,
                           "provisional": baseline["provisional"]}
    results["verdict"] = "baseline-updated"
    with open(result_path, "w") as fh:
        json.dump(results, fh, indent=2)
        fh.write("\n")
    sys.exit(0)

baseline, err = load_baseline(baseline_path)
policy = (baseline or {}).get("policy") or {}
threshold = float(threshold_s) if threshold_s else float(policy.get("max_regression_pct", 25))

base_flux = ((baseline or {}).get("throughput_mbps") or {}).get("flux_core")
armed = bool(baseline) and not bool((baseline or {}).get("provisional", True))

drop = None
if base_flux:
    drop = (base_flux - flux) / base_flux * 100.0

delta_text = "no baseline" if drop is None else "%.1f %% drop" % drop

print("### Throughput (median of interleaved rounds)")
print()
print("| Path | MB/s | vs stored baseline |")
print("|---|---:|---:|")
print(f"| flux-core (SOCKS5 → direct) | {flux:.1f} | {delta_text} |")
print(f"| Direct TCP loopback | {direct:.1f} | — |")
print(f"| flux-core as % of direct | {flux / direct * 100.0:.1f} % | — |")
print()

verdict = "ok"
code = 0

if err:
    print(f"**Baseline problem:** {err}")
    print()
    print("The benchmark ran and reported its numbers; the regression gate could not be "
          "evaluated. Record a baseline with `--update-baseline`.")
    verdict = "no-baseline"
elif not base_flux:
    print("**No baseline recorded** (`throughput_mbps.flux_core` is null or absent). "
          "The 25 % gate is dormant: dispatch the Benchmarks workflow with "
          "`update_baseline: true` and commit the resulting file.")
    verdict = "no-baseline"
else:
    print(f"Baseline: **{base_flux:.1f} MB/s**, recorded {baseline.get('recorded_at', '?')} "
          f"on `{baseline.get('runner_class', 'unknown')}` "
          f"({baseline.get('recorded_on', 'unknown')}).")
    print()
    if drop is not None and drop > threshold:
        if no_gate:
            print(f"**Warning**: a {drop:.1f} % drop exceeds the {threshold:.0f} % policy "
                  f"threshold, but `--no-gate` was passed: reporting only.")
            verdict = "regression-reported"
        elif armed:
            print(f"**REGRESSION**: a {drop:.1f} % drop exceeds the {threshold:.0f} % policy "
                  f"threshold and the baseline is armed for this runner class.")
            verdict = "regression"
            code = 1
        else:
            print(f"**Warning**: a {drop:.1f} % drop exceeds the {threshold:.0f} % threshold, "
                  f"but the baseline is provisional (recorded on "
                  f"`{baseline.get('runner_class', 'unknown')}`, not on this runner class). "
                  f"The gate stays dormant until a runner-class baseline is committed, "
                  f"because absolute throughput is not comparable across machines.")
            verdict = "regression-unarmed"
    elif drop is not None and drop < 0:
        print(f"Improvement: {abs(drop):.1f} % faster than the stored baseline. "
              f"Refresh the baseline once this holds on the runner.")
        verdict = "improved"
    else:
        print(f"Within policy: {drop:.1f} % below baseline (threshold {threshold:.0f} %).")
        verdict = "ok"
    print()

print(f"Policy: fail when the flux-core median drops more than {threshold:.0f} % below "
      f"`{baseline_path}` and the baseline is armed for this runner class. "
      f"See docs/quality.md §5.")

results["baseline"] = {
    "path": baseline_path,
    "flux_core_mbps": base_flux,
    "runner_class": (baseline or {}).get("runner_class"),
    "provisional": (baseline or {}).get("provisional"),
    "threshold_pct": threshold,
    "armed": armed,
    "drop_pct": round(drop, 3) if drop is not None else None,
}
results["verdict"] = verdict
with open(result_path, "w") as fh:
    json.dump(results, fh, indent=2)
    fh.write("\n")

print()
print(f"_result: {result_path}_")
sys.exit(code)
PY
STATUS=$?
set -e

cat "$SUMMARY"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        cat "$SUMMARY"
        echo
        echo '<details><summary>bench_native log (tail)</summary>'
        echo
        echo '```'
        tail -40 "$LOG"
        echo '```'
        echo
        echo '</details>'
    } >>"$GITHUB_STEP_SUMMARY"
fi

exit "$STATUS"