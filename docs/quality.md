# Engineering quality standard

This is the bar `flux-core` holds itself to, and how each part of that bar is
actually verified. It exists so that a statement like "the code is well tested"
can be replaced with a command, a count and a workflow that fails when it stops
being true.

Two rules govern everything below:

1. **Every claim is checkable.** If a quality property is not measured by a
   command in this repository, it is listed under [Known gaps](#7-known-gaps)
   instead of being asserted.
2. **A gate that cannot fail is not a gate.** Every job in CI fails for at least
   one real reason; jobs whose *tool* is unreliable are explicitly non-blocking
   and say so in their summary (see [§4](#4-api-stability)).

Machine-readable pointers to the files mentioned here live in
`[workspace.metadata.quality]` in [`Cargo.toml`](../Cargo.toml).

---

## 1. The standard, item by item

| # | Property | Requirement | Verified by | Enforced in | Blocking |
|---|---|---|---|---|---|
| 1 | **Formatting** | `rustfmt` clean, no diff | `cargo fmt --all --check` | `ci.yml` → *Formatting* | yes |
| 2 | **Lints** | Zero clippy warnings on all targets and features | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | `ci.yml` → *Check, Lint & Test* | yes |
| 3 | **Tests** | Whole workspace passes; interop suites actually run (not skipped) | `cargo test --workspace` with `SINGBOX_BIN` set | `ci.yml` → *Check, Lint & Test* | yes |
| 4 | **Privileged behaviour** | TUN / REDIRECT / TPROXY paths work with `CAP_NET_ADMIN` | `sudo cargo test --test test_transparent_inbounds --test-threads=1`, with the environment pre-verified and `SKIP:` treated as failure | `ci.yml` → *Privileged Tests* | yes |
| 5 | **Release profile** | The shipped profile (`lto = "fat"`, `codegen-units = 1`, `strip`) compiles | `cargo build --release` | `ci.yml`, `release.yml` | yes |
| 6 | **Advisories** | No known vulnerability in the dependency graph | `cargo audit` + `cargo deny check advisories` | `ci.yml` → *Supply Chain* | yes |
| 7 | **Licenses / bans / sources** | Only allow-listed licenses, no duplicate-version creep, crates.io only | `cargo deny check` against [`deny.toml`](../deny.toml) | `ci.yml` → *Supply Chain* | yes |
| 8 | **MSRV** | Builds on `rust-version = 1.91` — the same version CI uses | every job pins `1.91.0` | all workflows | yes |
| 9 | **API stability** | No semver-breaking change to the library crates since the last release | `cargo semver-checks check-release --workspace --baseline-rev …` | `ci.yml` → *API Stability* | **no — advisory** ([§4](#4-api-stability)) |
| 10 | **Throughput** | No more than 25 % regression against the recorded baseline | `scripts/bench_regress.sh` vs [`benches/baseline.json`](../benches/baseline.json) | `bench.yml` (weekly + dispatch) | yes, once the baseline is armed ([§5](#5-benchmark-tracking)) |
| 11 | **Coverage** | A coverage report can be produced on demand, and the trend is tracked | `scripts/coverage.sh` / `cargo llvm-cov` | `coverage.yml` (push to `main`) | pipeline only ([§6](#6-coverage)) |
| 12 | **Interop** | Wire compatibility with sing-box (and Xray for Vision) in both directions | `tests/test_singbox_interop.rs`, `tests/test_xray_interop.rs` | `ci.yml` | yes |
| 13 | **Conformance** | HTTP/2 connection, frame and HPACK layers conform to h2spec | `scripts/run_conformance.sh` | manual / local | no — see gap G2 |
| 14 | **Docs** | Public items documented, no broken intra-doc links | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` | *not gated* | **no** — see gap G1 |
| 15 | **`unsafe` hygiene** | Every `unsafe` block justified; no implicit unsafe operations inside `unsafe fn` | `unsafe_op_in_unsafe_fn` (warn-by-default in edition 2024) promoted to an error by clippy's `-D warnings` | `ci.yml` → *Check, Lint & Test* | yes for the lint; no UB checker — see gap G4 |
| 16 | **CI is itself checked** | Workflows parse, no duplicate keys, no dangling `steps.<id>` references, every `run:` block is valid shell, every referenced script exists | `scripts/check_workflows.sh` | `ci.yml` → *Formatting* | yes |

The four numbers that are easiest to quote and hardest to fake are reproduced in
the [appendix](#8-appendix--measured-snapshot): LOC per crate, test count per
crate, files with no test at all, and the harness-counted test total.

### What "green" must mean

- A test that **skips** is not a passing test. The privileged job treats a `SKIP:`
  line as a failure because that job exists precisely to run those tests. The
  interop suites skip silently when the external binary is missing, which is why
  CI installs a pinned sing-box instead of hoping it is there.
- A job with no assertion is not a job. The coverage job does not enforce a
  percentage (no baseline exists yet) but it does fail if instrumentation, test
  execution or the lcov report breaks — that is a real gate on the pipeline.
- Advisory jobs must say *why* they are advisory, in the workflow and in this
  document. Anything else is a permanently green check that trains people to
  ignore red.

---

## 2. Reproducing the whole standard locally

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
SINGBOX_BIN=/usr/local/bin/sing-box cargo test --workspace
cargo build --release
cargo audit
cargo deny check
scripts/quality_metrics.sh        # the numbers in the appendix
scripts/check_workflows.sh        # validates the workflows and every script
scripts/coverage.sh --check       # which coverage tier this machine can reach
scripts/bench_regress.sh --no-gate
```

The privileged suite needs root:

```bash
sudo -E env "PATH=$PATH" cargo test --test test_transparent_inbounds -- --test-threads=1 --nocapture
```

---

## 3. Release process

A release is a tag, and the tag is the only trigger — there is no separate
"publish" button whose state can drift from the tag.

```
v1.2.2 pushed
   │
   ├─ preflight   tag == Cargo.toml version · fmt · clippy · full test suite
   │              (with sing-box installed) · release-profile build
   │
   ├─ build       matrix: linux-x86_64 (native, required)
   │                      linux-aarch64 (via `cross`, best effort)
   │               → tar.gz + per-asset .sha256, uploaded as artifacts
   │
   └─ publish     re-verify every checksum → SHA256SUMS
                  → gh release create --verify-tag --generate-notes
                  → re-runs upload with --clobber instead of failing
```

- **Tag convention:** `v` + the root package `version`. The preflight job fails if
  they disagree, because artefact names, the release title and the version the
  binary reports would otherwise diverge.
- **Nothing is published from a red tree.** The full test suite runs *before* the
  matrix; a failure means "fix, delete the tag, re-tag". Deleting and re-pushing
  a tag is the supported recovery path.
- **Checksums, not signatures.** Each archive ships a `.sha256`, and the release
  carries an aggregated `SHA256SUMS`. There is no signing key infrastructure and
  this document does not pretend otherwise — see gap G6.
- **aarch64 is best effort.** It is built in the `cross` container, needs an image
  the project does not otherwise require, and its failure does not block the
  x86_64 release; the job emits a `::warning::` and the run shows it as failed.
  If aarch64 must become a hard requirement, drop `continue-on-error` from that
  matrix leg and add a cross build to the required checks.
- **`Cargo.toml` cannot drift silently.** `[workspace.metadata.release]` records
  the convention that the workflow enforces.

Not done, deliberately: signing, SBOM generation, reproducible-build verification,
package-manager publishing, and cross-compilation beyond aarch64. All are listed
as gaps rather than implied.

---

## 4. API stability

**What the public API actually is.** Every workspace crate is a path dependency
of the `flux-core` binary; none of them is a distribution channel today (there is
no `publish` metadata and no package-manager contract behind them). So the API
that users actually depend on, in order of practical importance, is:

1. the **configuration schema** (YAML/JSON/JSONC — see
   [`docs/configuration.md`](configuration.md)),
2. the **CLI** (`run`, `check`, `trace`, `version`) and its exit codes,
3. the **management API** ([`docs/api.md`](api.md)),
4. the **wire behaviour** of every inbound/outbound,
5. the Rust library API of the workspace crates.

Items 1–4 are contract-checked the only way that is honest: by tests
(`test_modular_config`, `test_flux_native_api`, the interop suites) and by the
CHANGELOG discipline. Rustdoc-level API stability applies to item 5, and
`cargo-semver-checks` is where it is mechanised — as a *preventive* measure, so
that the first time a crate becomes consumable it has not already accumulated
silent breaking changes.

**How it runs.** `ci.yml` → *API Stability* installs the tool with
`cargo install --locked cargo-semver-checks --root ~/.cargo-tools` (cached), then
resolves a baseline revision and runs
`cargo semver-checks check-release --workspace --baseline-rev <rev>`:

| Event | Baseline |
|---|---|
| Pull request | `origin/<base branch>` — catches a breaking change introduced by that PR |
| Push to `main` | the most recent reachable `v*` tag — "changes since the last release" |
| Tag push | the previous `v*` tag |

**Why it is non-blocking, and what "visible" means.** The tool is a large build
whose dependency tree can fail to compile on the pinned 1.91.0 toolchain for
reasons unrelated to this repository, and before the first `v*` tag exists there
is no baseline at all. Either condition would produce a red X that nobody can act
on. So the job:

- keeps `continue-on-error` on the install and check steps,
- writes install/baseline/check outcomes to the job summary,
- emits a `::warning::` when no baseline exists,
- uploads `semver-checks.log` as an artefact (14-day retention),
- and, critically, **says in its summary that the API was not checked**, so the
  absence of a result is itself recorded.

To make it blocking: verify the tool installs on 1.91.0 once, then remove
`continue-on-error` from the *Check public API* step. That is tracked as gap G3.

---

## 5. Benchmark tracking

CI runners are noisy: the same commit can move ±10 % between runs on a shared
VM, and loopback numbers depend on the neighbour workload. The policy therefore
separates **reporting** from **gating**.

**What is measured.** `examples/bench_native.rs`: a pipelined TCP echo through
flux-core (SOCKS5 inbound → direct outbound) versus a direct loopback connection,
interleaved across rounds, summarised by median. The *ratio* to direct loopback is
far less machine-dependent than the absolute number, but the policy gates on the
absolute MB/s, because that is what a user actually experiences.

**Reported on every run** (step summary + `bench-results` artefact, 90-day retention):

| Metric | Why |
|---|---|
| flux-core median / min / max MB/s | the number the gate uses, plus its spread |
| direct loopback median MB/s | the runner's speed, for context |
| flux-core as % of direct | normalises out runner speed |
| delta vs stored baseline | the verdict input |
| raw log + JSON record | a trend across runs, and evidence for a bisect |

**The gate.** Fail when `flux_core` median drops **more than 25 %** below
`throughput_mbps.flux_core` in [`benches/baseline.json`](../benches/baseline.json).
The threshold lives *in the baseline file* (`policy.max_regression_pct`) so there
is exactly one place to change it; `scripts/bench_regress.sh` reads it from there.

**Arming.** A baseline is comparable only to another machine of the same class, so
the file carries `runner_class` and `provisional`:

- `provisional: true` (the committed state: recorded on a developer workstation)
  → the gate is **dormant**. A >25 % drop prints a loud warning and exits 0
  instead of inventing a regression that is really just a slower CPU.
- `provisional: false` + matching `runner_class` → the gate is **armed** and a
  >25 % drop fails the workflow.

To arm it: dispatch *Benchmarks* with `update_baseline: true`, download the
`bench-baseline` artefact, commit it over `benches/baseline.json`. Baselines are
committed by hand on purpose — a workflow that silently rewrites its own
yardstick can hide a regression by moving the goalposts.

**Why sing-box is not in the CI comparison.** The runner does not have it, and
pinning a third-party binary as the reference makes the regression check depend
on an external project's release schedule. Comparing flux-core against the same
runner's direct loopback is self-contained and still catches "the proxy got
slower".

**Exit codes** from `scripts/bench_regress.sh`: `0` ok / gate dormant / `--no-gate`,
`1` regression on an armed baseline, `2` bad input or an unparsable log.

---

## 6. Coverage

**What this toolchain allows.** The project builds with a distro Rust toolchain
and no rustup, so the LLVM coverage binaries (`llvm-profdata`, `llvm-cov`) are
usually absent — they are not part of a distro `rustc` and are not installed with
`cargo`. `cargo-llvm-cov` is also not installed locally by policy. What *is*
achievable here, verified on this machine: nothing instrumented — `scripts/coverage.sh`
detects the situation and exits **3** (tooling unavailable) with the exact
remediation rather than a confusing failure. In CI (rustup available) the same
script takes the fully supported path.

`scripts/coverage.sh` has three tiers:

| Tier | Condition | Behaviour |
|---|---|---|
| 1 | `cargo-llvm-cov` on `PATH` | `cargo llvm-cov --workspace --lib --tests` (`--lcov`, `--html`, or summary) |
| 2 | `llvm-profdata` + `llvm-cov` only | best effort: `-C instrument-coverage`, run tests, merge profiles, report |
| 3 | neither | print precise install instructions, **exit 3** |

Install instructions it prints (tier 3), exactly as needed:

```bash
# option A — recommended, and what CI does
rustup component add llvm-tools-preview
cargo install --locked cargo-llvm-cov

# option B — keep the distro toolchain, add only the LLVM tools
sudo dnf install llvm      # Fedora
sudo apt install llvm      # Debian/Ubuntu
```

`--check` reports the tier without measuring anything, which is what CI uses to
assert "the runner has tier 1" before blaming the code.

**CI.** `coverage.yml` runs on every push to `main` and on dispatch (not on PRs:
instrumentation multiplies suite runtime, and a coverage number is a trend, not a
per-commit verdict). It installs `llvm-tools-preview` + `cargo-llvm-cov`, installs
sing-box so the interop suites contribute, writes an lcov report, summarises the
totals into the step summary, and uploads `coverage-lcov` (90 days).

**Current picture: proxies, not a percentage.** A real line-coverage number cannot
be produced on this toolchain (see above), so the appendix records what *can* be
measured objectively today — code size and test presence per crate, the
harness-counted test total, and the list of source files that contain no test at
all. Those are honest lower bounds: a file with no `#[test]` is definitely not
covered by a unit test, even if it is exercised end-to-end by the integration
suites.

**No threshold yet.** A percentage picked out of the air would gate nothing
meaningful. The path is: produce the first report in CI, record the number here,
then add `--fail-under-lines` (or a ratchet on the previous run) as a separate,
deliberate decision — gap G5.

---

## 7. Known gaps

Each gap is stated with what would be required to close it. None of them is
hidden by a green check.

**G1 — No documentation gate.** `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
--workspace` is not part of CI, so broken intra-doc links are reviewed, not
enforced. (The previously recorded example — `[data]` in a doc comment at
`crates/flux-outbound/src/hysteria2.rs` — has since been moved inside a code span
and no longer resolves as a link; the gap itself remains until the gate is added
to `ci.yml`.)

**G2 — Conformance is not in CI.** `scripts/run_conformance.sh` needs `h2spec`,
which is not installed on GitHub runners and is not a Rust tool this project can
`cargo install`. It runs locally and is expected before changes to the H2/HPACK
layer. Closing it means vendoring a pinned `h2spec` build into the workflow (or a
container image) and adding the script to the job.

**G3 — API stability is advisory.** `cargo-semver-checks` cannot be verified on
the pinned 1.91.0 toolchain from here, and no `v*` tag exists yet, so the job is
`continue-on-error`. Closing it: confirm the install once on a runner, cut the
first tag, then remove `continue-on-error` from the check step.

**G4 — No nightly tooling.** There is no rustup and no nightly here, so the
following are unavailable and out of scope by construction:

| Tool | What it would add | Requirement |
|---|---|---|
| `cargo-fuzz` (libFuzzer) | continuous fuzzing of the 8 libFuzzer targets in `fuzz/` | nightly + `cargo install cargo-fuzz` |
| `-Z sanitizer=address` / `=thread` | memory/race checking of the userspace stacks | nightly |
| Miri | UB detection in `unsafe` code | nightly (`+miri`) |
| `-Z build-std` | std-level coverage and cross builds | nightly |

What exists instead: the fuzz corpus is replayed as a deterministic regression
suite on stable (`tests/test_fuzz_parsers.rs`), and clippy covers the lints that
stable can express. A CI job that fuzzes would need a nightly toolchain in the
workflow only — a deliberate, reviewable change, not something this repository
does today.

**G5 — No coverage threshold.** See [§6](#6-coverage). Requires the first CI
report to exist first.

**G6 — Releases are unsigned.** SHA256 checksums only; no `cosign`/GPG
infrastructure, no SBOM, no reproducible-build verification (the release profile
used `lto = "fat"` + `strip`, which is deterministic in principle but has not
been verified byte-for-byte between machines).

**G7 — Benchmark gate is dormant until a runner baseline exists.** The committed
baseline is `provisional: true` because it was recorded on a developer machine
(§5). Until it is replaced, large regressions are *reported*, not blocked.

**G8 — Linux only.** TUN/REDIRECT/TPROXY, `splice(2)` and the WireGuard userspace
stack are Linux-specific; there is no macOS/Windows job, and no cross-platform
CI matrix.

**G9 — No mutation testing, no formal verification, no threat-model test suite.**
`cargo-mutants` would give a much better answer to "are these tests actually
testing anything?" than a coverage number does. It is a large, slow, ad-hoc run
and is not part of any workflow.

---

## 8. Appendix — measured snapshot

Generated by `scripts/quality_metrics.sh`; re-run it to refresh. The tree is under
active development, so treat the numbers as a dated snapshot rather than
constants — the command is the source of truth.

<!-- BEGIN GENERATED: scripts/quality_metrics.sh -->

<!-- generated by scripts/quality_metrics.sh — do not edit by hand -->
Snapshot: `2026-10-21T17:49:40Z` at commit `959aa0b` **plus uncommitted changes**

### Code size and test presence per workspace member

| Member | `.rs` files | Lines | `#[test]` attributes | Files w/o tests |
|---|---:|---:|---:|---:|
| `crates/flux-app` | 7 | 6877 | 50 | 3 |
| `crates/flux-common` | 8 | 1388 | 19 | 2 |
| `crates/flux-dns` | 7 | 4454 | 47 | 2 |
| `crates/flux-inbound` | 15 | 6798 | 15 | 10 |
| `crates/flux-outbound` | 18 | 4759 | 30 | 10 |
| `crates/flux-protocol` | 14 | 10290 | 76 | 1 |
| `crates/flux-router` | 7 | 1678 | 15 | 2 |
| `crates/flux-transport` | 16 | 8433 | 45 | 3 |
| `crates/flux-types` | 5 | 504 | 3 | 3 |
| `src` | 1 | 292 | 0 | 1 |
| `tests` | 25 | 14256 | 171 | 1 |
| `examples (non-member)` | 8 | 5000 | 0 | 8 |
| `benches (non-member)` | 1 | 210 | 0 | 1 |

**Total:** 132 files, 64939 lines, 471 test attributes.

### Files with no `#[test]`/`#[tokio::test]` (>= 100 lines)

Module roots (`lib.rs`) that only re-export and files below the cutoff are
excluded; the full list is available with `--min-loc 0`.

- crates/flux-app/src/instance.rs — 1660 lines
- crates/flux-app/src/api.rs — 1002 lines
- crates/flux-inbound/src/tuic.rs — 616 lines
- crates/flux-inbound/src/shadowsocks.rs — 501 lines
- crates/flux-inbound/src/hysteria2.rs — 497 lines
- crates/flux-inbound/src/wireguard.rs — 482 lines
- crates/flux-outbound/src/shadowsocks.rs — 395 lines
- crates/flux-inbound/src/tproxy.rs — 378 lines
- crates/flux-transport/src/h3_tables.rs — 360 lines
- crates/flux-inbound/src/trojan.rs — 309 lines
- crates/flux-transport/src/pipeline.rs — 304 lines
- src/main.rs — 292 lines
- crates/flux-inbound/src/vmess.rs — 283 lines
- crates/flux-inbound/src/vless.rs — 281 lines
- crates/flux-outbound/src/vmess.rs — 204 lines
- crates/flux-outbound/src/vless.rs — 188 lines
- crates/flux-inbound/src/http.rs — 182 lines
- tests/common/mod.rs — 179 lines
- crates/flux-dns/src/dot.rs — 179 lines
- crates/flux-outbound/src/trojan.rs — 174 lines
- crates/flux-outbound/src/socks.rs — 155 lines
- crates/flux-types/src/traits.rs — 125 lines

### Harness-counted tests (`cargo test --lib -- --list` per member)

Authoritative: this is what `cargo test` will actually run, so it can
differ from the attribute count above (`#[cfg]`-gated modules, macros).
Requires a full build, so this section is opt-in.

| Scope | Tests |
|---|---:|
| `flux-types` (unit) | 3 |
| `flux-common` (unit) | 19 |
| `flux-router` (unit) | 15 |
| `flux-dns` (unit) | 47 |
| `flux-transport` (unit) | 45 |
| `flux-protocol` (unit) | 76 |
| `flux-inbound` (unit) | 15 |
| `flux-outbound` (unit) | 30 |
| `flux-app` (unit) | 50 |
| `flux-core` (`tests/` integration) | 171 |
| **Total** | **471** |

Note: `--lib --tests` excludes examples, benches and doc-tests, so this
is the count of tests `cargo test --workspace` runs, not of `#[test]`
attributes in the tree.

<!-- END GENERATED: scripts/quality_metrics.sh -->

### How to read the appendix

- **Lines** is `wc -l` over `*.rs`: it includes comments, blank lines and
  `#[cfg(test)]` bodies. It is the definition a reviewer can reproduce by hand,
  not a "logical SLOC" metric.
- **`#[test]` attributes** is a static count and is a *lower* bound: a file can
  contain zero attributes and still be covered by the integration suites in
  `tests/`, and macro-generated tests do not appear at all. The
  harness-counted total (`cargo test --workspace --lib --tests -- --list`) is
  the authoritative number.
- **Files with no test** lists shipped code only (`crates/`, `src/`, `tests/`).
  A `lib.rs` that only re-exports still shows up there — judge the list by path
  and size, not by count alone. `--min-loc N` changes the cutoff and
  `--min-loc 0` prints everything.
- Examples, benches and integration tests are **not** shipped code; they are
  listed as non-members for completeness and are deliberately kept out of the
  "no test" list (a benchmark harness asserting on itself would prove nothing).
- **Snapshot semantics.** These numbers are a photograph of a working tree that
  is under active development: the snapshot above was taken with uncommitted
  changes present, so a re-run a few minutes later will differ. The command is
  the source of truth; the table is evidence that the command works.