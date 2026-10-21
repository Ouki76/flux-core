# Contributing to flux-core

Thanks for taking the time to contribute. This file covers how to build, test and
validate a change. The quality bar a pull request is measured against — and how
each part of it is verified — lives in [docs/quality.md](docs/quality.md).

## Before you start

| Requirement | Notes |
|---|---|
| Rust **1.91** or newer | This is the MSRV (`rust-version` in `Cargo.toml`, edition 2024). CI builds with exactly 1.91.0, so it is also the *maximum* you can rely on for new syntax. |
| Linux | The proxy targets Linux: `splice(2)` zero-copy, TUN/REDIRECT/TPROXY inbounds, `SO_ORIGINAL_DST`, WireGuard userspace stack. Other platforms are not supported. |
| `sing-box` (optional) | Needed only for the interoperability suite. Without it those tests **skip** and still pass. |
| `Xray-core` (optional) | Needed only for the Xray interoperability tests. |
| LLVM coverage tools (optional) | Only for `scripts/coverage.sh`; see [Coverage](#coverage). |

No nightly toolchain is required or used. Nothing in the repository needs `-Z`
flags, and `cargo +nightly` is not part of any workflow.

## Build

```bash
cargo build --release                 # LTO + codegen-units=1, the shipped profile
./target/release/flux-core version
./target/release/flux-core check -c examples/config.yaml   # validate a config
```

`examples/` holds runnable configurations (`config.yaml`, `config.jsonc`,
`nodes.json`) and the load/benchmark harnesses.

## Test

```bash
cargo test --workspace                       # unit + integration
cargo test --workspace --all-features        # same, with every feature enabled
cargo test -p flux-protocol                  # one crate
cargo test --test test_protocols_e2e         # one integration target
```

Two things to know about the suite:

1. **Interop tests skip when the external binary is missing.** They print `SKIP:`
   and pass, so a green local run does *not* mean sing-box compatibility was
   exercised. To actually run them:

   ```bash
   SINGBOX_BIN=/usr/local/bin/sing-box cargo test --test test_singbox_interop -- --nocapture
   XRAY_BIN=/usr/local/bin/xray       cargo test --test test_xray_interop    -- --nocapture
   ```

   CI installs sing-box (pinned version) for every run, so the interop suite is
   genuinely gated there.

2. **The transparent-inbound tests need privileges.** They skip unless the process
   is root and `/dev/net/tun` exists:

   ```bash
   sudo -E env "PATH=$PATH" cargo test --test test_transparent_inbounds -- --test-threads=1 --nocapture
   ```

   They must run serially: they create TUN devices, host addresses on `lo` and
   install `iptables` rules.

### Exhaustive local checks

```bash
scripts/run_conformance.sh          # h2spec HTTP/2 conformance (needs h2spec on PATH or H2SPEC_BIN)
scripts/soak.sh 3600                # one-hour soak with leak detection
scripts/quality_metrics.sh          # LOC / test-presence snapshot (docs/quality.md appendix)
```

`scripts/run_conformance.sh` also has a `--full` mode that runs the whole h2spec
suite; the default subset is what a tunnel endpoint can satisfy by construction —
the exclusions are documented at the top of the script.

## Lint and format

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Both are required to pass; CI runs them as blocking gates. Clippy runs with
`-D warnings`, so a new warning is a failed build, not a suggestion. If a lint is
genuinely wrong for the code, `#[allow(clippy::...)]` with a one-line reason next
to it is the accepted escape hatch — a crate-level allow is not.

## Supply chain

```bash
cargo audit                # RustSec advisories
cargo deny check           # advisories + licenses + bans + sources, per deny.toml
```

A new dependency is a supply-chain change and is reviewed as such:

- its license must be on the allow-list in [`deny.toml`](deny.toml) (or the list
  must be extended *deliberately*, with a comment);
- it must not duplicate an existing crate in the same role (`bans` warns on
  multiple versions — silence the warning by choosing one, not by relaxing the
  policy);
- prefer `default-features = false` plus explicit features; the shipped binary
  already carries rustls/ring rather than OpenSSL for this reason.

## Performance-sensitive changes

If a change touches the data path (transport, protocol codecs, buffers, splice,
the dispatcher), include before/after numbers:

```bash
cargo run --release --example bench_native -- --no-singbox --rounds 5 --mb 300
scripts/bench_regress.sh                    # compares against benches/baseline.json
```

The harness interleaves rounds and reports medians because loopback throughput
drifts by more than 10 % between runs. Compare medians and the *ratio* to the
direct-loopback baseline, never a single shot. The policy for turning these
numbers into a CI verdict is in [docs/quality.md §5](docs/quality.md).

## Coverage

```bash
scripts/coverage.sh              # summary, if a usable toolchain is present
scripts/coverage.sh --check      # what tier is available here, changes nothing
scripts/coverage.sh --lcov target/coverage/lcov.info
```

The script explains exactly what to install when the tooling is missing (LLVM
coverage binaries are not part of a distro toolchain). CI measures coverage on
pushes to `main` with `cargo llvm-cov`.

## What CI will run on your PR

| Workflow | Trigger | Blocking |
|---|---|---|
| `ci.yml` — formatting, clippy, tests, privileged tests, supply chain | every PR | **yes** |
| `ci.yml` — `api-stability` (`cargo-semver-checks`) | every PR | no, advisory (visible in the job summary) |
| `bench.yml` | weekly + manual dispatch | only on a >25 % regression against an armed baseline |
| `coverage.yml` | push to `main` | pipeline only, no percentage threshold |
| `release.yml` | `v*` tag | n/a (it produces the release) |

## Pull request checklist

- [ ] `cargo fmt --all --check` is clean.
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` is clean.
- [ ] `cargo test --workspace` passes, **and** the interop suite was run with
      `SINGBOX_BIN` set if the change touches a protocol, transport or framing
      layer. "It skipped" is not a result.
- [ ] New behaviour has a test that fails without the change. Bug fixes get a
      regression test that reproduces the bug.
- [ ] Privileged paths (TUN/REDIRECT/TPROXY) were exercised with `sudo` if touched.
- [ ] `deny.toml` still passes; new dependencies are justified in the PR text.
- [ ] Documentation is updated when the config schema, CLI surface or public API
      changes (`docs/configuration.md`, `README.md`, `docs/api.md`).
- [ ] `CHANGELOG.md` has an entry under the unreleased/next version heading for
      user-visible changes.
- [ ] No secrets, credentials or private keys; config examples use `${ENV_VAR}`
      expansion rather than literals.

## Commit and PR style

History follows a short conventional prefix plus a scope, e.g.
`fix(protocol): …`, `perf(transport): …`, `test: …`, `docs: …`. Keep the subject
imperative and specific; put the *why* and any measurement in the body. Separate
behavioural changes from refactors and formatting so a reviewer can trust
"refactor only" commits.

## Reporting security issues

Please do **not** open a public issue for a vulnerability — see
[SECURITY.md](SECURITY.md).