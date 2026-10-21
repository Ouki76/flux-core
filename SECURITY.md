# Security Policy

flux-core is a network proxy: by design it terminates untrusted input from the
public internet and relays bytes it does not own. A vulnerability here is
therefore potentially worse than in an ordinary application — it can expose the
traffic of everyone using the proxy, or the host it runs on.

This file covers **how to report a problem** and **what is in scope**. The threat
model and the hardening that is already implemented are documented in
[docs/security.md](docs/security.md); read that first if you want to understand
what the design already assumes.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Use GitHub's private vulnerability reporting on this repository
(**Security** tab → **Report a vulnerability**). That creates a private advisory
where the maintainers can respond, and it keeps the report, the fix and the
credit on one thread.

If private reporting is unavailable, open a *content-free* issue asking for a
private channel — no details, no reproducer, no affected version — and a
maintainer will contact you.

Please include:

- affected version (`flux-core version`) and how you built it (release/tag or commit);
- the configuration class involved (inbound type, transport, outbound, API), with
  secrets redacted;
- a reproducer, ideally a minimal config plus the bytes/packets that trigger it;
- impact: what an attacker gains (traffic disclosure, credential replay, RCE,
  crash, resource exhaustion, topology disclosure, …);
- whether the issue is already public anywhere.

You will get an acknowledgement, an assessment, and a fix timeline. Fixes ship
in the next patch release with an advisory and credit unless you ask to stay
anonymous.

## Supported versions

Only the latest release on the `main` line receives security fixes. The project
is pre-1.x-compatible in the sense that configuration and wire behaviour may
change between minor versions; pin a tag if you need stability, but expect to
move to the newest tag for fixes.

| Version | Supported |
|---|---|
| latest `v1.2.x` | yes |
| older tags | no — upgrade first |

## Scope

### In scope

- Protocol implementations: VLESS/REALITY/XTLS-Vision, Trojan, VMess, Shadowsocks
  and Shadowsocks-2022, TUIC v5, Hysteria 2 (+ Salamander obfuscation),
  SOCKS5, HTTP/HTTP CONNECT, WireGuard (AmneziaWG dialect).
- Authentication and replay protection of those protocols (credential checks,
  anti-replay windows, AEAD handling, timestamp windows, MAC pre-screening).
- Parsers and decoders reached from the network: TLS/HTTP/2/HTTP/3 framing,
  WebSocket, gRPC, HTTPUpgrade, proxy URI parsing, DNS wire format, rule-set
  parsing, configuration parsing of **operator-supplied** files.
- The routing engine and DNS resolver, where a malicious *remote* peer (rule-set
  host, DNS upstream) or a malicious client can influence outcomes.
- Transparent inbounds (TUN, REDIRECT, TPROXY) and the userspace TCP/IP stack.
- The management API: authentication, CSRF/cross-origin handling, request
  limits, and information disclosure.
- Supply chain: a dependency that is compromised, or a build that silently pulls
  something other than what `Cargo.lock` pins.
- Denial of service that is cheap for the attacker and costly for the proxy
  (amplification, unbounded allocation per connection, lock contention that
  stalls all traffic). The built-in rate limiting and connection caps are the
  mitigation; bypassing them is in scope.

### Out of scope

- **No DNSSEC.** The resolver does not validate DNSSEC signatures, and DNSSEC
  record types (RRSIG, DNSKEY, DS, NSEC…) are relayed verbatim rather than
  interpreted. A spoofed answer from an authenticated-but-hostile upstream, or
  an on-path attacker on a plaintext UDP upstream, is a known non-property. Use
  DoH/DoT/DoQ to a trusted upstream if that matters to you. Reports that amount
  to "DNSSEC is not validated" are not vulnerabilities.
- **Host compromise.** Once an attacker has code execution as the proxy user,
  they own the configuration, the keys and the traffic; that is the starting
  assumption, not a finding.
- **Misconfiguration that the project warns about.** Binding the management API
  to a public address without a secret, using `allow_insecure_api`, or disabling
  QUIC certificate verification (`insecure: true`) are documented, explicit
  opt-outs. See the deployment checklist in [docs/security.md](docs/security.md).
- **Traffic analysis of the underlying protocols.** Fingerprinting resistance is
  a feature goal (REALITY, Salamander, ShadowTLS), but "an active prober can
  distinguish this from a real TLS site" is a research result, not an incident,
  unless it crashes, leaks memory contents, or bypasses authentication.
- **Upstream libraries' own cryptographic correctness.** A weakness in `ring`,
  `rustls`, `quinn`, `chacha20poly1305`, `x25519-dalek` and friends should be
  reported upstream. If flux-core *misuses* one of them, that is in scope and we
  want the report.
- **Side-channel attacks** that require the attacker to already be on the same
  physical host or to control its scheduler.
- **Clients dialling the wrong node** because an operator's rule-set or routing
  configuration says so. Routing logic bugs that misroute traffic *silently* are
  in scope; a deliberate `final` outbound is configuration.
- **The `fuzz/` targets requiring nightly.** They are a development tool; see
  "Known limitations" below.
- Findings produced only by a scanner with no demonstrated impact on flux-core
  (generic "no security headers" reports on a proxy tunnel, TLS grade widgets,
  etc.).

## Known limitations that are deliberate

These are documented rather than fixed; please do not file them as
vulnerabilities.

| Limitation | Why |
|---|---|
| No DNSSEC validation | Out of scope by design; see above. |
| `unsafe-libyaml` (via `serde_yaml_ng`) is unmaintained | Tracked as `RUSTSEC-2024-0449` in [`deny.toml`](deny.toml) with a written acceptance rationale: the YAML parser only ever reads operator-supplied config, never network input. Replacing it is a separate migration. |
| Fuzzing is not part of CI | `cargo-fuzz` requires nightly; this project builds on stable only. The fuzz corpus is replayed as a deterministic regression suite (`tests/test_fuzz_parsers.rs`) on stable in CI. |
| No formal audit of protocol implementations | The protocols were validated against sing-box/Xray with interoperability suites (`tests/test_singbox_interop.rs`, `tests/test_xray_interop.rs`) and an independent second-pass review (see `CHANGELOG.md` 1.2.1), but interoperating is not the same as being audited. |
| Release artefacts are unsigned | Releases carry SHA256 checksums (`SHA256SUMS`) only. There is no signing key infrastructure, so a compromise of the release workflow cannot be detected by signature. Verify builds from a tag yourself if that matters. |

## What a fix looks like

A security fix comes with a regression test that fails on the vulnerable code, an
entry in `CHANGELOG.md` under a "Fixed (security)" heading, and — for anything
affecting users who cannot upgrade immediately — a deployment note in
[docs/security.md](docs/security.md). The test count and the reasoning behind
each gate are in [docs/quality.md](docs/quality.md).