//! Xray-side configuration for the protocol matrix a benchmark needs.
//!
//! This file is a library of **config builders**, not a test: every function
//! returns a complete `xray` JSON document as a `String`, so a harness that
//! wants to measure flux-core against Xray can ask for exactly one side at a
//! time and point the peer at it. `tests/test_xray_matrix_configs.rs` is the
//! proof that each of these documents actually starts and carries traffic.
//!
//! # Shape of the two sides
//!
//! * `*_server_config(port, …)` is a complete Xray **server**: one inbound of
//!   the requested protocol on `127.0.0.1:port`, plus a `freedom` outbound so it
//!   can reach the echo target.
//! * `*_client_config(socks_port, server_port, …)` is a complete Xray
//!   **client**: a SOCKS5 (no-auth, TCP-only) inbound on `127.0.0.1:socks_port`
//!   and a single outbound of the requested protocol towards
//!   `127.0.0.1:server_port`. Drive traffic through the SOCKS5 port; the tunnel
//!   is the outbound.
//!
//! Keeping the client's ingress SOCKS5 for every protocol means the transport
//! under test is the only thing that varies between matrix rows.
//!
//! # What Xray 26.3.27 actually accepts (discovered by running the binary)
//!
//! These are not guesses; each one was found by feeding a config to
//! `xray run -test -c` and to a live pair, and the error text is quoted where
//! relevant:
//!
//! 1. **`allowInsecure` is gone from `tlsSettings`.** A client config carrying
//!    it is refused at load time:
//!    `common/errors: The feature "allowInsecure" has been removed and migrated
//!    to "pinnedPeerCertSha256"`. The replacement is a **single hex string**
//!    (SHA-256 over the peer leaf certificate's DER), *not* the array
//!    `pinnedPeerCertificateChainSha256` used by older releases. Passing an
//!    array fails with `cannot unmarshal array into Go struct field
//!    TLSConfig….pinnedPeerCertSha256 of type string`, and passing base64 fails
//!    with `encoding/hex: invalid byte`. See [`cert_sha256_hex`].
//! 2. **Trojan `flow` is gone.** `The feature Flow for Trojan has been
//!    removed.` Trojan itself still works but is deprecated
//!    (`The feature Trojan (with no Flow, etc.) is deprecated`), so it is kept
//!    in the matrix with a caveat rather than dropped.
//! 3. **Trojan has a client-side first-write limit.** The outbound writes the
//!    request header and the first payload in one buffered write; when that
//!    first write is ≥ 8 KiB the tunnel dies with
//!    `proxy/trojan: failed to write A request payload > common/buf: buffer is
//!    full` and the server logs `failed to read first request > EOF`. The size
//!    that matters is what Xray's SOCKS5 inbound read, not what the sender
//!    wrote: the inbound coalesces queued bytes, so writing in small chunks
//!    does **not** avoid it — a bulk sender loses the race regardless. What
//!    works is one lockstep round trip below the limit before the bulk push,
//!    after which the outbound is in unbuffered copy mode and a full MiB
//!    streams through. See [`TROJAN_MAX_FIRST_WRITE`]; the test performs that
//!    prime for every protocol, so Trojan is a caveat rather than a broken row.
//! 4. **REALITY clients must be uTLS clients.** `fingerprint` is mandatory in
//!    `realitySettings`; without it the outbound is refused.
//! 5. **Shadowsocks-2022 keys are raw base64 PSKs**, 16 bytes for
//!    `2022-blake3-aes-128-gcm`. A wrong-length password is refused at load
//!    time, so [`ss2022_password`] generates exactly 16 bytes.
//!
//! Everything else in the matrix (VLESS over TCP/WS/gRPC/TLS, VMess over WS)
//! needed no shape beyond the obvious one, and each is exercised by the test.

#![allow(dead_code)] // this file is a module of builders; the test/bench picks what it needs

use serde_json::{Value, json};
use std::path::Path;

/// The Xray release every shape in this file was verified against.
pub const XRAY_VERSION_TESTED: &str = "26.3.27";

/// Loopback address both sides bind and dial. The matrix is a local smoke test;
/// nothing here should ever listen on a public interface.
pub const LOOPBACK: &str = "127.0.0.1";

/// SNI used by REALITY and by the TLS rows. For REALITY any name works as long
/// as client SNI, server `serverNames` and the decoy's certificate are mutually
/// plausible; for TLS it must match a SAN of the certificate the test issues.
pub const TLS_SNI: &str = "localhost";

/// REALITY short id. Xray requires hex, even length, at most 8 bytes.
pub const REALITY_SHORT_ID: &str = "01020304";

/// Default WebSocket path for both VLESS-over-WS and VMess-over-WS.
pub const WS_PATH: &str = "/flux";

/// Default gRPC service name for VLESS-over-gRPC.
pub const GRPC_SERVICE: &str = "FluxGun";

/// IANA/reference name of the Shadowsocks-2022 AEAD cipher used by the matrix.
pub const SS2022_METHOD: &str = "2022-blake3-aes-128-gcm";

/// Key length [`SS2022_METHOD`] requires, in bytes.
pub const SS2022_KEY_LEN: usize = 16;

/// Password for the Trojan row. Trojan has no username; the password is the
/// whole credential.
pub const TROJAN_PASSWORD: &str = "flux-core-trojan";

/// Upper bound (exclusive) for the **first** write into a Trojan tunnel.
///
/// Xray 26.3.27's Trojan outbound buffers the request header together with the
/// first payload; at 8192 bytes the write fails with `common/buf: buffer is
/// full`. Measured boundary: a 4096-byte first read passes, 8192 fails. The
/// rule is about the read Xray's SOCKS5 inbound performs, so the sender cannot
/// satisfy it by writing small chunks alone — it must stay **lockstep** until
/// the first echo comes back, which is exactly what the integration test does.
pub const TROJAN_MAX_FIRST_WRITE: usize = 8_191;

// ---------------------------------------------------------------------------
// Support matrix
// ---------------------------------------------------------------------------

/// Whether Xray can take a given role for a protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Xray starts, and traffic flows.
    Yes,
    /// Xray starts and traffic flows, but only under a documented rule.
    YesWithCaveat(&'static str),
    /// Xray refuses this role (the reason says why).
    No(&'static str),
}

impl Support {
    /// Whether a pair using this role can be exercised at all.
    pub fn is_usable(self) -> bool {
        !matches!(self, Support::No(_))
    }

    /// The caveat or refusal text, empty for [`Support::Yes`].
    pub fn reason(self) -> &'static str {
        match self {
            Support::Yes => "",
            Support::YesWithCaveat(r) | Support::No(r) => r,
        }
    }
}

/// One row of the benchmark matrix.
pub struct MatrixRow {
    /// Stable identifier, also used as the label in test output.
    pub protocol: &'static str,
    /// Can Xray act as the **server** of this protocol?
    pub xray_server: Support,
    /// Can Xray act as the **client** of this protocol?
    pub xray_client: Support,
    /// How the two roles are configured, or what is missing.
    pub note: &'static str,
}

/// Every protocol the benchmark is expected to cover, with the verdict for
/// Xray 26.3.27 in each role.
///
/// A row is `No` only when Xray refuses the role outright; a role that works
/// under a documented constraint is `YesWithCaveat`, because "deprecated but
/// functional" and "cannot be used" are very different facts for a benchmark.
pub const MATRIX: &[MatrixRow] = &[
    MatrixRow {
        protocol: "vless-tcp",
        xray_server: Support::Yes,
        xray_client: Support::Yes,
        note: "plain VLESS over TCP: `network: tcp`, `security: none`",
    },
    MatrixRow {
        protocol: "vless-ws",
        xray_server: Support::Yes,
        xray_client: Support::Yes,
        note: "VLESS over WebSocket: `network: ws` plus a matching `wsSettings.path`",
    },
    MatrixRow {
        protocol: "vless-grpc",
        xray_server: Support::Yes,
        xray_client: Support::Yes,
        note: "VLESS over gRPC: `network: grpc` plus a matching `grpcSettings.serviceName`",
    },
    MatrixRow {
        protocol: "vless-xhttp",
        xray_server: Support::Yes,
        xray_client: Support::Yes,
        note: "VLESS over XHTTP (`network: splithttp`) in `stream-one` mode: one POST \
               carries both directions, and the absence of a session id in the path is \
               what selects the mode",
    },
    MatrixRow {
        protocol: "vless-tls",
        xray_server: Support::Yes,
        xray_client: Support::YesWithCaveat(
            "clients must pin the peer certificate: Xray 26 removed `allowInsecure`, \
             `pinnedPeerCertSha256` (hex string over the leaf DER) replaces it",
        ),
        note: "VLESS over TLS 1.3 with a self-signed certificate and certificate pinning",
    },
    MatrixRow {
        protocol: "vless-reality",
        xray_server: Support::Yes,
        xray_client: Support::Yes,
        note: "REALITY needs a real TLS 1.3 `dest` on the server and `fingerprint` on the client",
    },
    MatrixRow {
        protocol: "vless-reality-vision",
        xray_server: Support::Yes,
        xray_client: Support::Yes,
        note: "REALITY + `xtls-rprx-vision`: the flow is set on both the inbound client entry \
               and the outbound user",
    },
    MatrixRow {
        protocol: "trojan-tls",
        xray_server: Support::YesWithCaveat(
            "deprecated in Xray 26 (`The feature Trojan (with no Flow, etc.) is deprecated`), \
             and its `flow` option was removed; the server itself behaves correctly",
        ),
        xray_client: Support::YesWithCaveat(
            "the outbound fails with `failed to write A request payload > common/buf: buffer is \
             full` unless the first read into the tunnel stays below 8192 bytes, so a bulk \
             sender must prime it with one sub-8 KiB lockstep round trip first",
        ),
        note: "Trojan over TLS 1.3, password-only credential, certificate pinned",
    },
    MatrixRow {
        protocol: "shadowsocks-2022",
        xray_server: Support::Yes,
        xray_client: Support::Yes,
        note: "`2022-blake3-aes-128-gcm` with a raw 16-byte base64 PSK on both sides",
    },
    MatrixRow {
        protocol: "vmess-ws",
        xray_server: Support::Yes,
        xray_client: Support::Yes,
        note: "VMess AEAD (`alterId: 0`) over WebSocket",
    },
];

// ---------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------

/// Xray log section used by every config. `warning` keeps the log short enough
/// to quote in a failure message while still carrying every refusal.
fn log_section() -> Value {
    json!({ "loglevel": "warning" })
}

/// The SOCKS5 ingress every client config uses, so that the only difference
/// between matrix rows is the outbound.
fn socks_inbound(port: u16) -> Value {
    json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "socks",
        // TCP only: this is a stream benchmark, and UDP over SOCKS would add a
        // second, unrelated code path to every row.
        "settings": { "auth": "noauth", "udp": false }
    })
}

/// Assembles a server document around one inbound.
fn server_doc(inbound: Value) -> String {
    json!({
        "log": log_section(),
        "inbounds": [inbound],
        "outbounds": [{ "protocol": "freedom" }]
    })
    .to_string()
}

/// Assembles a client document around one outbound.
fn client_doc(socks_port: u16, outbound: Value) -> String {
    json!({
        "log": log_section(),
        "inbounds": [socks_inbound(socks_port)],
        "outbounds": [outbound]
    })
    .to_string()
}

/// `streamSettings` for a plain (unencrypted) transport of the given network.
fn plain_stream(network: &str) -> Value {
    json!({ "network": network, "security": "none" })
}

/// Server-side TLS 1.3 `streamSettings` around a PEM certificate/key pair.
fn tls_server_stream(cert_path: &Path, key_path: &Path) -> Value {
    json!({
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "certificates": [{
                "certificateFile": cert_path.to_string_lossy(),
                "keyFile": key_path.to_string_lossy()
            }]
        }
    })
}

/// Client-side TLS `streamSettings` that pins the server's leaf certificate.
///
/// `cert_sha256_hex` comes from [`cert_sha256_hex`]. Xray 26 has no
/// `allowInsecure`; pinning is the supported way to trust a self-signed peer.
fn tls_client_stream(server_name: &str, cert_sha256_hex: &str) -> Value {
    json!({
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "serverName": server_name,
            "pinnedPeerCertSha256": cert_sha256_hex
        }
    })
}

// ---------------------------------------------------------------------------
// 1. VLESS over TCP, plain
// ---------------------------------------------------------------------------

/// Xray server: plain VLESS over TCP.
pub fn vless_tcp_server_config(port: u16, uuid: &str) -> String {
    server_doc(json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [{ "id": uuid }],
            // Xray refuses a VLESS inbound without an explicit `decryption`, and
            // "none" is the only value that means "no outer encryption".
            "decryption": "none"
        },
        "streamSettings": plain_stream("tcp")
    }))
}

/// Xray client: SOCKS5 in, plain VLESS over TCP out.
pub fn vless_tcp_client_config(socks_port: u16, server_port: u16, uuid: &str) -> String {
    client_doc(
        socks_port,
        json!({
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "users": [{ "id": uuid, "encryption": "none" }]
                }]
            },
            "streamSettings": plain_stream("tcp")
        }),
    )
}

// ---------------------------------------------------------------------------
// 2. VLESS over WebSocket
// ---------------------------------------------------------------------------

/// Xray server: VLESS over WebSocket on `path`.
pub fn vless_ws_server_config(port: u16, uuid: &str, path: &str) -> String {
    server_doc(json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [{ "id": uuid }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "security": "none",
            "wsSettings": { "path": path }
        }
    }))
}

/// Xray server: VLESS over XHTTP in `stream-one` mode.
///
/// `stream-one` is the mode Xray itself selects for XHTTP under REALITY, and the only one
/// that needs no sequence numbers: a single POST keeps both directions open.
pub fn vless_xhttp_server_config(port: u16, uuid: &str, path: &str) -> String {
    server_doc(json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [{ "id": uuid }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "splithttp",
            "security": "none",
            "splithttpSettings": { "path": path, "mode": "stream-one" }
        }
    }))
}

/// Xray client: SOCKS5 in, VLESS over XHTTP out.
pub fn vless_xhttp_client_config(
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    path: &str,
) -> String {
    client_doc(
        socks_port,
        json!({
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "users": [{ "id": uuid, "encryption": "none" }]
                }]
            },
            "streamSettings": {
                "network": "splithttp",
                "security": "none",
                "splithttpSettings": { "path": path, "mode": "stream-one" }
            }
        }),
    )
}

/// Xray client: SOCKS5 in, VLESS over WebSocket out.
pub fn vless_ws_client_config(socks_port: u16, server_port: u16, uuid: &str, path: &str) -> String {
    client_doc(
        socks_port,
        json!({
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "users": [{ "id": uuid, "encryption": "none" }]
                }]
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                // Both sides must agree on the path; Xray's WS handler rejects
                // any request whose path does not match.
                "wsSettings": { "path": path }
            }
        }),
    )
}

// ---------------------------------------------------------------------------
// 3. VLESS over gRPC
// ---------------------------------------------------------------------------

/// Xray server: VLESS over gRPC on `service_name`.
pub fn vless_grpc_server_config(port: u16, uuid: &str, service_name: &str) -> String {
    server_doc(json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [{ "id": uuid }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "security": "none",
            "grpcSettings": { "serviceName": service_name }
        }
    }))
}

/// Xray client: SOCKS5 in, VLESS over gRPC out.
pub fn vless_grpc_client_config(
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    service_name: &str,
) -> String {
    client_doc(
        socks_port,
        json!({
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "users": [{ "id": uuid, "encryption": "none" }]
                }]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": { "serviceName": service_name }
            }
        }),
    )
}

// ---------------------------------------------------------------------------
// 4. VLESS over TLS
// ---------------------------------------------------------------------------

/// Xray server: VLESS over TLS 1.3 with a PEM certificate pair.
pub fn vless_tls_server_config(port: u16, uuid: &str, cert_path: &Path, key_path: &Path) -> String {
    server_doc(json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [{ "id": uuid }],
            "decryption": "none"
        },
        "streamSettings": tls_server_stream(cert_path, key_path)
    }))
}

/// Xray client: SOCKS5 in, VLESS over TLS out, pinning the server certificate.
pub fn vless_tls_client_config(
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    server_name: &str,
    cert_sha256_hex: &str,
) -> String {
    client_doc(
        socks_port,
        json!({
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "users": [{ "id": uuid, "encryption": "none" }]
                }]
            },
            "streamSettings": tls_client_stream(server_name, cert_sha256_hex)
        }),
    )
}

// ---------------------------------------------------------------------------
// 5. VLESS + REALITY (with or without XTLS Vision)
// ---------------------------------------------------------------------------

/// Xray server: VLESS + REALITY.
///
/// `decoy_port` must be a **real TLS 1.3 listener**: Xray's server steals the
/// certificate for `serverNames` from `dest` during the handshake, so a plain
/// TCP socket there produces a server that starts but never handshakes.
///
/// `vision` adds `flow: xtls-rprx-vision` to the client entry, which is what
/// makes the server expect Vision's uuid-keyed record padding.
pub fn vless_reality_server_config(
    port: u16,
    decoy_port: u16,
    uuid: &str,
    private_key_b64: &str,
    vision: bool,
) -> String {
    let mut client = json!({ "id": uuid });
    if vision {
        client["flow"] = json!("xtls-rprx-vision");
    }
    server_doc(json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [client],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": format!("{LOOPBACK}:{decoy_port}"),
                // No PROXY protocol towards the decoy: the decoy is a plain TLS
                // echo server, not an HTTP server behind a load balancer.
                "xver": 0,
                "serverNames": [TLS_SNI],
                "privateKey": private_key_b64,
                "shortIds": [REALITY_SHORT_ID]
            }
        }
    }))
}

/// Xray client: SOCKS5 in, VLESS + REALITY out.
///
/// `fingerprint` is not optional: Xray's REALITY client is a uTLS client and
/// refuses to start without one.
pub fn vless_reality_client_config(
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    public_key_b64: &str,
    vision: bool,
) -> String {
    let mut user = json!({ "id": uuid, "encryption": "none" });
    if vision {
        user["flow"] = json!("xtls-rprx-vision");
    }
    client_doc(
        socks_port,
        json!({
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "users": [user]
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": TLS_SNI,
                    "fingerprint": "chrome",
                    "publicKey": public_key_b64,
                    "shortId": REALITY_SHORT_ID,
                    "spiderX": "/"
                }
            }
        }),
    )
}

// ---------------------------------------------------------------------------
// 6. Trojan over TLS
// ---------------------------------------------------------------------------

/// Xray server: Trojan over TLS 1.3.
///
/// Trojan is deprecated in Xray 26 but functional; it has no flow, no uuid and
/// no `decryption` — the password is the whole credential.
pub fn trojan_tls_server_config(
    port: u16,
    password: &str,
    cert_path: &Path,
    key_path: &Path,
) -> String {
    server_doc(json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "trojan",
        "settings": {
            "clients": [{ "password": password }]
        },
        "streamSettings": tls_server_stream(cert_path, key_path)
    }))
}

/// Xray client: SOCKS5 in, Trojan over TLS out.
///
/// The returned config is correct as-is, but the tunnel has a data-path limit:
/// see [`TROJAN_MAX_FIRST_WRITE`].
pub fn trojan_tls_client_config(
    socks_port: u16,
    server_port: u16,
    password: &str,
    server_name: &str,
    cert_sha256_hex: &str,
) -> String {
    client_doc(
        socks_port,
        json!({
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "password": password
                }]
            },
            "streamSettings": tls_client_stream(server_name, cert_sha256_hex)
        }),
    )
}

// ---------------------------------------------------------------------------
// 7. Shadowsocks-2022
// ---------------------------------------------------------------------------

/// Xray server: Shadowsocks-2022 AEAD.
///
/// `password` is the raw PSK in standard base64: 16 bytes for
/// `2022-blake3-aes-128-gcm`, 32 for the chacha20 variant. A password of the
/// wrong length is refused at load time, not at handshake time.
pub fn shadowsocks_server_config(port: u16, method: &str, password: &str) -> String {
    server_doc(json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "shadowsocks",
        "settings": {
            "method": method,
            "password": password
        },
        "streamSettings": plain_stream("tcp")
    }))
}

/// Xray client: SOCKS5 in, Shadowsocks-2022 out.
pub fn shadowsocks_client_config(
    socks_port: u16,
    server_port: u16,
    method: &str,
    password: &str,
) -> String {
    client_doc(
        socks_port,
        json!({
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "method": method,
                    "password": password
                }]
            },
            "streamSettings": plain_stream("tcp")
        }),
    )
}

// ---------------------------------------------------------------------------
// 8. VMess over WebSocket
// ---------------------------------------------------------------------------

/// Xray server: VMess (AEAD) over WebSocket.
///
/// `alterId: 0` selects AEAD; any non-zero value would opt into the legacy
/// header format the rest of this crate does not implement.
pub fn vmess_ws_server_config(port: u16, uuid: &str, path: &str) -> String {
    server_doc(json!({
        "listen": LOOPBACK,
        "port": port,
        "protocol": "vmess",
        "settings": {
            "clients": [{ "id": uuid, "alterId": 0 }]
        },
        "streamSettings": {
            "network": "ws",
            "security": "none",
            "wsSettings": { "path": path }
        }
    }))
}

/// Xray client: SOCKS5 in, VMess over WebSocket out.
pub fn vmess_ws_client_config(socks_port: u16, server_port: u16, uuid: &str, path: &str) -> String {
    client_doc(
        socks_port,
        json!({
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "users": [{
                        "id": uuid,
                        "alterId": 0,
                        // "auto" lets the client pick the cipher it was told to
                        // use; pinning a specific one adds a failure mode for
                        // no coverage.
                        "security": "auto"
                    }]
                }]
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": { "path": path }
            }
        }),
    )
}

// ---------------------------------------------------------------------------
// Credential and certificate helpers
// ---------------------------------------------------------------------------

/// Fresh REALITY keypair: (private, public), base64url without padding, which
/// is the encoding `realitySettings.privateKey` / `publicKey` expect.
pub fn reality_keypair() -> (String, String) {
    use base64::Engine;
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes()),
    )
}

/// A Shadowsocks-2022 PSK: 16 random bytes, standard base64 (with padding).
pub fn ss2022_password() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut key = [0u8; SS2022_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// SHA-256 over a PEM certificate's DER, lowercase hex.
///
/// This is exactly what `tlsSettings.pinnedPeerCertSha256` takes in Xray 26.
pub fn cert_sha256_hex(cert_pem_path: &Path) -> String {
    use base64::Engine;
    use sha2::Digest;
    let pem = std::fs::read_to_string(cert_pem_path).expect("read certificate pem");
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .expect("decode certificate DER");
    let digest = sha2::Sha256::digest(&der);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes a self-signed certificate and its key into `dir`, returning both
/// paths. `names` become SANs, so the SNI used by the client must be one of
/// them (`localhost` is always included).
pub fn write_self_signed_cert(
    dir: &Path,
    names: &[&str],
) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let mut sans = vec!["localhost".to_string()];
    for name in names {
        if !sans.iter().any(|s| s == name) {
            sans.push((*name).to_string());
        }
    }
    let cert = rcgen::generate_simple_self_signed(sans).expect("generate self-signed certificate");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
    Ok((cert_path, key_path))
}

// ---------------------------------------------------------------------------
// Uniform interface for a harness
// ---------------------------------------------------------------------------

/// Everything one pair needs to be rendered, gathered in one place.
///
/// The free `*_server_config` / `*_client_config` functions stay available when
/// a caller wants exactly one document, but a harness should prefer
/// [`Protocol::server_config`] / [`Protocol::client_config`]: one call shape for
/// every protocol means adding a row does not change the harness.
///
/// Fields a given protocol does not use are ignored, so one `Params` can be
/// kept for a whole matrix run.
pub struct Params<'a> {
    /// Port the Xray **server** binds. Only server configs read it.
    pub server_port: u16,
    /// Port the Xray **client**'s SOCKS5 inbound binds. Only client configs
    /// read it.
    pub socks_port: u16,
    /// VLESS/VMess user id (a UUID string).
    pub uuid: &'a str,
    /// PEM certificate the TLS rows serve. Must cover [`TLS_SNI`] as a SAN.
    pub cert_path: &'a Path,
    /// PEM private key matching [`Params::cert_path`].
    pub key_path: &'a Path,
    /// [`cert_sha256_hex`] of [`Params::cert_path`]; the client pins it.
    pub cert_sha256_hex: &'a str,
    /// REALITY private key, base64url unpadded, from [`reality_keypair`].
    pub reality_private: &'a str,
    /// Matching REALITY public key.
    pub reality_public: &'a str,
    /// Port of the real TLS 1.3 listener the REALITY server steals its
    /// certificate from. A plain TCP socket there yields a server that starts
    /// and never handshakes.
    pub decoy_port: u16,
    /// Shadowsocks-2022 PSK, base64, [`SS2022_KEY_LEN`] bytes, from
    /// [`ss2022_password`].
    pub ss_password: &'a str,
}

/// One row of the matrix, usable as a value.
///
/// [`Protocol::ALL`] is the canonical order; [`MATRIX`] carries the per-role
/// verdicts and must list the same names in the same order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    VlessTcp,
    VlessWs,
    VlessGrpc,
    /// XHTTP (`splithttp`) in stream-one mode.
    VlessXhttp,
    VlessTls,
    Reality,
    RealityVision,
    TrojanTls,
    Shadowsocks2022,
    VmessWs,
}

impl Protocol {
    /// Every protocol, in report order.
    pub const ALL: [Protocol; 10] = [
        Protocol::VlessTcp,
        Protocol::VlessWs,
        Protocol::VlessGrpc,
        Protocol::VlessXhttp,
        Protocol::VlessTls,
        Protocol::Reality,
        Protocol::RealityVision,
        Protocol::TrojanTls,
        Protocol::Shadowsocks2022,
        Protocol::VmessWs,
    ];

    /// Stable identifier, identical to the matching [`MatrixRow::protocol`].
    pub fn name(self) -> &'static str {
        match self {
            Protocol::VlessTcp => "vless-tcp",
            Protocol::VlessWs => "vless-ws",
            Protocol::VlessGrpc => "vless-grpc",
            Protocol::VlessXhttp => "vless-xhttp",
            Protocol::VlessTls => "vless-tls",
            Protocol::Reality => "vless-reality",
            Protocol::RealityVision => "vless-reality-vision",
            Protocol::TrojanTls => "trojan-tls",
            Protocol::Shadowsocks2022 => "shadowsocks-2022",
            Protocol::VmessWs => "vmess-ws",
        }
    }

    /// Complete Xray server document for this protocol.
    pub fn server_config(self, p: &Params<'_>) -> String {
        match self {
            Protocol::VlessTcp => vless_tcp_server_config(p.server_port, p.uuid),
            Protocol::VlessWs => vless_ws_server_config(p.server_port, p.uuid, WS_PATH),
            Protocol::VlessGrpc => vless_grpc_server_config(p.server_port, p.uuid, GRPC_SERVICE),
            Protocol::VlessXhttp => vless_xhttp_server_config(p.server_port, p.uuid, WS_PATH),
            Protocol::VlessTls => {
                vless_tls_server_config(p.server_port, p.uuid, p.cert_path, p.key_path)
            }
            Protocol::Reality => vless_reality_server_config(
                p.server_port,
                p.decoy_port,
                p.uuid,
                p.reality_private,
                false,
            ),
            Protocol::RealityVision => vless_reality_server_config(
                p.server_port,
                p.decoy_port,
                p.uuid,
                p.reality_private,
                true,
            ),
            Protocol::TrojanTls => {
                trojan_tls_server_config(p.server_port, TROJAN_PASSWORD, p.cert_path, p.key_path)
            }
            Protocol::Shadowsocks2022 => {
                shadowsocks_server_config(p.server_port, SS2022_METHOD, p.ss_password)
            }
            Protocol::VmessWs => vmess_ws_server_config(p.server_port, p.uuid, WS_PATH),
        }
    }

    /// Complete Xray client document for this protocol: SOCKS5 in, tunnel out.
    pub fn client_config(self, p: &Params<'_>) -> String {
        match self {
            Protocol::VlessTcp => vless_tcp_client_config(p.socks_port, p.server_port, p.uuid),
            Protocol::VlessWs => {
                vless_ws_client_config(p.socks_port, p.server_port, p.uuid, WS_PATH)
            }
            Protocol::VlessXhttp => {
                vless_xhttp_client_config(p.socks_port, p.server_port, p.uuid, WS_PATH)
            }
            Protocol::VlessGrpc => {
                vless_grpc_client_config(p.socks_port, p.server_port, p.uuid, GRPC_SERVICE)
            }
            Protocol::VlessTls => vless_tls_client_config(
                p.socks_port,
                p.server_port,
                p.uuid,
                TLS_SNI,
                p.cert_sha256_hex,
            ),
            Protocol::Reality => vless_reality_client_config(
                p.socks_port,
                p.server_port,
                p.uuid,
                p.reality_public,
                false,
            ),
            Protocol::RealityVision => vless_reality_client_config(
                p.socks_port,
                p.server_port,
                p.uuid,
                p.reality_public,
                true,
            ),
            Protocol::TrojanTls => trojan_tls_client_config(
                p.socks_port,
                p.server_port,
                TROJAN_PASSWORD,
                TLS_SNI,
                p.cert_sha256_hex,
            ),
            Protocol::Shadowsocks2022 => {
                shadowsocks_client_config(p.socks_port, p.server_port, SS2022_METHOD, p.ss_password)
            }
            Protocol::VmessWs => {
                vmess_ws_client_config(p.socks_port, p.server_port, p.uuid, WS_PATH)
            }
        }
    }
}
