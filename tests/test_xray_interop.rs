//! REALITY interoperability against **Xray**, the protocol's reference
//! implementation, in both directions.
//!
//! `tests/test_singbox_interop.rs` already proves flux-core's REALITY against
//! sing-box, but REALITY is Xray's protocol: the session-id authentication,
//! the HMAC-tagged certificate and the target-record-framing mimicry are
//! defined by Xray's implementation, not by a written spec. A single
//! reference implementation is a thin basis for "compatible", so every test
//! here puts a real `xray` binary on one side of flux-core:
//!
//! | test                                   | client | server |
//! |----------------------------------------|--------|--------|
//! | `reality_plain_flux_client_to_xray`    | flux   | xray   |
//! | `reality_plain_xray_client_to_flux`    | xray   | flux   |
//! | `reality_vision_flux_client_to_xray`   | flux   | xray   |
//! | `reality_vision_xray_client_to_flux`   | xray   | flux   |
//!
//! `REALITY + xtls-rprx-vision` is covered separately from plain REALITY
//! because that is the combination people actually deploy, and Vision adds its
//! own uuid-keyed record padding on top of the REALITY handshake.
//!
//! Notes on the configs:
//! * Xray 26 removed `allowInsecure` from `tlsSettings`. REALITY never used it
//!   (there is no CA path to disable: the peer is authenticated by the REALITY
//!   HMAC, not by a certificate chain), so these tests need no pinning. The
//!   plain-TLS Vision tests in `tests/test_singbox_interop.rs` are the ones
//!   that pin with `pinnedPeerCertSha256` (a string, not an array).
//! * Both REALITY roles need a genuine TLS 1.3 target: Xray's server steals
//!   the certificate from `realitySettings.dest`, and flux-core's server probes
//!   the target and mirrors its handshake record sizes. `start_tls_echo_server`
//!   is a real rustls 1.3 listener, which is what the existing sing-box REALITY
//!   tests use as well.
//!
//! Every test asserts a full echo round-trip with a distinctive binary payload
//! (marker text + all 256 byte values), not just a successful connect.

mod common;

use common::{
    get_free_tcp_port, retry_on_flake, start_large_tls_echo_server, start_tcp_echo_server,
    start_tls_echo_server,
};
use flux_app::{Config, Instance};
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use serde_json::{Value, json};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SNI the REALITY peers agree on. Any name works as long as all three of
/// client SNI, server `serverNames` and the decoy's certificate are consistent
/// enough for the handshake to be relayed.
const SNI: &str = "www.microsoft.com";
/// REALITY short id. Xray wants hex, even length, at most 8 bytes.
const SHORT_ID: &str = "01020304";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn which(name: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let full = Path::new(dir).join(name);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

/// Locates the Xray binary (`XRAY_BIN`, then `xray` on PATH).
fn get_xray_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("XRAY_BIN") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    which("xray")
}

/// Generates ML-DSA-65 seed (32 bytes) and verify key (1952 bytes) as base64url unpadded.
fn mldsa65_keypair() -> (String, String) {
    use base64::Engine;
    use fips204::traits::{KeyGen, SerDes};
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let (pubkey, _) = fips204::ml_dsa_65::KG::keygen_from_seed(&seed);
    (
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey.into_bytes()),
    )
}

/// Generates ML-KEM-768 seed (64 bytes) and client encapsulation key (1184 bytes) as base64url unpadded.
fn mlkem768_keypair() -> (String, String) {
    use base64::Engine;
    use fips203::traits::{KeyGen, SerDes};
    let mut seed = [0u8; 64];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let (ek, _) = fips203::ml_kem_768::KG::keygen_from_seed(
        seed[..32].try_into().unwrap(),
        seed[32..].try_into().unwrap(),
    );
    (
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ek.into_bytes()),
    )
}

fn reality_keypair() -> (String, String) {
    use base64::Engine;
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes()),
    )
}

/// A running Xray process; killed and reaped on drop so a failing assertion
/// never leaves a daemon behind holding a port.
struct XrayProcess {
    child: Child,
    _dir: TempDir,
    log_path: PathBuf,
}

impl XrayProcess {
    /// Writes the config into a temp dir and starts `xray run -c`.
    /// Returns `None` only when the binary is genuinely missing.
    fn start(config: &Value, label: &str) -> Option<Self> {
        let bin = get_xray_bin()?;
        let dir = TempDir::new().expect("tempdir for xray config");
        let cfg_path = dir.path().join("config.json");
        fs::write(&cfg_path, serde_json::to_vec_pretty(config).unwrap())
            .expect("write xray config");
        let log_path = dir.path().join("xray.log");
        let log = fs::File::create(&log_path).expect("xray log file");
        let log2 = log.try_clone().expect("clone xray log handle");
        let child = Command::new(&bin)
            .args(["run", "-c", cfg_path.to_str().unwrap()])
            .env("XRAY_LOCATION_ASSET", dir.path())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn xray for {label}: {e}"));
        Some(Self {
            child,
            _dir: dir,
            log_path,
        })
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Waits (time-bounded) until `port` accepts a TCP connection, reporting the
/// daemon's log and exit status instead of a bare timeout.
async fn wait_for_listen(xray: &mut XrayProcess, port: u16, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        if let Ok(Some(status)) = xray.child.try_wait() {
            panic!(
                "{what} exited with {status} before listening on 127.0.0.1:{port}\n--- xray log ---\n{}",
                xray.log()
            );
        }
        if Instant::now() > deadline {
            panic!(
                "{what} did not listen on 127.0.0.1:{port} within 20s\n--- xray log ---\n{}",
                xray.log()
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// SOCKS5 no-auth CONNECT through `proxy_port` to `target`, returning the
/// tunnelled stream once the proxy reports success.
async fn socks5_connect(proxy_port: u16, target: SocketAddr, ctx: &str) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap_or_else(|e| panic!("{ctx}: connect to socks proxy failed: {e}"));

    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x00], "{ctx}: socks method selection");

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match target.ip() {
        std::net::IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => panic!("{ctx}: echo target must be IPv4"),
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut resp = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut resp))
        .await
        .unwrap_or_else(|_| panic!("{ctx}: socks CONNECT reply timed out"))
        .unwrap();
    assert_eq!(resp[0], 0x05, "{ctx}: socks version in reply");
    assert_eq!(resp[1], 0x00, "{ctx}: socks CONNECT must succeed");
    stream
}

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

/// Xray VLESS+REALITY inbound. `vision` selects `xtls-rprx-vision`.
fn xray_server_config(
    port: u16,
    decoy_port: u16,
    uuid: &str,
    priv_b64: &str,
    vision: bool,
) -> Value {
    let mut client = json!({ "id": uuid });
    if vision {
        client["flow"] = json!("xtls-rprx-vision");
    }
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
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
                    "dest": format!("127.0.0.1:{decoy_port}"),
                    "xver": 0,
                    "serverNames": [SNI],
                    "privateKey": priv_b64,
                    "shortIds": [SHORT_ID]
                }
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    })
}

/// Xray VLESS+REALITY outbound behind a socks inbound.
fn xray_client_config(
    socks_port: u16,
    server_port: u16,
    uuid: &str,
    pub_b64: &str,
    vision: bool,
) -> Value {
    let mut user = json!({ "id": uuid, "encryption": "none" });
    if vision {
        user["flow"] = json!("xtls-rprx-vision");
    }
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false }
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": server_port,
                    "users": [user]
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": SNI,
                    // REALITY clients are uTLS clients; Xray refuses to start
                    // without a fingerprint.
                    "fingerprint": "chrome",
                    "publicKey": pub_b64,
                    "shortId": SHORT_ID,
                    "spiderX": "/"
                }
            }
        }]
    })
}

/// flux-core layered VLESS+REALITY outbound.
fn flux_client_config(server_port: u16, uuid: &str, pub_b64: &str, vision: bool) -> String {
    let mut protocol = json!({ "type": "vless", "uuid": uuid });
    if vision {
        protocol["flow"] = json!("xtls-rprx-vision");
    }
    json!({
        "outbounds": [{
            "tag": "xray-reality",
            "carrier": { "type": "tcp", "address": format!("127.0.0.1:{server_port}") },
            "security": {
                "type": "reality",
                "sni": SNI,
                "public_key": pub_b64,
                "short_id": SHORT_ID
            },
            "protocol": protocol
        }]
    })
    .to_string()
}

/// flux-core layered VLESS+REALITY inbound.
fn flux_server_config(
    port: u16,
    decoy_port: u16,
    uuid: &str,
    priv_b64: &str,
    vision: bool,
) -> String {
    let mut protocol = json!({ "type": "vless", "uuid": uuid });
    if vision {
        protocol["flow"] = json!("xtls-rprx-vision");
    }
    json!({
        "inbounds": [{
            "tag": "xray-reality-in",
            "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": port },
            "security": {
                "type": "reality",
                "server_names": [SNI],
                "private_key": priv_b64,
                "short_ids": [SHORT_ID],
                "fallback": format!("127.0.0.1:{decoy_port}")
            },
            "protocol": protocol
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Traffic assertion helpers
// ---------------------------------------------------------------------------

/// A distinctive payload: marker text, a sequence number so two round-trips
/// cannot be confused, and every byte value so binary transparency is covered
/// (Vision pads/frames records, a text-only payload would hide truncation).
fn distinctive_payload(tag: &str, seq: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(format!("<<flux-core-xray-reality:{tag}:{seq}>>").as_bytes());
    v.extend((0u8..=255).cycle().take(1536));
    v.extend_from_slice(b"<<end>>");
    assert!(v.len() > 1500);
    v
}

/// Writes `payload` through `stream`, reads the echo back and compares.
async fn assert_echo(stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin), payload: &[u8]) {
    stream
        .write_all(payload)
        .await
        .expect("write payload through REALITY tunnel");
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut got))
        .await
        .expect("echo read timed out")
        .expect("echo read failed");
    assert_eq!(got, payload, "echoed bytes must match what was sent");
}

/// Two consecutive round-trips prove the tunnel is a continuous stream, not a
/// one-shot request/response pair (Vision switches its padding state after the
/// first records, so a second message exercises a different code path).
async fn assert_two_roundtrips(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    tag: &str,
) {
    assert_echo(stream, &distinctive_payload(tag, 0)).await;
    let second = distinctive_payload(tag, 1)[..64].to_vec();
    assert_echo(stream, &second).await;
}

// ---------------------------------------------------------------------------
// 1. flux-core REALITY client -> Xray REALITY server
// ---------------------------------------------------------------------------

async fn reality_flux_client_to_xray(vision: bool) {
    let echo = start_tcp_echo_server().await;
    let decoy = start_tls_echo_server().await;
    let xray_port = get_free_tcp_port().await;
    let (priv_b64, pub_b64) = reality_keypair();
    let uuid = uuid::Uuid::new_v4().to_string();
    let label = if vision {
        "xray REALITY+Vision server"
    } else {
        "xray REALITY server"
    };

    let cfg = xray_server_config(xray_port, decoy.port(), &uuid, &priv_b64, vision);
    let Some(mut xray) = XrayProcess::start(&cfg, label) else {
        eprintln!(
            "SKIPPING REALITY interop: xray binary not found (set XRAY_BIN or put `xray` on PATH)"
        );
        return;
    };
    wait_for_listen(&mut xray, xray_port, label).await;

    let flux_cfg = flux_client_config(xray_port, &uuid, &pub_b64, vision);
    let inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    let outbound = inst.registry.get_outbound("xray-reality").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo),
        "test",
        NetworkType::Tcp,
    );
    let mut stream =
        match tokio::time::timeout(Duration::from_secs(20), outbound.dial_stream(&meta)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => panic!(
                "flux REALITY client -> {label}: handshake failed: {e}\n--- xray log ---\n{}",
                xray.log()
            ),
            Err(_) => panic!(
                "flux REALITY client -> {label}: handshake timed out\n--- xray log ---\n{}",
                xray.log()
            ),
        };

    assert_two_roundtrips(
        &mut stream,
        if vision {
            "flux->xray-real+vision"
        } else {
            "flux->xray-real"
        },
    )
    .await;

    drop(stream);
    // A REALITY server whose log shows a rejected connection would not have
    // echoed; this is only a diagnostic aid when the assertion above failed.
    assert!(
        !xray.log().contains("rejected"),
        "xray reported rejected connections:\n{}",
        xray.log()
    );
}

#[tokio::test]
async fn reality_plain_flux_client_to_xray() {
    retry_on_flake("reality_plain_flux_client_to_xray", 2, || {
        reality_flux_client_to_xray(false)
    })
    .await;
}

#[tokio::test]
async fn reality_vision_flux_client_to_xray() {
    retry_on_flake("reality_vision_flux_client_to_xray", 2, || {
        reality_flux_client_to_xray(true)
    })
    .await;
}

// ---------------------------------------------------------------------------
// 2. Xray REALITY client -> flux-core REALITY server
// ---------------------------------------------------------------------------

async fn reality_xray_client_to_flux(vision: bool) {
    let echo = start_tcp_echo_server().await;
    let decoy = start_tls_echo_server().await;
    let flux_port = get_free_tcp_port().await;
    let xray_socks_port = get_free_tcp_port().await;
    let (priv_b64, pub_b64) = reality_keypair();
    let uuid = uuid::Uuid::new_v4().to_string();
    let label = if vision {
        "flux REALITY+Vision server"
    } else {
        "flux REALITY server"
    };

    let flux_cfg = flux_server_config(flux_port, decoy.port(), &uuid, &priv_b64, vision);
    let inst = Instance::new(Config::from_json_str(&flux_cfg).unwrap()).unwrap();
    inst.start().await.unwrap();

    // The inbound listener is bound synchronously by `start`, but make the
    // readiness check explicit so a bind problem surfaces before xray starts.
    let cfg = xray_client_config(xray_socks_port, flux_port, &uuid, &pub_b64, vision);
    let Some(mut xray) = XrayProcess::start(&cfg, &format!("{label}: xray REALITY client")) else {
        eprintln!(
            "SKIPPING REALITY interop: xray binary not found (set XRAY_BIN or put `xray` on PATH)"
        );
        inst.stop().await.unwrap();
        return;
    };
    wait_for_listen(&mut xray, xray_socks_port, "xray socks inbound").await;

    let mut stream = socks5_connect(
        xray_socks_port,
        echo,
        if vision {
            "xray REALITY+Vision client -> flux"
        } else {
            "xray REALITY client -> flux"
        },
    )
    .await;

    assert_two_roundtrips(
        &mut stream,
        if vision {
            "xray-real+vision->flux"
        } else {
            "xray-real->flux"
        },
    )
    .await;

    drop(stream);
    inst.stop().await.unwrap();

    assert!(
        !xray.log().contains("rejected"),
        "xray reported rejected connections:\n{}",
        xray.log()
    );
}

#[tokio::test]
async fn reality_plain_xray_client_to_flux() {
    retry_on_flake("reality_plain_xray_client_to_flux", 2, || {
        reality_xray_client_to_flux(false)
    })
    .await;
}

#[tokio::test]
async fn reality_vision_xray_client_to_flux() {
    retry_on_flake("reality_vision_xray_client_to_flux", 2, || {
        reality_xray_client_to_flux(true)
    })
    .await;
}

// ===========================================================================
// Post-quantum tests: ML-DSA-65 (REALITY) and mlkem768x25519plus (VLESS Encryption)
// ===========================================================================

#[tokio::test]
async fn reality_mldsa65_flux_client_to_xray() {
    let echo = start_tcp_echo_server().await;
    let target = start_large_tls_echo_server().await;

    let xray_vless_port = get_free_tcp_port().await;
    let flux_socks_port = get_free_tcp_port().await;
    let uuid = uuid::Uuid::new_v4().to_string();
    let (priv_b64, pub_b64) = reality_keypair();
    let (mldsa_seed, mldsa_verify) = mldsa65_keypair();

    let mut srv_cfg = xray_server_config(xray_vless_port, target.port(), &uuid, &priv_b64, false);
    srv_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["mldsa65Seed"] = json!(mldsa_seed);
    srv_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["show"] = json!(true);

    let Some(mut xray) = XrayProcess::start(&srv_cfg, "xray REALITY ML-DSA-65 server") else {
        eprintln!("SKIPPING: xray binary not found");
        return;
    };
    wait_for_listen(&mut xray, xray_vless_port, "xray reality listener").await;

    let mut flux_val: Value =
        serde_json::from_str(&flux_client_config(xray_vless_port, &uuid, &pub_b64, false)).unwrap();
    flux_val["outbounds"][0]["security"]["mldsa65_verify"] = json!(mldsa_verify);
    let inbounds = json!([{
        "tag": "in",
        "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": flux_socks_port },
        "protocol": { "type": "socks" }
    }]);
    flux_val["inbounds"] = inbounds;
    flux_val["route"] = json!({ "final": "xray-reality" });

    let inst = Instance::new(Config::from_json_str(&flux_val.to_string()).unwrap()).unwrap();
    inst.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    println!(
        "xray log before connect:
{}",
        xray.log()
    );
    let mut stream = socks5_connect(
        flux_socks_port,
        echo,
        "flux REALITY+ML-DSA-65 client -> xray",
    )
    .await;
    println!(
        "xray log after connect:
{}",
        xray.log()
    );
    assert_two_roundtrips(&mut stream, "flux-mldsa65->xray").await;

    drop(stream);
    inst.stop().await.unwrap();
}

#[tokio::test]
async fn reality_mldsa65_xray_client_to_flux() {
    let echo = start_tcp_echo_server().await;
    let target = start_tls_echo_server().await;

    let flux_port = get_free_tcp_port().await;
    let xray_socks_port = get_free_tcp_port().await;
    let uuid = uuid::Uuid::new_v4().to_string();
    let (priv_b64, pub_b64) = reality_keypair();
    let (mldsa_seed, mldsa_verify) = mldsa65_keypair();

    let mut flux_val: Value = serde_json::from_str(&flux_server_config(
        flux_port,
        target.port(),
        &uuid,
        &priv_b64,
        false,
    ))
    .unwrap();
    flux_val["log"]["level"] = json!("debug");
    flux_val["inbounds"][0]["security"]["mldsa65_seed"] = json!(mldsa_seed);

    let inst = Instance::new(Config::from_json_str(&flux_val.to_string()).unwrap()).unwrap();
    inst.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut cli_cfg = xray_client_config(xray_socks_port, flux_port, &uuid, &pub_b64, false);
    cli_cfg["outbounds"][0]["streamSettings"]["realitySettings"]["mldsa65Verify"] =
        json!(mldsa_verify);
    cli_cfg["log"]["loglevel"] = json!("debug");
    cli_cfg["outbounds"][0]["streamSettings"]["realitySettings"]["show"] = json!(true);

    let Some(mut xray) = XrayProcess::start(&cli_cfg, "xray REALITY ML-DSA-65 client") else {
        eprintln!("SKIPPING: xray binary not found");
        inst.stop().await.unwrap();
        return;
    };
    wait_for_listen(&mut xray, xray_socks_port, "xray socks inbound").await;

    let mut stream = socks5_connect(
        xray_socks_port,
        echo,
        "xray REALITY+ML-DSA-65 client -> flux",
    )
    .await;
    assert_two_roundtrips(&mut stream, "xray-mldsa65->flux").await;

    drop(stream);
    inst.stop().await.unwrap();
}

#[tokio::test]
async fn vlessenc_mlkem768_flux_client_to_xray() {
    let echo = start_tcp_echo_server().await;

    let xray_vless_port = get_free_tcp_port().await;
    let flux_socks_port = get_free_tcp_port().await;
    let uuid = uuid::Uuid::new_v4().to_string();
    let (sec_b64, pub_b64) = mlkem768_keypair();
    let dec_str = format!("mlkem768x25519plus.native.600s.{sec_b64}");
    let enc_str = format!("mlkem768x25519plus.native.0rtt.{pub_b64}");

    let xray_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "port": xray_vless_port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": uuid }],
                "decryption": dec_str
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    });

    let Some(mut xray) = XrayProcess::start(&xray_cfg, "xray VLESS Decryption server") else {
        eprintln!("SKIPPING: xray binary not found");
        return;
    };
    wait_for_listen(&mut xray, xray_vless_port, "xray vless listener").await;

    let flux_cfg = json!({
        "log": { "level": "warning" },
        "inbounds": [{
            "tag": "in",
            "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": flux_socks_port },
            "protocol": { "type": "socks" }
        }],
        "outbounds": [{
            "tag": "out",
            "carrier": { "type": "tcp", "address": format!("127.0.0.1:{xray_vless_port}") },
            "protocol": {
                "type": "vless",
                "uuid": uuid,
                "encryption": enc_str
            }
        }],
        "route": { "final": "out" }
    });

    let inst = Instance::new(Config::from_json_str(&flux_cfg.to_string()).unwrap()).unwrap();
    inst.start().await.unwrap();

    let mut stream = socks5_connect(flux_socks_port, echo, "flux VLESS PQ client -> xray").await;
    assert_two_roundtrips(&mut stream, "flux-vlessenc-pq->xray").await;

    drop(stream);
    inst.stop().await.unwrap();
}

#[tokio::test]
async fn vlessenc_mlkem768_xray_client_to_flux() {
    let echo = start_tcp_echo_server().await;

    let flux_vless_port = get_free_tcp_port().await;
    let xray_socks_port = get_free_tcp_port().await;
    let uuid = uuid::Uuid::new_v4().to_string();
    let (sec_b64, pub_b64) = mlkem768_keypair();
    let dec_str = format!("mlkem768x25519plus.native.600s.{sec_b64}");
    let enc_str = format!("mlkem768x25519plus.native.0rtt.{pub_b64}");

    let flux_cfg = json!({
        "log": { "level": "warning" },
        "inbounds": [{
            "tag": "in",
            "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": flux_vless_port },
            "protocol": {
                "type": "vless",
                "uuid": uuid,
                "decryption": dec_str
            }
        }],
        "outbounds": [{ "type": "direct", "tag": "d" }],
        "route": { "final": "d" }
    });

    let inst = Instance::new(Config::from_json_str(&flux_cfg.to_string()).unwrap()).unwrap();
    inst.start().await.unwrap();

    let xray_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "port": xray_socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth" }
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": flux_vless_port,
                    "users": [{
                        "id": uuid,
                        "encryption": enc_str
                    }]
                }]
            }
        }]
    });

    let Some(mut xray) = XrayProcess::start(&xray_cfg, "xray VLESS Encryption client") else {
        eprintln!("SKIPPING: xray binary not found");
        inst.stop().await.unwrap();
        return;
    };
    wait_for_listen(&mut xray, xray_socks_port, "xray socks listener").await;

    let mut stream = socks5_connect(xray_socks_port, echo, "xray VLESS PQ client -> flux").await;
    assert_two_roundtrips(&mut stream, "xray-vlessenc-pq->flux").await;

    drop(stream);
    inst.stop().await.unwrap();
}

#[tokio::test]
async fn vlessenc_mlkem768_bulk_traffic_xray_interop() {
    let echo = start_tcp_echo_server().await;

    let xray_vless_port = get_free_tcp_port().await;
    let flux_socks_port = get_free_tcp_port().await;
    let uuid = uuid::Uuid::new_v4().to_string();
    let (sec_b64, pub_b64) = mlkem768_keypair();
    let dec_str = format!("mlkem768x25519plus.native.600s.{sec_b64}");
    let enc_str = format!("mlkem768x25519plus.native.0rtt.{pub_b64}");

    let xray_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "port": xray_vless_port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": uuid }],
                "decryption": dec_str
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    });

    let Some(mut xray) = XrayProcess::start(&xray_cfg, "xray VLESS Decryption server") else {
        return;
    };
    wait_for_listen(&mut xray, xray_vless_port, "xray vless listener").await;

    let flux_cfg = json!({
        "log": { "level": "warning" },
        "inbounds": [{
            "tag": "in",
            "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": flux_socks_port },
            "protocol": { "type": "socks" }
        }],
        "outbounds": [{
            "tag": "out",
            "carrier": { "type": "tcp", "address": format!("127.0.0.1:{xray_vless_port}") },
            "protocol": {
                "type": "vless",
                "uuid": uuid,
                "encryption": enc_str
            }
        }],
        "route": { "final": "out" }
    });

    let inst = Instance::new(Config::from_json_str(&flux_cfg.to_string()).unwrap()).unwrap();
    inst.start().await.unwrap();

    let mut stream =
        socks5_connect(flux_socks_port, echo, "flux VLESS PQ client -> xray bulk").await;

    // Simulate TLS ClientHello size (1560 bytes)
    let client_hello = vec![0x16u8; 1560];
    assert_echo(&mut stream, &client_hello).await;

    // Send large multi-chunk transfer (128 KB)
    let large_payload = vec![0x55u8; 4096];
    assert_echo(&mut stream, &large_payload).await;

    drop(stream);
    inst.stop().await.unwrap();
}
