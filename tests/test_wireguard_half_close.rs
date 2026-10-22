//! Half-close through the WireGuard datapath.
//!
//! The datapath is a userspace stack on both ends, so `shutdown(SHUT_WR)` is not
//! a kernel detail: it becomes a FIN segment that the client's smoltcp has to
//! emit, the server's smoltcp has to deliver as EOF to the relayed connection,
//! and the reply the peer writes *after* that EOF has to travel back over the
//! same tunnel on a half-closed connection. Nothing here is allowed to be
//! best-effort: a relay that closes the read side when it sees a FIN loses the
//! reply tail, which is exactly the defect this pins down.
//!
//! The peer only replies once it has read EOF, so every byte that arrives
//! provably reached us *after* the FIN.

mod common;

use base64::Engine;
use common::get_free_tcp_port;
use flux_app::{Config, Instance};
use flux_outbound::WireGuardOutbound;
use flux_protocol::wireguard::WireGuardConfig;
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Reply written only after the client's FIN has been read.
const AFTER_FIN_REPLY: &[u8] = b"reply-written-only-after-the-client-finished";

fn b64_key(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
}

/// Accepts one connection, drains it to EOF, then writes `AFTER_FIN_REPLY`.
async fn start_reply_after_eof_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut sink = Vec::new();
        // EOF here can only come from the client's half-close.
        socket.read_to_end(&mut sink).await.unwrap();
        socket.write_all(AFTER_FIN_REPLY).await.unwrap();
        socket.flush().await.unwrap();
        socket.shutdown().await.unwrap();
    });
    addr
}

#[tokio::test]
async fn test_wireguard_half_close_reply_after_fin() {
    let peer_addr = start_reply_after_eof_server().await;
    let wg_port = get_free_tcp_port().await;

    let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pub = X25519PublicKey::from(&server_secret);
    let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pub = X25519PublicKey::from(&client_secret);

    let raw_config = format!(
        r#"{{
            "inbounds": [
                {{
                    "type": "wireguard",
                    "tag": "wg-in",
                    "listen": "127.0.0.1",
                    "listen_port": {},
                    "private_key": "{}",
                    "peers": [{{ "public_key": "{}", "allowed_ips": ["10.0.0.0/24"] }}]
                }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        wg_port,
        b64_key(&server_secret.to_bytes()),
        b64_key(client_pub.as_bytes())
    );

    let instance = Instance::new(Config::from_json_str(&raw_config).unwrap()).unwrap();
    instance.start().await.unwrap();

    let outbound = WireGuardOutbound::new(
        "wg-out",
        WireGuardConfig {
            private_key: client_secret.to_bytes(),
            peer_public_key: *server_pub.as_bytes(),
            preshared_key: None,
            server_address: TargetAddress::Ip(format!("127.0.0.1:{wg_port}").parse().unwrap()),
            local_address: Some("10.0.0.2".parse().unwrap()),
            keepalive_secs: Some(0),
            awg: None,
        },
        Arc::new(flux_dns::DnsResolver::new(None)),
    );

    let meta = SessionMeta::new(
        "10.0.0.2:10000".parse().unwrap(),
        TargetAddress::Ip(peer_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = tokio::time::timeout(
        Duration::from_secs(15),
        flux_types::Outbound::dial_stream(&outbound, &meta),
    )
    .await
    .expect("wireguard TCP dial timed out")
    .expect("wireguard TCP dial must succeed");

    stream.write_all(b"request").await.unwrap();
    // Send the FIN before reading anything: the reply cannot exist yet.
    stream.shutdown().await.unwrap();

    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut reply))
        .await
        .expect("timed out waiting for the reply that follows our FIN")
        .expect("reading the post-FIN reply failed");

    assert_eq!(
        reply, AFTER_FIN_REPLY,
        "the reply written after our half-close was truncated or lost"
    );

    instance.stop().await.unwrap();
}
