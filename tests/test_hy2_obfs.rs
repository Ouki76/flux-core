//! Hysteria 2 Salamander obfuscation e2e: flux hy2 inbound (obfs) <- flux hy2
//! outbound (obfs). Also asserts that a non-obfs client cannot connect.

mod common;

use common::{get_free_tcp_port, start_tcp_echo_server};
use flux_app::{Config, Instance};
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn hy2_config(
    port: u16,
    password: &str,
    obfs_password: Option<&str>,
    server: Option<u16>,
) -> String {
    let obfs = match obfs_password {
        Some(p) => format!(r#", "obfs": "salamander", "obfs_password": "{}""#, p),
        None => String::new(),
    };
    if let Some(srv_port) = server {
        format!(
            r#"{{
                "outbounds": [{{
                    "tag": "hy2-out",
                    "carrier": {{ "type": "udp", "address": "127.0.0.1:{}" }},
                    "security": {{ "type": "tls", "sni": "localhost", "insecure": true }},
                    "protocol": {{ "type": "hysteria2", "password": "{}"{} }}
                }}]
            }}"#,
            srv_port, password, obfs
        )
    } else {
        format!(
            r#"{{
                "inbounds": [{{
                    "tag": "hy2-in",
                    "carrier": {{ "type": "udp", "listen": "127.0.0.1", "listen_port": {} }},
                    "protocol": {{ "type": "hysteria2", "password": "{}"{} }}
                }}],
                "outbounds": [{{"type": "direct", "tag": "direct"}}]
            }}"#,
            port, password, obfs
        )
    }
}

#[tokio::test]
async fn test_hy2_salamander_obfs_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let srv_cfg =
        Config::from_json_str(&hy2_config(srv_port, "hy2-pw", Some("obfs-secret"), None)).unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    let cli_cfg = Config::from_json_str(&hy2_config(
        0,
        "hy2-pw",
        Some("obfs-secret"),
        Some(srv_port),
    ))
    .unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let hy2_out = cli_instance.registry.get_outbound("hy2-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:40041".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut stream = tokio::time::timeout(Duration::from_secs(10), hy2_out.dial_stream(&meta))
        .await
        .expect("obfs hy2 dial timed out")
        .expect("obfs hy2 dial failed");

    let payload = b"salamander obfuscated hy2 payload";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);

    srv_instance.stop().await.unwrap();
}

/// A non-obfs client must NOT be able to handshake with an obfs server:
/// every datagram from it fails deobfuscation and is dropped.
#[tokio::test]
async fn test_hy2_obfs_rejects_plain_client() {
    let _echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let srv_cfg =
        Config::from_json_str(&hy2_config(srv_port, "hy2-pw", Some("obfs-secret"), None)).unwrap();
    let srv_instance = Instance::new(srv_cfg).unwrap();
    srv_instance.start().await.unwrap();

    // Client WITHOUT obfs.
    let cli_cfg = Config::from_json_str(&hy2_config(0, "hy2-pw", None, Some(srv_port))).unwrap();
    let cli_instance = Instance::new(cli_cfg).unwrap();
    let hy2_out = cli_instance.registry.get_outbound("hy2-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:40042".parse().unwrap(),
        TargetAddress::Ip(_echo_addr),
        "test",
        NetworkType::Tcp,
    );
    let result = tokio::time::timeout(Duration::from_secs(12), hy2_out.dial_stream(&meta)).await;
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "plain client must not connect to an obfs server"
    );

    srv_instance.stop().await.unwrap();
}
