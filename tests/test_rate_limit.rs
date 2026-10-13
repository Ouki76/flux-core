mod common;

use common::get_free_tcp_port;
use flux_app::{Config, Instance};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Performs a SOCKS5 handshake; returns Ok(stream) when the server accepted
/// the connection and answered the greeting, Err when rejected/closed.
async fn socks5_greet(port: u16) -> Option<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    s.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
    let mut buf = [0u8; 2];
    // Rejected connections are closed without a greeting reply.
    tokio::time::timeout(std::time::Duration::from_secs(2), s.read_exact(&mut buf))
        .await
        .ok()?
        .ok()?;
    if buf == [0x05, 0x00] { Some(s) } else { None }
}

#[tokio::test]
async fn test_inbound_rate_limit_per_ip() {
    let port = get_free_tcp_port().await;
    let raw_config = format!(
        r#"{{
            "inbounds": [
                {{
                    "tag": "socks-in",
                    "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                    "protocol": {{ "type": "socks" }},
                    "rate_limit": {{ "max_conn_per_ip_per_sec": 2, "burst": 2 }}
                }}
            ],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        port
    );

    let cfg = Config::from_json_str(&raw_config).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // Burst of 2 allowed.
    let c1 = socks5_greet(port).await;
    let c2 = socks5_greet(port).await;
    assert!(c1.is_some() && c2.is_some(), "first connections must pass");

    // 3rd connection within the same second must be rejected (bucket empty).
    let c3 = socks5_greet(port).await;
    assert!(
        c3.is_none(),
        "connection beyond per-IP rate must be rejected"
    );

    // After ~600ms the bucket refills by >1 token (rate = 2/s).
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    let c4 = socks5_greet(port).await;
    assert!(
        c4.is_some(),
        "connection must be allowed after bucket refill"
    );

    drop((c1, c2, c4));
    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_inbound_rate_limit_max_concurrent() {
    let port = get_free_tcp_port().await;
    let raw_config = format!(
        r#"{{
            "inbounds": [
                {{
                    "tag": "socks-in",
                    "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                    "protocol": {{ "type": "socks" }},
                    "rate_limit": {{ "max_concurrent": 1 }}
                }}
            ],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        port
    );

    let cfg = Config::from_json_str(&raw_config).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // First connection occupies the single slot (held open).
    let c1 = socks5_greet(port).await;
    assert!(c1.is_some(), "first connection must pass");

    // Second concurrent connection is rejected while the first is alive.
    let c2 = socks5_greet(port).await;
    assert!(
        c2.is_none(),
        "concurrent connection must be rejected at cap"
    );

    // Releasing the slot frees capacity.
    drop(c1);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c3 = socks5_greet(port).await;
    assert!(
        c3.is_some(),
        "connection must be allowed after slot release"
    );

    drop(c3);
    instance.stop().await.unwrap();
}
