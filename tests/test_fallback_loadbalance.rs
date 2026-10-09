mod common;

use common::{get_free_tcp_port, start_tcp_echo_server};
use flux_app::{Config, Instance};
use flux_protocol::socks5::{CMD_CONNECT, Socks5Handshake};
use flux_types::TargetAddress;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_fallback_outbound_failover() {
    let working_echo = start_tcp_echo_server().await;
    let dead_port = get_free_tcp_port().await; // Nothing listening on this port

    let socks_port = get_free_tcp_port().await;

    let cfg_json = format!(
        r#"{{
            "inbounds": [
                {{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {} }}
            ],
            "outbounds": [
                {{ "type": "socks", "tag": "dead-node", "server": "127.0.0.1", "server_port": {} }},
                {{ "type": "direct", "tag": "working-node" }},
                {{
                    "type": "fallback",
                    "tag": "fallback-group",
                    "outbounds": ["dead-node", "working-node"]
                }}
            ],
            "route": {{
                "rules": [
                    {{ "port": [{}], "outbound": "fallback-group" }}
                ],
                "final": "fallback-group"
            }}
        }}"#,
        socks_port,
        dead_port,
        working_echo.port()
    );

    let cfg = Config::from_json_str(&cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // Connect through SOCKS5 to working_echo via fallback-group
    // First candidate "dead-node" will fail to connect, and fallback-group should failover to "working-node"
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .unwrap();
    Socks5Handshake::client_handshake(&mut client, CMD_CONNECT, &TargetAddress::Ip(working_echo))
        .await
        .unwrap();

    let msg = b"Fallback failover test successfully reached working-node!";
    client.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);

    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_loadbalance_outbound_distribution() {
    let echo1 = start_tcp_echo_server().await;
    let echo2 = start_tcp_echo_server().await;

    let socks_port = get_free_tcp_port().await;

    let cfg_json = format!(
        r#"{{
            "inbounds": [
                {{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {} }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "node-1" }},
                {{ "type": "direct", "tag": "node-2" }},
                {{
                    "type": "loadbalance",
                    "tag": "lb-group",
                    "outbounds": ["node-1", "node-2"],
                    "strategy": "round-robin"
                }}
            ],
            "route": {{
                "rules": [
                    {{ "inbound": ["socks-in"], "outbound": "lb-group" }}
                ],
                "final": "lb-group"
            }}
        }}"#,
        socks_port
    );

    let cfg = Config::from_json_str(&cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // Make 2 connections to echo1 and echo2
    for &target in &[echo1, echo2] {
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
            .await
            .unwrap();
        Socks5Handshake::client_handshake(&mut client, CMD_CONNECT, &TargetAddress::Ip(target))
            .await
            .unwrap();
        client.write_all(b"LoadBalance ping").await.unwrap();
        let mut buf = vec![0u8; 16];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"LoadBalance ping");
    }

    instance.stop().await.unwrap();
}
