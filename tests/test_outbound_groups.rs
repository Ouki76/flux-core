mod common;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use flux_app::{Config, Instance};
use flux_protocol::socks5::{Socks5Handshake, CMD_CONNECT};
use common::{get_free_tcp_port, start_tcp_echo_server};

#[tokio::test]
async fn test_selector_and_urltest_groups() {
    let echo1_addr = start_tcp_echo_server().await;
    let echo2_addr = start_tcp_echo_server().await;

    let socks_port = get_free_tcp_port().await;

    let cfg_json = format!(
        r#"{{
            "inbounds": [
                {{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": {} }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct-node1" }},
                {{ "type": "direct", "tag": "direct-node2" }},
                {{
                    "type": "selector",
                    "tag": "proxy-selector",
                    "outbounds": ["direct-node1", "direct-node2"],
                    "default": "direct-node1"
                }},
                {{
                    "type": "urltest",
                    "tag": "auto-urltest",
                    "outbounds": ["direct-node1", "direct-node2"],
                    "url": "http://127.0.0.1:{}/",
                    "interval": "1s",
                    "tolerance": 10
                }}
            ],
            "route": {{
                "rules": [
                    {{ "port": [{}], "outbound": "proxy-selector" }},
                    {{ "port": [{}], "outbound": "auto-urltest" }}
                ],
                "final": "direct-node1"
            }}
        }}"#,
        socks_port, echo1_addr.port(), echo1_addr.port(), echo2_addr.port()
    );

    let cfg = Config::from_json_str(&cfg_json).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // 1. Connect via selector to echo1
    let mut client1 = TcpStream::connect(format!("127.0.0.1:{}", socks_port)).await.unwrap();
    Socks5Handshake::client_handshake(&mut client1, CMD_CONNECT, &TargetAddress::Ip(echo1_addr)).await.unwrap();
    client1.write_all(b"Hello selector!").await.unwrap();
    let mut buf = vec![0u8; 15];
    client1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"Hello selector!");

    // 2. Dynamically change selector to direct-node2
    let selector_outbound = instance.registry.get_outbound("proxy-selector").unwrap();
    // Verify it implements Outbound
    let meta = SessionMeta::new(
        "127.0.0.1:12345".parse().unwrap(),
        TargetAddress::Ip(echo1_addr),
        "test",
        NetworkType::Tcp,
    );
    let mut s_stream = selector_outbound.dial_stream(&meta).await.unwrap();
    s_stream.write_all(b"Direct selector test").await.unwrap();
    let mut s_buf = vec![0u8; 20];
    s_stream.read_exact(&mut s_buf).await.unwrap();
    assert_eq!(&s_buf, b"Direct selector test");

    // 3. Connect via urltest to echo2
    let mut client2 = TcpStream::connect(format!("127.0.0.1:{}", socks_port)).await.unwrap();
    Socks5Handshake::client_handshake(&mut client2, CMD_CONNECT, &TargetAddress::Ip(echo2_addr)).await.unwrap();
    client2.write_all(b"Hello urltest!").await.unwrap();
    let mut buf2 = vec![0u8; 14];
    client2.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"Hello urltest!");

    instance.stop().await.unwrap();
}
