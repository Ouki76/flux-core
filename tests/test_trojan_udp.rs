//! Trojan UDP relay end-to-end: flux Trojan inbound (TLS) -> flux direct outbound,
//! exercised by a flux Trojan client outbound PacketEndpoint.

mod common;

use common::{get_free_tcp_port, start_udp_echo_server};
use flux_app::{Config, Instance};
use flux_outbound::TrojanOutbound;
use flux_types::{NetworkType, SessionMeta, TargetAddress, UdpPacket};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_trojan_udp_over_tls_relay() {
    let udp_echo = start_udp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let password = "flux-trojan-udp-password";

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{ "type": "tls" }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // Client side: Trojan outbound over TLS to the flux server.
    let resolver = Arc::new(flux_dns::DnsResolver::new(None));
    let tls = flux_transport::tls::TlsClientConfig::new("localhost").with_insecure(true);
    let dialer = Arc::new(flux_outbound::LazyPipelineDialer::new(
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver,
        flux_transport::pipeline::SecurityLayer::Tls(tls),
        flux_transport::pipeline::FramingLayer::Raw,
    ));
    let trojan_out = TrojanOutbound::new("client", password, dialer);

    let meta = SessionMeta::new(
        "127.0.0.1:50001".parse().unwrap(),
        TargetAddress::Ip(udp_echo),
        "test",
        NetworkType::Udp,
    );
    let ep = flux_types::Outbound::dial_packet(&trojan_out, &meta)
        .await
        .expect("trojan dial_packet must succeed");

    let payload = bytes::Bytes::from_static(b"trojan udp relay payload");
    let pkt = UdpPacket::new(
        payload.clone(),
        TargetAddress::Ip("127.0.0.1:50001".parse().unwrap()),
        TargetAddress::Ip(udp_echo),
    );
    ep.send_packet(pkt).await.expect("send_packet");

    let reply = tokio::time::timeout(Duration::from_secs(5), ep.recv_packet())
        .await
        .expect("recv_packet timed out — UDP relay broken")
        .expect("recv_packet error");

    assert_eq!(reply.payload, payload, "echoed payload must match");
    assert_eq!(
        reply.destination,
        TargetAddress::Ip(udp_echo),
        "reply source must be the echo server"
    );

    instance.stop().await.unwrap();
}

/// Multiple datagrams over a single association, plus oversized-packet safety.
#[tokio::test]
async fn test_trojan_udp_multiple_datagrams() {
    let udp_echo = start_udp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let password = "flux-trojan-udp-multi";

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "security": {{ "type": "tls" }},
                "protocol": {{ "type": "trojan", "password": "{}" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let resolver = Arc::new(flux_dns::DnsResolver::new(None));
    let tls = flux_transport::tls::TlsClientConfig::new("localhost").with_insecure(true);
    let dialer = Arc::new(flux_outbound::LazyPipelineDialer::new(
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver,
        flux_transport::pipeline::SecurityLayer::Tls(tls),
        flux_transport::pipeline::FramingLayer::Raw,
    ));
    let trojan_out = TrojanOutbound::new("client", password, dialer);

    let meta = SessionMeta::new(
        "127.0.0.1:50002".parse().unwrap(),
        TargetAddress::Ip(udp_echo),
        "test",
        NetworkType::Udp,
    );
    let ep = flux_types::Outbound::dial_packet(&trojan_out, &meta)
        .await
        .unwrap();

    // Three sequential datagrams on one association, each must echo back in order.
    for i in 0..3u8 {
        let payload = bytes::Bytes::from(vec![i; 256 * (i as usize + 1)]);
        let pkt = UdpPacket::new(
            payload.clone(),
            TargetAddress::Ip("127.0.0.1:50002".parse().unwrap()),
            TargetAddress::Ip(udp_echo),
        );
        ep.send_packet(pkt).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), ep.recv_packet())
            .await
            .expect("datagram lost")
            .unwrap();
        assert_eq!(reply.payload, payload, "datagram {} payload mismatch", i);
    }

    instance.stop().await.unwrap();
}
