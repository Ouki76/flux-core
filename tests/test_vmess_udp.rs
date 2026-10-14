//! VMess UDP-over-TCP relay end-to-end: flux VMess inbound -> flux direct outbound,
//! exercised by a flux VMess client outbound PacketEndpoint.

mod common;

use common::{get_free_tcp_port, start_udp_echo_server};
use flux_app::{Config, Instance};
use flux_types::{NetworkType, SessionMeta, TargetAddress, UdpPacket};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_vmess_udp_over_tcp_relay() {
    let udp_echo = start_udp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let uuid = "a1b2c3d4-e5f6-7890-1234-56789abcdef0";

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "protocol": {{ "type": "vmess", "uuid": "{}" }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, uuid
    ))
    .unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // Client side: VMess outbound to the flux server.
    let resolver = Arc::new(flux_dns::DnsResolver::new(None));
    let dialer = Arc::new(flux_outbound::LazyPipelineDialer::new(
        TargetAddress::domain("127.0.0.1", srv_port),
        resolver,
        flux_transport::pipeline::SecurityLayer::None,
        flux_transport::pipeline::FramingLayer::Raw,
    ));
    let vmess_out = flux_outbound::VmessOutbound::new(
        "client",
        uuid::Uuid::parse_str(uuid).unwrap(),
        Some("aes-128-gcm"),
        dialer,
    );

    let meta = SessionMeta::new(
        "127.0.0.1:50011".parse().unwrap(),
        TargetAddress::Ip(udp_echo),
        "test",
        NetworkType::Udp,
    );
    let ep = flux_types::Outbound::dial_packet(&vmess_out, &meta)
        .await
        .expect("vmess dial_packet must succeed");

    // Two sequential datagrams on one association.
    for i in 0..2u8 {
        let payload = bytes::Bytes::from(vec![0xA0 + i; 128 * (i as usize + 1)]);
        let pkt = UdpPacket::new(
            payload.clone(),
            TargetAddress::Ip("127.0.0.1:50011".parse().unwrap()),
            TargetAddress::Ip(udp_echo),
        );
        ep.send_packet(pkt).await.expect("send_packet");
        let reply = tokio::time::timeout(Duration::from_secs(5), ep.recv_packet())
            .await
            .expect("datagram lost — VMess UDP relay broken")
            .expect("recv_packet error");
        assert_eq!(reply.payload, payload, "datagram {} payload mismatch", i);
    }

    instance.stop().await.unwrap();
}
