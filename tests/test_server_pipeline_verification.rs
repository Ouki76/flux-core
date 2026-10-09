mod common;

use common::{get_free_tcp_port, start_tcp_echo_server};
use flux_app::{Config, Instance};
use flux_transport::pipeline::{ServerFramingLayer, ServerSecurityLayer, ServerTransportPipeline};
use flux_types::{FluxError, NetworkType, SessionMeta, TargetAddress};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_pipeline_raw_roundtrip() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let pipeline = ServerTransportPipeline::raw();

    let srv = tokio::spawn(async move {
        let mut stream = pipeline.unwrap(server_io).await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping!");
        stream.write_all(b"pong!").await.unwrap();
        stream.flush().await.unwrap();
    });

    let mut client = client_io;
    client.write_all(b"ping!").await.unwrap();
    client.flush().await.unwrap();

    let mut resp = [0u8; 5];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"pong!");

    srv.await.unwrap();
}

#[tokio::test]
async fn test_pipeline_unwrap_timeout() {
    let (_client_io, server_io) = tokio::io::duplex(64 * 1024);
    let mut pipeline = ServerTransportPipeline::single(
        ServerSecurityLayer::None,
        ServerFramingLayer::WebSocket {
            path: Some("/ws".into()),
        },
    );
    pipeline.timeout = Duration::from_millis(100);

    let start = std::time::Instant::now();
    let res = pipeline.unwrap(server_io).await;
    let elapsed = start.elapsed();

    assert!(res.is_err(), "Expected timeout error");
    match res {
        Err(FluxError::Timeout(msg)) => {
            assert!(msg.contains("server transport pipeline handshake timed out"));
        }
        _ => panic!("Expected FluxError::Timeout"),
    }
    assert!(elapsed >= Duration::from_millis(90));
}

#[tokio::test]
async fn test_pipeline_websocket_framing() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let pipeline = ServerTransportPipeline::single(
        ServerSecurityLayer::None,
        ServerFramingLayer::WebSocket {
            path: Some("/flux-ws".into()),
        },
    );

    let srv = tokio::spawn(async move {
        let mut stream = pipeline.unwrap(server_io).await.unwrap();
        let mut buf = [0u8; 15];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello ws server");
        stream.write_all(b"hello ws client").await.unwrap();
        stream.flush().await.unwrap();
    });

    let mut client = flux_transport::websocket::client_handshake(
        Box::new(client_io),
        "127.0.0.1",
        "/flux-ws",
        &HashMap::new(),
    )
    .await
    .unwrap();

    client.write_all(b"hello ws server").await.unwrap();
    client.flush().await.unwrap();

    let mut resp = [0u8; 15];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"hello ws client");

    srv.await.unwrap();
}

#[tokio::test]
async fn test_pipeline_websocket_path_mismatch_rejected() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let pipeline = ServerTransportPipeline::single(
        ServerSecurityLayer::None,
        ServerFramingLayer::WebSocket {
            path: Some("/expected-path".into()),
        },
    );

    let srv = tokio::spawn(async move {
        let res = pipeline.unwrap(server_io).await;
        assert!(res.is_err(), "Server must reject mismatched websocket path");
    });

    let client_res = flux_transport::websocket::client_handshake(
        Box::new(client_io),
        "127.0.0.1",
        "/wrong-path",
        &HashMap::new(),
    )
    .await;
    let _ = client_res;

    srv.await.unwrap();
}

#[tokio::test]
async fn test_pipeline_httpupgrade_framing() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let pipeline = ServerTransportPipeline::single(
        ServerSecurityLayer::None,
        ServerFramingLayer::HttpUpgrade {
            path: Some("/flux-upgrade".into()),
        },
    );

    let srv = tokio::spawn(async move {
        let mut stream = pipeline.unwrap(server_io).await.unwrap();
        let mut buf = [0u8; 12];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"upgrade data");
        stream.write_all(b"upgrade reply").await.unwrap();
        stream.flush().await.unwrap();
    });

    let mut client = flux_transport::httpupgrade::client_handshake(
        Box::new(client_io),
        "127.0.0.1",
        "/flux-upgrade",
        &HashMap::new(),
    )
    .await
    .unwrap();

    client.write_all(b"upgrade data").await.unwrap();
    client.flush().await.unwrap();

    let mut resp = [0u8; 13];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"upgrade reply");

    srv.await.unwrap();
}

#[tokio::test]
async fn test_pipeline_http2_framing() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let pipeline =
        ServerTransportPipeline::single(ServerSecurityLayer::None, ServerFramingLayer::Http2);

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let srv = tokio::spawn(async move {
        let mut stream = pipeline.unwrap(server_io).await.unwrap();
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"h2 ping");
        stream.write_all(b"h2 pong").await.unwrap();
        stream.flush().await.unwrap();
        let _ = done_rx.await;
    });

    let mut client = flux_transport::h2::H2Transport::client_handshake(
        Box::new(client_io),
        "127.0.0.1",
        "/h2-path",
        &HashMap::new(),
    )
    .await
    .unwrap();

    client.write_all(b"h2 ping").await.unwrap();
    client.flush().await.unwrap();

    let mut resp = [0u8; 7];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"h2 pong");

    let _ = done_tx.send(());
    srv.await.unwrap();
}

#[tokio::test]
async fn test_pipeline_grpc_framing() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let pipeline =
        ServerTransportPipeline::single(ServerSecurityLayer::None, ServerFramingLayer::Grpc);

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let srv = tokio::spawn(async move {
        let mut stream = pipeline.unwrap(server_io).await.unwrap();
        let mut buf = [0u8; 9];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"grpc ping");
        stream.write_all(b"grpc pong").await.unwrap();
        stream.flush().await.unwrap();
        let _ = done_rx.await;
    });

    let mut client = flux_transport::grpc::GrpcTransport::client_handshake(
        Box::new(client_io),
        "127.0.0.1",
        "GunService",
        &HashMap::new(),
    )
    .await
    .unwrap();

    client.write_all(b"grpc ping").await.unwrap();
    client.flush().await.unwrap();

    let mut resp = [0u8; 9];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"grpc pong");

    let _ = done_tx.send(());
    srv.await.unwrap();
}

#[tokio::test]
async fn test_vless_websocket_pipeline_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let test_uuid = "12345678-1234-1234-1234-123456789abc";

    let server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "vless-ws-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{
                    "type": "ws",
                    "path": "/vless-ws-path"
                }},
                "protocol": {{
                    "type": "vless",
                    "uuid": "{}"
                }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, test_uuid
    );

    let srv_instance = Instance::new(Config::from_json_str(&server_cfg).unwrap()).unwrap();
    srv_instance.start().await.unwrap();

    let client_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "vless-ws-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{
                    "type": "ws",
                    "path": "/vless-ws-path"
                }},
                "protocol": {{
                    "type": "vless",
                    "uuid": "{}"
                }}
            }},
            {{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, test_uuid
    );

    let cli_instance = Instance::new(Config::from_json_str(&client_cfg).unwrap()).unwrap();
    let outbound = cli_instance.registry.get_outbound("vless-ws-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "vless-ws-test",
        NetworkType::Tcp,
    );

    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let test_payload = b"VLESS through ServerTransportPipeline over WebSocket!";
    stream.write_all(test_payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut recv_buf = vec![0u8; test_payload.len()];
    stream.read_exact(&mut recv_buf).await.unwrap();
    assert_eq!(&recv_buf, test_payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_shadowsocks_websocket_pipeline_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let password = "ss-websocket-test-password-123";

    let server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "ss-ws-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{
                    "type": "ws",
                    "path": "/ss-ws-tunnel"
                }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "chacha20-ietf-poly1305"
                }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    );

    let srv_instance = Instance::new(Config::from_json_str(&server_cfg).unwrap()).unwrap();
    srv_instance.start().await.unwrap();

    let client_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "ss-ws-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{
                    "type": "ws",
                    "path": "/ss-ws-tunnel"
                }},
                "protocol": {{
                    "type": "shadowsocks",
                    "password": "{}",
                    "method": "chacha20-ietf-poly1305"
                }}
            }},
            {{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    );

    let cli_instance = Instance::new(Config::from_json_str(&client_cfg).unwrap()).unwrap();
    let outbound = cli_instance.registry.get_outbound("ss-ws-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "ss-ws-test",
        NetworkType::Tcp,
    );

    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let test_payload = b"Shadowsocks through ServerTransportPipeline over WebSocket!";
    stream.write_all(test_payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut recv_buf = vec![0u8; test_payload.len()];
    stream.read_exact(&mut recv_buf).await.unwrap();
    assert_eq!(&recv_buf, test_payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_trojan_websocket_pipeline_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let password = "trojan-plain-ws-password";

    // Trojan with tls disabled + websocket framing
    let server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "trojan-ws-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{
                    "type": "ws",
                    "path": "/trojan-ws"
                }},
                "protocol": {{
                    "type": "trojan",
                    "password": "{}"
                }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    );

    let srv_instance = Instance::new(Config::from_json_str(&server_cfg).unwrap()).unwrap();
    srv_instance.start().await.unwrap();

    let client_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "trojan-ws-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{
                    "type": "ws",
                    "path": "/trojan-ws"
                }},
                "protocol": {{
                    "type": "trojan",
                    "password": "{}"
                }}
            }},
            {{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, password
    );

    let cli_instance = Instance::new(Config::from_json_str(&client_cfg).unwrap()).unwrap();
    let outbound = cli_instance.registry.get_outbound("trojan-ws-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "trojan-ws-test",
        NetworkType::Tcp,
    );

    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let test_payload = b"Trojan through ServerTransportPipeline over WebSocket!";
    stream.write_all(test_payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut recv_buf = vec![0u8; test_payload.len()];
    stream.read_exact(&mut recv_buf).await.unwrap();
    assert_eq!(&recv_buf, test_payload);

    srv_instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_vmess_websocket_pipeline_e2e() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;
    let test_uuid = "22222222-2222-2222-2222-222222222222";

    let server_cfg = format!(
        r#"{{
            "inbounds": [{{
                "tag": "vmess-ws-in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {} }},
                "framing": {{
                    "type": "ws",
                    "path": "/vmess-ws"
                }},
                "protocol": {{
                    "type": "vmess",
                    "uuid": "{}"
                }}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, test_uuid
    );

    let srv_instance = Instance::new(Config::from_json_str(&server_cfg).unwrap()).unwrap();
    srv_instance.start().await.unwrap();

    let client_cfg = format!(
        r#"{{
            "outbounds": [{{
                "tag": "vmess-ws-out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:{}" }},
                "framing": {{
                    "type": "ws",
                    "path": "/vmess-ws"
                }},
                "protocol": {{
                    "type": "vmess",
                    "uuid": "{}",
                    "security": "aes-128-gcm"
                }}
            }},
            {{ "type": "direct", "tag": "direct" }}]
        }}"#,
        srv_port, test_uuid
    );

    let cli_instance = Instance::new(Config::from_json_str(&client_cfg).unwrap()).unwrap();
    let outbound = cli_instance.registry.get_outbound("vmess-ws-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "vmess-ws-test",
        NetworkType::Tcp,
    );

    let mut stream = outbound.dial_stream(&meta).await.unwrap();
    let test_payload = b"VMess through ServerTransportPipeline over WebSocket!";
    stream.write_all(test_payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut recv_buf = vec![0u8; test_payload.len()];
    stream.read_exact(&mut recv_buf).await.unwrap();
    assert_eq!(&recv_buf, test_payload);

    srv_instance.stop().await.unwrap();
}
