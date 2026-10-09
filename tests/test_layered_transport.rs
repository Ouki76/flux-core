mod common;

use common::{get_free_tcp_port, start_tcp_echo_server};
use flux_app::{Config, Instance};
use flux_protocol::vless::VlessProtocol;
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

#[tokio::test]
async fn test_layered_websocket_framing() {
    let ws_server_port = get_free_tcp_port().await;
    let echo_addr = start_tcp_echo_server().await;
    let test_uuid_str = "a1b2c3d4-e5f6-7890-1234-56789abcdef0";
    let test_uuid = Uuid::parse_str(test_uuid_str).unwrap();

    // Upstream VLESS + WebSocket server
    let listener = TcpListener::bind(format!("127.0.0.1:{}", ws_server_port))
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let uuids = vec![test_uuid];
            tokio::spawn(async move {
                // 1. Terminate WebSocket layer
                let mut ws =
                    flux_transport::websocket::server_handshake(socket, Some("/my-ws-tunnel"))
                        .await
                        .unwrap();

                // 2. Terminate VLESS protocol layer
                let _req = VlessProtocol::read_request_header(&mut ws, &uuids)
                    .await
                    .unwrap();
                VlessProtocol::write_response_header(&mut ws).await.unwrap();

                // 3. Echo back application payload over the layered tunnel
                let mut b = [0u8; 1024];
                loop {
                    match ws.read(&mut b).await {
                        Ok(0) => break,
                        Ok(cnt) => {
                            if ws.write_all(&b[..cnt]).await.is_err() {
                                break;
                            }
                            let _ = ws.flush().await;
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    // Configure client VLESS with WebSocket transport
    let raw_config = format!(
        r#"{{
            "outbounds": [
                {{
                    "type": "vless",
                    "tag": "vless-ws-node",
                    "server": "127.0.0.1",
                    "server_port": {},
                    "uuid": "{}",
                    "transport": {{
                        "type": "ws",
                        "path": "/my-ws-tunnel",
                        "headers": {{
                            "Host": "custom-cdn.example.com"
                        }}
                    }}
                }},
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        ws_server_port, test_uuid_str
    );

    let cfg = Config::from_json_str(&raw_config).unwrap();
    let instance = Instance::new(cfg).unwrap();
    let outbound = instance.registry.get_outbound("vless-ws-node").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:0".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "test-inbound",
        NetworkType::Tcp,
    );

    let mut stream = outbound.dial_stream(&meta).await.unwrap();

    let test_payload = b"Full bidirectional VLESS streaming over WebSocket framing verified!";
    stream.write_all(test_payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut recv_buf = vec![0u8; test_payload.len()];
    stream.read_exact(&mut recv_buf).await.unwrap();
    assert_eq!(&recv_buf, test_payload);

    instance.stop().await.unwrap();
}
