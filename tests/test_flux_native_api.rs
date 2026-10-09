mod common;

use common::get_free_tcp_port;
use flux_app::{Config, Instance};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_flux_native_api_and_route_tracer() {
    let api_port = get_free_tcp_port().await;

    // Config showcasing Native Flux format:
    // 1. Native API config block with secret
    // 2. Inline URI in outbounds array!
    let raw_config = format!(
        r#"{{
            "flux": "1.0",
            "api": {{
                "listen": "127.0.0.1:{}",
                "secret": "native-flux-secret"
            }},
            "inbounds": [
                {{
                    "tag": "socks-in",
                    "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": 10999 }},
                    "protocol": {{ "type": "socks" }}
                }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct-node" }},
                {{ "type": "block", "tag": "block-node" }},
                // Inline URI representation of proxy node!
                "socks5://127.0.0.1:1080#proxy-socks-node",
                {{
                    "type": "selector",
                    "tag": "my-selector",
                    "outbounds": ["proxy-socks-node", "direct-node"],
                    "default": "proxy-socks-node"
                }}
            ],
            "route": {{
                "rules": [
                    {{ "domain_suffix": [".google.com", ".youtube.com"], "outbound": "my-selector" }},
                    {{ "domain_keyword": ["ads", "telemetry"], "outbound": "block-node" }}
                ],
                "final": "direct-node"
            }}
        }}"#,
        api_port
    );

    let cfg = Config::from_json_str(&raw_config).unwrap();
    assert_eq!(cfg.outbounds.len(), 4); // direct-node, block-node, proxy-socks-node (from URI), my-selector

    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let api_addr = format!("127.0.0.1:{}", api_port);

    // 1. Test GET /api/v1/status
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("uptime_seconds"));
        assert!(resp.contains("outbounds_count"));
        assert!(resp.contains("flux-core"));
    }

    // 2. Test POST /api/v1/route/test (Route Simulation Tracer)
    // Test 2.1: Domain matching ".google.com" -> routes to "my-selector" -> active "proxy-socks-node"
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        let req_body =
            r#"{"destination": "mail.google.com:443", "network": "tcp", "inbound": "socks-in"}"#;
        let req = format!(
            "POST /api/v1/route/test HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\nContent-Length: {}\r\n\r\n{}",
            req_body.len(),
            req_body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"matched_outbound\":\"my-selector\""));
        assert!(resp.contains("\"active_target_outbound\":\"proxy-socks-node\""));
    }

    // Test 2.2: Keyword matching "telemetry" -> routes to "block-node"
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        let req_body = r#"{"destination": "app.telemetry.domain.org:80", "network": "tcp", "inbound": "socks-in"}"#;
        let req = format!(
            "POST /api/v1/route/test HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\nContent-Length: {}\r\n\r\n{}",
            req_body.len(),
            req_body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"matched_outbound\":\"block-node\""));
    }

    // Test 2.3: Non-matching domain -> falls back to final outbound "direct-node"
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        let req_body =
            r#"{"destination": "wikipedia.org:443", "network": "tcp", "inbound": "socks-in"}"#;
        let req = format!(
            "POST /api/v1/route/test HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\nContent-Length: {}\r\n\r\n{}",
            req_body.len(),
            req_body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"matched_outbound\":\"direct-node\""));
    }

    // 3. Test GET /api/v1/outbounds
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/outbounds HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("my-selector"));
        assert!(resp.contains("candidates"));
    }

    // 4. Test POST /api/v1/outbounds/my-selector/select
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        let req_body = r#"{"name": "direct-node"}"#;
        let req = format!(
            "PUT /api/v1/outbounds/my-selector HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\nContent-Length: {}\r\n\r\n{}",
            req_body.len(),
            req_body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("204 No Content"));
    }

    // Verify route tracer now reflects that my-selector switched to "direct-node"
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        let req_body =
            r#"{"destination": "mail.google.com:443", "network": "tcp", "inbound": "socks-in"}"#;
        let req = format!(
            "POST /api/v1/route/test HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\nContent-Length: {}\r\n\r\n{}",
            req_body.len(),
            req_body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"active_target_outbound\":\"direct-node\""));
    }

    // 5. Test GET /api/v1/version
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/version HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"engine\":\"flux-core\""));
        assert!(resp.contains("\"api_version\":\"v1\""));
    }

    // 6. Test GET /api/v1/traffic
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/traffic HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("upload_speed"));
        assert!(resp.contains("download_speed"));
    }

    // 7. Test GET /api/v1/outbounds/my-selector
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/outbounds/my-selector HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"tag\":\"my-selector\""));
        assert!(resp.contains("\"current\":\"direct-node\""));
    }

    // 8. Test Auth failures
    {
        // Missing token -> 401
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream
            .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("401 Unauthorized"));

        // Query param token -> 200
        let mut stream2 = TcpStream::connect(&api_addr).await.unwrap();
        stream2
            .write_all(
                b"GET /api/v1/status?token=native-flux-secret HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf2 = vec![0u8; 2048];
        let n2 = stream2.read(&mut buf2).await.unwrap();
        let resp2 = String::from_utf8_lossy(&buf2[..n2]);
        assert!(resp2.contains("200 OK"));
    }

    // 9. Test Connections API: register, inspect, and close
    {
        let meta = flux_types::SessionMeta::new(
            "127.0.0.1:45678".parse().unwrap(),
            "example.org:443".parse().unwrap(),
            "socks-in",
            flux_types::NetworkType::Tcp,
        );
        let (conn_id, conn, mut cancel_rx) = instance.meter.register_connection(&meta);
        conn.upload.store(512, std::sync::atomic::Ordering::Relaxed);
        conn.download
            .store(1024, std::sync::atomic::Ordering::Relaxed);

        // GET /api/v1/connections
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/connections HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains(&conn_id));
        assert!(resp.contains("example.org"));

        // DELETE /api/v1/connections/{id}
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        let req = format!(
            "DELETE /api/v1/connections/{} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n",
            conn_id
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("204 No Content"));
        assert!(cancel_rx.try_recv().is_ok());

        // Verify connection removed
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/connections HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(!resp.contains(&conn_id));
    }

    // 10. Test GET /api/v1/rules
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/rules HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"rules\""));
        assert!(resp.contains("\"final\":\"direct-node\""));
    }

    // 11. Test trailing slash normalization: GET /api/v1/status/
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/status/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("uptime_seconds"));
    }

    // 12. Test DELETE /api/v1/connections (flush all)
    {
        let meta1 = flux_types::SessionMeta::new(
            "127.0.0.1:40001".parse().unwrap(),
            "target1.org:80".parse().unwrap(),
            "socks-in",
            flux_types::NetworkType::Tcp,
        );
        let meta2 = flux_types::SessionMeta::new(
            "127.0.0.1:40002".parse().unwrap(),
            "target2.org:80".parse().unwrap(),
            "socks-in",
            flux_types::NetworkType::Tcp,
        );
        let (_id1, _c1, mut rx1) = instance.meter.register_connection(&meta1);
        let (_id2, _c2, mut rx2) = instance.meter.register_connection(&meta2);
        assert_eq!(instance.meter.connections.len(), 2);

        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"DELETE /api/v1/connections HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("204 No Content"));

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
        assert_eq!(instance.meter.connections.len(), 0);
    }

    // 13. Test GET /api/v1/inbounds
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/inbounds HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"tag\":\"socks-in\""));
        assert!(resp.contains("\"protocol\":\"socks\""));
        assert!(resp.contains("10999"));
    }

    // 14. Test GET /api/v1/dns/resolve?name=127.0.0.1
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/dns/resolve?name=127.0.0.1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"ip\":\"127.0.0.1\""));
    }

    // 15. Test 404 Not Found on unknown path
    {
        let mut stream = TcpStream::connect(&api_addr).await.unwrap();
        stream.write_all(b"GET /api/v1/nonexistent HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer native-flux-secret\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("404 Not Found"));
    }

    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_flux_unix_domain_socket_api() {
    let dir = tempdir().unwrap();
    let sock_path = dir.path().join("flux.sock");
    let unix_endpoint = format!("unix://{}", sock_path.display());

    let raw_config = format!(
        r#"{{
            "api": {{
                "listen": "{}"
            }},
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }}
            ]
        }}"#,
        unix_endpoint
    );

    let cfg = Config::from_json_str(&raw_config).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    // Connect via UnixStream!
    let mut stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    stream
        .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 2048];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200 OK"));
    assert!(resp.contains("flux-core"));
    assert!(resp.contains("uptime_seconds"));

    instance.stop().await.unwrap();
}
