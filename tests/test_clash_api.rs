use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use flux_app::api::{ApiServer, TrafficMeter};
use flux_app::instance::OutboundRegistry;
use flux_outbound::DirectOutbound;
use flux_dns::DnsResolver;

#[tokio::test]
async fn test_clash_rest_api() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    drop(listener);

    let registry = Arc::new(OutboundRegistry::new());
    let resolver = Arc::new(DnsResolver::new(None));
    registry.insert("direct".into(), Arc::new(DirectOutbound::new("direct", resolver)));

    let meter = TrafficMeter::new();
    meter.record_traffic(1024, 2048);

    let server = ApiServer::new(api_addr, registry, meter);
    server.start().await.unwrap();

    // 1. Test GET /version
    {
        let mut stream = TcpStream::connect(api_addr).await.unwrap();
        stream.write_all(b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("flux-core"));
    }

    // 2. Test GET /traffic
    {
        let mut stream = TcpStream::connect(api_addr).await.unwrap();
        stream.write_all(b"GET /traffic HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"up\""));
        assert!(resp.contains("\"down\""));
    }

    // 3. Test GET /proxies
    {
        let mut stream = TcpStream::connect(api_addr).await.unwrap();
        stream.write_all(b"GET /proxies HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"direct\""));
    }

    // 4. Test GET /connections
    {
        let mut stream = TcpStream::connect(api_addr).await.unwrap();
        stream.write_all(b"GET /connections HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("uploadTotal"));
    }

    server.stop().await.unwrap();
}
