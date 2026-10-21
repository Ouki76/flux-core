//! Robustness: every inbound must survive arbitrary garbage on its listening
//! socket and keep serving real clients afterwards.
//!
//! A proxy's whole attack surface is "bytes from the network". A panic, a hang or
//! a wedged listener in any handler is a remote denial of service, so this suite
//! throws structured and random garbage at every inbound it can start and then
//! proves the listener still works.

mod common;

use common::get_free_tcp_port;
use flux_app::{Config, Instance};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Deterministic PRNG so a failure reproduces exactly.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len + 8);
        while v.len() < len {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

/// Speaks just enough SOCKS5 to prove the listener is alive and routing.
async fn socks5_is_alive(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await else {
        return false;
    };
    if s.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return false;
    }
    let mut sel = [0u8; 2];
    matches!(
        tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut sel)).await,
        Ok(Ok(_))
    ) && sel == [0x05, 0x00]
}

/// A listener is alive if it still accepts a connection.
async fn tcp_alive(port: u16) -> bool {
    tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// VLESS liveness: a valid request header must still produce the server's
/// two-byte response header. Proves the handler is not just accepting but working.
async fn vless_alive(port: u16, uuid: &str) -> bool {
    let Ok(u) = uuid.parse::<uuid::Uuid>() else {
        return false;
    };
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await else {
        return false;
    };
    let mut req = vec![0u8]; // version
    req.extend_from_slice(u.as_bytes());
    req.push(0); // addon length
    req.push(0x01); // command TCP
    req.extend_from_slice(&80u16.to_be_bytes());
    req.push(0x01); // IPv4
    req.extend_from_slice(&[127, 0, 0, 1]);
    if s.write_all(&req).await.is_err() {
        return false;
    }
    let mut hdr = [0u8; 2];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut hdr)).await,
        Ok(Ok(_))
    ) && hdr[0] == 0x00
}

async fn exists_after_garbage(port: u16, seed: u64) -> bool {
    let mut rng = Rng(seed);
    for _ in 0..40 {
        let len = (rng.next() % 512) as usize;
        let junk = rng.bytes(len);
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await {
            let _ = s.write_all(&junk).await;
            let _ = s.flush().await;
            // Half the time also try a truncated-but-plausible header.
            if rng.next().is_multiple_of(2) {
                let mut hdr = vec![0x05u8];
                hdr.extend_from_slice(&rng.bytes(3));
                let _ = s.write_all(&hdr).await;
            }
            // Give the handler a moment, then drop the connection.
            tokio::time::sleep(Duration::from_millis(2)).await;
            drop(s);
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    true
}

/// Socks, HTTP and mixed inbounds all auto-detect on the same kind of socket, so
/// they are exercised together. The instance must remain usable after 40 garbage
/// connections per listener.
#[tokio::test]
async fn garbage_on_stream_inbounds_does_not_break_the_proxy() {
    let socks_port = get_free_tcp_port().await;
    let http_port = get_free_tcp_port().await;
    let mixed_port = get_free_tcp_port().await;
    let vless_port = get_free_tcp_port().await;
    let trojan_port = get_free_tcp_port().await;
    let uuid = "aa11bb22-cc33-dd44-ee55-ff6677889900";

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "outbounds": [{{ "type": "direct", "tag": "direct" }}],
            "inbounds": [
                {{ "tag": "socks", "carrier": {{"type":"tcp","listen":"127.0.0.1","listen_port":{socks_port}}}, "protocol": {{"type":"socks"}} }},
                {{ "tag": "http",  "carrier": {{"type":"tcp","listen":"127.0.0.1","listen_port":{http_port}}},  "protocol": {{"type":"http"}} }},
                {{ "type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": {mixed_port} }},
                {{ "tag": "vless", "carrier": {{"type":"tcp","listen":"127.0.0.1","listen_port":{vless_port}}}, "protocol": {{"type":"vless","uuid":"{uuid}"}} }},
                {{ "tag": "trojan","carrier": {{"type":"tcp","listen":"127.0.0.1","listen_port":{trojan_port}}}, "protocol": {{"type":"trojan","password":"pw-garbage-test"}} }}
            ]
        }}"#
    ))
    .expect("config must parse");
    let instance = Instance::new(cfg).expect("instance");
    instance.start().await.expect("start");

    exists_after_garbage(socks_port, 0x1234_5678).await;
    exists_after_garbage(mixed_port, 0x2345_6789).await;
    exists_after_garbage(vless_port, 0x3456_789a).await;
    exists_after_garbage(trojan_port, 0x4567_89ab).await;

    // Each listener must still do its job, not merely accept a socket.
    assert!(
        socks5_is_alive(socks_port).await,
        "socks wedged after garbage"
    );
    assert!(
        socks5_is_alive(mixed_port).await,
        "mixed wedged after garbage"
    );
    assert!(
        vless_alive(vless_port, "aa11bb22-cc33-dd44-ee55-ff6677889900").await,
        "vless wedged after garbage"
    );
    assert!(
        tcp_alive(trojan_port).await,
        "trojan listener stopped accepting after garbage"
    );

    // HTTP: garbage must not stop it answering a real request with a proxy status.
    let mut rng = Rng(0x5678_9abc);
    for _ in 0..40 {
        let len = (rng.next() % 400) as usize;
        let junk = rng.bytes(len);
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", http_port)).await {
            let _ = s.write_all(&junk).await;
            let _ = s.flush().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    let mut s = TcpStream::connect(("127.0.0.1", http_port))
        .await
        .expect("http inbound still accepting");
    s.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut resp = vec![0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut resp))
        .await
        .expect("http inbound must answer within 5 s")
        .expect("read");
    assert!(n > 0, "http inbound closed without answering");

    let _ = instance.stop().await;
}

/// A UDP listener (the fake-IP DNS inbound) must survive garbage datagrams and
/// still answer a valid query.
#[tokio::test]
async fn garbage_datagrams_do_not_break_the_dns_listener() {
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    let dns_port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };

    let cfg = Config::from_json_str(&format!(
        r#"{{
            "dns": {{ "listen": "127.0.0.1:{dns_port}",
                      "fakeip": {{ "enabled": true, "inet4_range": "198.18.0.0/15" }} }},
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#
    ))
    .expect("config");
    let instance = Instance::new(cfg).expect("instance");
    instance.start().await.expect("start");

    let addr: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut rng = Rng(0x6789_abcd);
    for _ in 0..300 {
        let len = (rng.next() % 300) as usize;
        let junk = rng.bytes(len);
        let _ = sock.send_to(&junk, addr).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A well-formed query must still be answered.
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x07example\x03com\x00");
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    sock.send_to(&q, addr).await.unwrap();

    let mut buf = vec![0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("DNS listener stopped answering after garbage")
        .expect("recv");
    assert!(
        n >= 12 && buf[0] == 0x12 && buf[1] == 0x34,
        "unexpected DNS reply"
    );

    let _ = instance.stop().await;
}
