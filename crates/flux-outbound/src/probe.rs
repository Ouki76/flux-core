use flux_types::{NetworkType, Outbound, SessionMeta, TargetAddress};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Performs an HTTP or HTTPS probe against the given outbound node.
/// Returns `Some(latency)` if the node connected and responded, or `None` on failure or timeout.
pub async fn probe_outbound(
    outbound: &Arc<dyn Outbound>,
    target_addr: &TargetAddress,
    host_header: &str,
    request_path: &str,
    is_tls: bool,
    probe_tag: &str,
    timeout: Duration,
) -> Option<Duration> {
    let dummy_src = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let meta = SessionMeta::new(dummy_src, target_addr.clone(), probe_tag, NetworkType::Tcp);

    let start = Instant::now();
    let stream = match tokio::time::timeout(timeout, outbound.dial_stream(&meta)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let mut stream = if is_tls {
        let tls_cfg = flux_transport::tls::TlsClientConfig::new(host_header)
            .with_alpn(vec!["http/1.1".into()]);
        match tokio::time::timeout(
            timeout,
            flux_transport::tls::TlsTransport::connect(stream, &tls_cfg),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return None,
        }
    } else {
        stream
    };

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: flux-core-probe\r\nConnection: close\r\n\r\n",
        request_path, host_header
    );

    if stream.write_all(req.as_bytes()).await.is_err() {
        return None;
    }

    let mut buf = [0u8; 64];
    match stream.read(&mut buf).await {
        Ok(n) if n > 0 => {
            let resp_str = String::from_utf8_lossy(&buf[..n]);
            if resp_str.starts_with("HTTP/1.") {
                Some(start.elapsed())
            } else {
                None
            }
        }
        _ => None,
    }
}
