use flux_types::{NetworkType, Outbound, SessionMeta, TargetAddress};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The prefix an HTTP/1.x status line starts with. Deciding on exactly this many
/// bytes lets the read loop return as soon as the answer is unambiguous.
const HTTP_STATUS_PREFIX: &[u8] = b"HTTP/1.";

/// Performs an HTTP or HTTPS probe against the given outbound node.
/// Returns `Some(latency)` if the node connected and responded, or `None` on failure or timeout.
///
/// `timeout` bounds the **whole** probe — dial, TLS handshake, request write and
/// response read — not each phase separately. That matters for the callers that
/// run this on a timer (`urltest`, `fallback`): a member that accepts a
/// connection and then never answers used to block the probe (and therefore the
/// group's whole probe round) for as long as the peer stayed silent.
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

    let start = tokio::time::Instant::now();
    let deadline = start + timeout;

    let stream = match tokio::time::timeout_at(deadline, outbound.dial_stream(&meta)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let mut stream = if is_tls {
        let tls_cfg = flux_transport::tls::TlsClientConfig::new(host_header)
            .with_alpn(vec!["http/1.1".into()]);
        match tokio::time::timeout_at(
            deadline,
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

    match tokio::time::timeout_at(deadline, stream.write_all(req.as_bytes())).await {
        Ok(Ok(())) => {}
        _ => return None,
    }

    // Read until the prefix is either complete or contradicted. TCP delivers a
    // byte stream, so a single `read` can legitimately return one byte of
    // "HTTP/1."; judging the peer on that fragment reports a healthy node as
    // dead. The loop is bounded by the deadline, not by a byte count.
    let mut buf = [0u8; 64];
    let mut filled = 0usize;
    loop {
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => return None, // EOF before a status line: not HTTP
            Ok(Ok(n)) => n,
            _ => return None, // read error, or the probe budget ran out
        };
        filled += n;

        let seen = &buf[..filled.min(HTTP_STATUS_PREFIX.len())];
        if !HTTP_STATUS_PREFIX.starts_with(seen) {
            return None; // already contradicted: some other protocol
        }
        if filled >= HTTP_STATUS_PREFIX.len() {
            return Some(start.elapsed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flux_types::{BoxedStream, FluxError, FluxResult, PacketEndpoint};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    /// An outbound whose `dial_stream` opens a real localhost connection, so the
    /// probe exercises exactly the socket path it uses in production.
    struct DialingOutbound {
        tag: String,
        addr: SocketAddr,
        dials: AtomicUsize,
    }

    impl DialingOutbound {
        fn new(addr: SocketAddr) -> Self {
            Self {
                tag: "dialing".into(),
                addr,
                dials: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl Outbound for DialingOutbound {
        fn tag(&self) -> &str {
            &self.tag
        }
        async fn dial_stream(&self, _meta: &SessionMeta) -> FluxResult<BoxedStream> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let sock = TcpStream::connect(self.addr).await.map_err(FluxError::Io)?;
            Ok(Box::new(sock) as BoxedStream)
        }
        async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
            unreachable!("the probe only dials streams")
        }
    }

    /// What the fake server does once a probe connects.
    #[derive(Clone, Copy)]
    enum Wire {
        /// A well-formed status line, written in one segment.
        Answer,
        /// Accepts and then says nothing, forever: a hung member.
        Silent,
        /// Writes `H`, waits, then the rest of the status line.
        SplitStatus,
        /// A non-HTTP protocol banner.
        Garbage,
        /// Accepts and immediately closes.
        Hangup,
        /// One byte of a valid status line every 60 ms: slower than any budget.
        Dribble,
    }

    async fn handle(wire: Wire, mut sock: TcpStream) {
        match wire {
            Wire::Answer => {
                let _ = sock.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            }
            Wire::Silent => {
                // Hold the connection open without ever writing a byte.
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            Wire::SplitStatus => {
                let _ = sock.write_all(b"H").await;
                tokio::time::sleep(Duration::from_millis(150)).await;
                let _ = sock.write_all(b"TTP/1.1 204 No Content\r\n\r\n").await;
            }
            Wire::Garbage => {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
            }
            Wire::Hangup => {}
            Wire::Dribble => {
                for byte in b"HTTP/1.1 204 No Content\r\n\r\n" {
                    let _ = sock.write_all(&[*byte]).await;
                    tokio::time::sleep(Duration::from_millis(60)).await;
                }
            }
        }
    }

    async fn spawn_server(wire: Wire) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(handle(wire, sock));
            }
        });
        addr
    }

    async fn probe(addr: SocketAddr, budget: Duration) -> Option<Duration> {
        let out: Arc<dyn Outbound> = Arc::new(DialingOutbound::new(addr));
        probe_outbound(
            &out,
            &TargetAddress::Ip(addr),
            "localhost",
            "/generate_204",
            false,
            "probe-test",
            budget,
        )
        .await
    }

    #[tokio::test]
    async fn a_real_answer_yields_a_real_rtt() {
        let addr = spawn_server(Wire::Answer).await;
        let rtt = probe(addr, Duration::from_secs(2))
            .await
            .expect("a server that answers with a status line is healthy");
        assert!(rtt > Duration::ZERO, "the measurement must be non-zero");
        assert!(
            rtt < Duration::from_secs(2),
            "RTT must be the measured time"
        );
    }

    /// A member that accepts the connection and then never answers must not be
    /// able to hang the probe — and through it the whole group's probe loop —
    /// forever. The budget is the probe's own, not the caller's.
    #[tokio::test]
    async fn a_silent_peer_is_cut_off_by_the_probe_budget() {
        let addr = spawn_server(Wire::Silent).await;
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            probe(addr, Duration::from_millis(150)),
        )
        .await;
        assert!(
            matches!(outcome, Ok(None)),
            "a silent peer must produce a timeout inside the probe, got {outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the probe returned only because the caller gave up: {:?}",
            started.elapsed()
        );
    }

    /// TCP is a byte stream: the status line can arrive in several segments. A
    /// single `read` that happens to return `H` is not evidence of a non-HTTP
    /// peer, and treating it as one fails a perfectly healthy member.
    #[tokio::test]
    async fn a_fragmented_status_line_is_still_a_success() {
        let addr = spawn_server(Wire::SplitStatus).await;
        let rtt = probe(addr, Duration::from_secs(2)).await;
        assert!(
            rtt.is_some(),
            "a status line split across two segments must still count as healthy"
        );
    }

    /// The budget must be a budget for the whole probe, not per phase: a peer
    /// that dribbles one byte at a time must be abandoned at the deadline, but
    /// not before it — a peer that is merely slow yet still on track deserves
    /// the full budget.
    #[tokio::test]
    async fn the_budget_covers_the_whole_probe() {
        let addr = spawn_server(Wire::Dribble).await;
        let started = std::time::Instant::now();
        let rtt = probe(addr, Duration::from_millis(200)).await;
        let elapsed = started.elapsed();
        assert!(rtt.is_none(), "an incomplete status line is not a success");
        assert!(
            elapsed < Duration::from_millis(700),
            "the probe must stop at its deadline, not per read: {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(150),
            "a slow but valid response must be given the whole budget, \
             not rejected after the first byte: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_non_http_banner_is_not_healthy() {
        let addr = spawn_server(Wire::Garbage).await;
        assert!(probe(addr, Duration::from_secs(2)).await.is_none());
    }

    #[tokio::test]
    async fn a_peer_that_hangs_up_is_not_healthy() {
        let addr = spawn_server(Wire::Hangup).await;
        assert!(probe(addr, Duration::from_secs(2)).await.is_none());
    }

    #[tokio::test]
    async fn a_refused_dial_is_not_healthy() {
        // Bind then drop the listener: the port is (almost certainly) closed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(probe(addr, Duration::from_secs(1)).await.is_none());
    }
}
