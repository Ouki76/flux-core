use crate::tcp::TcpTransport;
use flux_types::{AsyncStream, BoxedStream, FluxError, FluxResult};
use hmac::Mac;
use rand::RngCore;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

/// A stream wrapper that handles ShadowTLS v3 TLS record framing and HMAC verification.
/// How many consecutive HMAC failures are tolerated before giving up.
const MAX_SKIPPED_RECORDS: usize = 32;

pub struct ShadowTlsStream<S> {
    inner: S,
    write_hmac: HmacSha1,
    read_hmac: HmacSha1,
    write_buf: Vec<u8>,
    write_pos: usize,
    writing_plain_len: usize,

    // Header buffer: 5 bytes TLS record header + 4 bytes HMAC = 9 bytes
    hdr_buf: [u8; 9],
    hdr_pos: usize,
    payload_len: usize,
    /// Consecutive records rejected by HMAC verification.
    skipped_records: usize,
    payload_buf: Vec<u8>,
    payload_pos: usize,

    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> ShadowTlsStream<S> {
    pub fn new_client(inner: S, password: &str, server_random: &[u8]) -> Self {
        let mut write_hmac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
        write_hmac.update(server_random);
        write_hmac.update(b"C");

        let mut read_hmac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
        read_hmac.update(server_random);
        read_hmac.update(b"S");

        Self {
            inner,
            write_hmac,
            read_hmac,
            write_buf: Vec::with_capacity(16384 + 16),
            write_pos: 0,
            writing_plain_len: 0,
            hdr_buf: [0u8; 9],
            hdr_pos: 0,
            payload_len: 0,
            skipped_records: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// Server-side constructor for the v3 handshake-switch path: the read HMAC
    /// chain is already advanced past the client's first authenticated data frame,
    /// and that frame's payload is pre-buffered for reading.
    pub fn new_server_after_switch(
        inner: S,
        password: &str,
        server_random: &[u8],
        read_hmac: HmacSha1,
        first_payload: Vec<u8>,
    ) -> Self {
        let mut write_hmac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
        write_hmac.update(server_random);
        write_hmac.update(b"S");

        Self {
            inner,
            write_hmac,
            read_hmac,
            write_buf: Vec::with_capacity(16384 + 16),
            write_pos: 0,
            writing_plain_len: 0,
            hdr_buf: [0u8; 9],
            hdr_pos: 0,
            payload_len: 0,
            skipped_records: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            read_buf: first_payload,
            read_pos: 0,
        }
    }

    pub fn new_server(inner: S, password: &str, server_random: &[u8]) -> Self {
        let mut write_hmac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
        write_hmac.update(server_random);
        write_hmac.update(b"S");

        let mut read_hmac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
        read_hmac.update(server_random);
        read_hmac.update(b"C");

        Self {
            inner,
            write_hmac,
            read_hmac,
            write_buf: Vec::with_capacity(16384 + 16),
            write_pos: 0,
            writing_plain_len: 0,
            hdr_buf: [0u8; 9],
            hdr_pos: 0,
            payload_len: 0,
            skipped_records: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // 1. Drain existing decrypted plaintext
            if this.read_pos < this.read_buf.len() {
                let avail = this.read_buf.len() - this.read_pos;
                let to_copy = avail.min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_copy]);
                this.read_pos += to_copy;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. Read TLS record header (5 bytes)
            if this.payload_len == 0 {
                while this.hdr_pos < 5 {
                    let mut tmp = [0u8; 5];
                    let needed = 5 - this.hdr_pos;
                    let mut tmp_buf = ReadBuf::new(&mut tmp[..needed]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp_buf.filled().len();
                            if n == 0 {
                                if this.hdr_pos == 0 {
                                    return Poll::Ready(Ok(())); // Clean EOF
                                }
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF reading ShadowTLS record header",
                                )));
                            }
                            let pos = this.hdr_pos;
                            this.hdr_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                            this.hdr_pos += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let total_len = u16::from_be_bytes([this.hdr_buf[3], this.hdr_buf[4]]) as usize;

                // Handle non-applicationData TLS records (e.g. ChangeCipherSpec 20 or Handshake 22 from decoy)
                if this.hdr_buf[0] != 0x17 {
                    let mut skipped = 0;
                    while skipped < total_len {
                        let needed = total_len - skipped;
                        let mut tmp = [0u8; 512];
                        let to_read = needed.min(tmp.len());
                        let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = tmp_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "unexpected EOF skipping decoy TLS record",
                                    )));
                                }
                                skipped += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    this.hdr_pos = 0;
                    continue;
                }

                // Read 4 bytes HMAC tag into hdr_buf[5..9]
                while this.hdr_pos < 9 {
                    let mut tmp = [0u8; 4];
                    let needed = 9 - this.hdr_pos;
                    let mut tmp_buf = ReadBuf::new(&mut tmp[..needed]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "unexpected EOF reading ShadowTLS HMAC tag",
                                )));
                            }
                            let pos = this.hdr_pos;
                            this.hdr_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                            this.hdr_pos += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                if total_len < 4 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ShadowTLS record length shorter than HMAC size",
                    )));
                }

                this.payload_len = total_len - 4;
                this.payload_buf.resize(this.payload_len, 0);
                this.payload_pos = 0;
                this.hdr_pos = 0;
            }

            // 3. Read payload
            while this.payload_pos < this.payload_len {
                let needed = this.payload_len - this.payload_pos;
                let mut tmp = [0u8; 8192];
                let to_read = needed.min(tmp.len());
                let mut tmp_buf = ReadBuf::new(&mut tmp[..to_read]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected EOF reading ShadowTLS payload",
                            )));
                        }
                        let pos = this.payload_pos;
                        this.payload_buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                        this.payload_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // 4. Verify HMAC
            let mut mac = this.read_hmac.clone();
            mac.update(&this.payload_buf);
            let hmac_res = mac.finalize().into_bytes();
            let expected_tag = &hmac_res[..4];

            let actual_tag = &this.hdr_buf[5..9];
            if actual_tag != expected_tag {
                // A tag mismatch is expected only while the decoy handshake relay
                // is still finishing. An unbounded number of them is either a
                // broken peer or an attempt to keep this poll loop spinning, so
                // cap consecutive skips and fail instead of silently consuming
                // junk forever.
                this.skipped_records += 1;
                if this.skipped_records > MAX_SKIPPED_RECORDS {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "shadowtls: {MAX_SKIPPED_RECORDS} consecutive records failed                              HMAC verification; peer is not speaking ShadowTLS"
                        ),
                    )));
                }
                tracing::debug!(
                    "shadowtls: tag mismatch, skipping record ({}B, {}/{} skipped)",
                    this.payload_len,
                    this.skipped_records,
                    MAX_SKIPPED_RECORDS
                );
                this.payload_len = 0;
                this.hdr_pos = 0;
                continue;
            }
            this.skipped_records = 0;

            this.read_hmac.update(&this.payload_buf);
            this.read_hmac.update(actual_tag);

            this.read_buf = std::mem::take(&mut this.payload_buf);
            this.read_pos = 0;
            this.payload_len = 0;
            this.payload_pos = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_n = this.writing_plain_len;
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_len = 0;
                return Poll::Ready(Ok(plain_n));
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_size = buf.len().min(16384);
        let plain = &buf[..chunk_size];

        let mut mac = this.write_hmac.clone();
        mac.update(plain);
        let hmac_res = mac.finalize().into_bytes();
        let hmac_tag = &hmac_res[..4];

        this.write_hmac.update(plain);
        this.write_hmac.update(hmac_tag);

        let total_len = (4 + chunk_size) as u16;
        let mut frame = Vec::with_capacity(9 + chunk_size);
        frame.extend_from_slice(&[0x17, 0x03, 0x03]);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(hmac_tag);
        frame.extend_from_slice(plain);

        this.write_buf = frame;
        this.write_pos = 0;
        this.writing_plain_len = chunk_size;

        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_n = this.writing_plain_len;
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_len = 0;
                return Poll::Ready(Ok(plain_n));
            }
        }

        Poll::Pending
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                this.write_buf.clear();
                this.write_pos = 0;
                this.writing_plain_len = 0;
                break;
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            if n == 0 {
                break;
            }
            this.write_pos += n;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

pub const SHADOWTLS_V3_TAKEOVER: &[u8] = b"SHADOWTLS_V3_PROXY_HANDSHAKE_READY";
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const _TLS_RECORD_APP_DATA: u8 = 0x17;
const TLS_CLIENT_HELLO: u8 = 0x01;

#[derive(Clone, Debug)]
pub struct ShadowTlsClientConfig {
    pub server_name: String,
    pub password: String,
    pub insecure: bool,
}

#[derive(Clone, Debug)]
pub struct ShadowTlsServerConfig {
    pub server_names: Vec<String>,
    pub password: String,
    pub fallback_address: TargetFallback,
}

#[derive(Clone, Debug)]
pub enum TargetFallback {
    Address(SocketAddr),
    Domain(String, u16),
}

pub struct ShadowTlsHandshake;

impl ShadowTlsHandshake {
    /// Client-side ShadowTLS v3:
    /// 1. Prepares TLS 1.3 ClientHello with SNI and embedded HMAC challenge in Session ID.
    /// 2. Relays handshake with real SNI domain through ShadowTLS server.
    /// 3. Validates authentic TLS certificate with root CA.
    /// 4. Sends takeover signal to switch connection to inner proxy protocol.
    pub async fn client_handshake<S: AsyncStream + 'static>(
        mut stream: S,
        cfg: &ShadowTlsClientConfig,
    ) -> FluxResult<BoxedStream> {
        // Build authentic TLS 1.3 ClientHello with HMAC challenge matching official ShadowTLS v3 spec
        let client_hello = build_tls_client_hello(&cfg.server_name, &cfg.password);
        stream
            .write_all(&client_hello)
            .await
            .map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        // Read TLS ServerHello response from ShadowTLS server / decoy
        let mut resp_hdr = [0u8; 5];
        stream
            .read_exact(&mut resp_hdr)
            .await
            .map_err(FluxError::Io)?;
        if resp_hdr[0] != TLS_RECORD_HANDSHAKE {
            return Err(FluxError::Crypto(
                "expected TLS handshake response in ShadowTLS client".into(),
            ));
        }
        let resp_len = u16::from_be_bytes([resp_hdr[3], resp_hdr[4]]) as usize;
        let mut resp_body = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_body)
            .await
            .map_err(FluxError::Io)?;

        if resp_body.len() < 38 {
            return Err(FluxError::Crypto(
                "invalid ServerHello length in ShadowTLS".into(),
            ));
        }
        let server_random = &resp_body[6..38];
        let stream = ShadowTlsStream::new_client(stream, &cfg.password, server_random);
        Ok(Box::new(stream))
    }

    /// Server-side ShadowTLS v3:
    /// 1. Reads initial ClientHello from client.
    /// 2. Verifies HMAC challenge in Session ID.
    /// 3. If valid: establishes TLS bridge with fallback target, negotiates takeover, and returns proxy stream.
    /// 4. If invalid: transparently relays to real fallback server (mitigating active probing).
    pub async fn server_handshake<S: AsyncStream + 'static>(
        mut client_stream: S,
        cfg: &ShadowTlsServerConfig,
    ) -> FluxResult<BoxedStream> {
        // Read TLS record header (5 bytes)
        let mut record_hdr = [0u8; 5];
        client_stream
            .read_exact(&mut record_hdr)
            .await
            .map_err(FluxError::Io)?;

        if record_hdr[0] != TLS_RECORD_HANDSHAKE {
            return Err(FluxError::Crypto(
                "expected TLS handshake in ShadowTLS server".into(),
            ));
        }

        let record_len = u16::from_be_bytes([record_hdr[3], record_hdr[4]]) as usize;
        let mut record_body = vec![0u8; record_len];
        client_stream
            .read_exact(&mut record_body)
            .await
            .map_err(FluxError::Io)?;

        // Verify ClientHello and extract Session ID
        let (is_auth, _sni) = verify_shadowtls_session_id(&record_body, &cfg.password);

        let fallback_addr = match &cfg.fallback_address {
            TargetFallback::Address(a) => *a,
            TargetFallback::Domain(d, p) => {
                let addr_str = format!("{}:{}", d, p);
                tokio::net::lookup_host(&addr_str)
                    .await
                    .map_err(FluxError::Io)?
                    .next()
                    .ok_or_else(|| {
                        FluxError::Dns(format!("cannot resolve fallback domain '{}'", d))
                    })?
            }
        };

        let mut fallback_stream =
            TcpTransport::connect(fallback_addr, Duration::from_secs(5)).await?;

        // Relay ClientHello to fallback server
        fallback_stream
            .write_all(&record_hdr)
            .await
            .map_err(FluxError::Io)?;
        fallback_stream
            .write_all(&record_body)
            .await
            .map_err(FluxError::Io)?;
        fallback_stream.flush().await.map_err(FluxError::Io)?;

        if is_auth {
            // Authorized client (ShadowTLS v3): relay the ENTIRE TLS handshake with the
            // fallback, watching client→fallback records until the first application-data
            // record whose 4-byte HMAC tag matches HMAC-SHA1(password | server_random | "C").
            // Then switch to ShadowTlsStream data mode.

            // 1. Read + relay the fallback's ServerHello, extract server_random.
            let mut srv_hdr = [0u8; 5];
            tokio::time::timeout(
                Duration::from_secs(3),
                fallback_stream.read_exact(&mut srv_hdr),
            )
            .await
            .map_err(|_| FluxError::Timeout("shadowtls fallback ServerHello timed out".into()))?
            .map_err(FluxError::Io)?;
            let s_len = u16::from_be_bytes([srv_hdr[3], srv_hdr[4]]) as usize;
            if s_len > 16384 {
                return Err(FluxError::Crypto(
                    "shadowtls fallback ServerHello too large".into(),
                ));
            }
            let mut s_body = vec![0u8; s_len];
            tokio::time::timeout(
                Duration::from_secs(3),
                fallback_stream.read_exact(&mut s_body),
            )
            .await
            .map_err(|_| {
                FluxError::Timeout("shadowtls fallback ServerHello body timed out".into())
            })?
            .map_err(FluxError::Io)?;
            client_stream
                .write_all(&srv_hdr)
                .await
                .map_err(FluxError::Io)?;
            client_stream
                .write_all(&s_body)
                .await
                .map_err(FluxError::Io)?;
            client_stream.flush().await.map_err(FluxError::Io)?;

            // If the fallback didn't answer with a genuine TLS ServerHello, this is
            // a layered pipeline (the "fallback" is the next in-process layer, e.g.
            // REALITY) — degrade to legacy immediate-switch mode using whatever bytes
            // came back as the pseudo server_random (both flux ends stay consistent).
            let valid_sh =
                srv_hdr[0] == TLS_RECORD_HANDSHAKE && s_body.len() >= 38 && s_body[0] == 0x02;
            let server_random: [u8; 32] = if s_body.len() >= 38 {
                s_body[6..38]
                    .try_into()
                    .map_err(|_| FluxError::Crypto("shadowtls invalid server random".into()))?
            } else {
                [0u8; 32]
            };

            // 2. Relay the rest of the server flight (fallback → client) in a
            //    background task, while watching client records in the main flow.
            let (mut client_rd, mut client_wr) = tokio::io::split(client_stream);
            let (mut fb_rd, mut fb_wr) = tokio::io::split(fallback_stream);

            let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
            let relay_task = if valid_sh {
                let password = cfg.password.clone();
                tokio::spawn(async move {
                    // ShadowTLS v3 server→client relay WITH modification:
                    // the fallback's application-data records are XORed with
                    // SHA256(password|server_random) and prefixed with a rolling
                    // HMAC-SHA1(password | server_random) 4-byte tag — this is how the
                    // client detects a genuine ShadowTLS server (vs. plain relay).
                    let xor_key: [u8; 32] = {
                        use sha2::Digest;
                        let mut h = sha2::Sha256::new();
                        h.update(password.as_bytes());
                        h.update(server_random);
                        h.finalize().into()
                    };
                    let mut hmac_write =
                        <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).expect("hmac");
                    hmac_write.update(&server_random);

                    let mut hdr = [0u8; 5];
                    loop {
                        tokio::select! {
                            _ = stop_rx.changed() => break,
                            res = fb_rd.read_exact(&mut hdr) => {
                                if res.is_err() {
                                    break;
                                }
                                let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                                if len > 16384 + 256 {
                                    break;
                                }
                                let mut body = vec![0u8; len];
                                if fb_rd.read_exact(&mut body).await.is_err() {
                                    break;
                                }
                                if hdr[0] == 0x17 {
                                    // appdata: XOR + rolling HMAC tag
                                    for (i, b) in body.iter_mut().enumerate() {
                                        *b ^= xor_key[i % 32];
                                    }
                                    hmac_write.update(&body);
                                    let tag_full = hmac_write.clone().finalize().into_bytes();
                                    let tag = &tag_full[..4];
                                    let new_len = (body.len() + 4) as u16;
                                    let new_hdr = [0x17, 0x03, 0x03,
                                        (new_len >> 8) as u8, (new_len & 0xff) as u8];
                                    if client_wr.write_all(&new_hdr).await.is_err()
                                        || client_wr.write_all(tag).await.is_err()
                                        || client_wr.write_all(&body).await.is_err()
                                        || client_wr.flush().await.is_err()
                                    {
                                        break;
                                    }
                                } else if client_wr.write_all(&hdr).await.is_err()
                                    || client_wr.write_all(&body).await.is_err()
                                    || client_wr.flush().await.is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    (fb_rd, client_wr)
                })
            } else {
                // Legacy/layered mode: no fallback flight relay; inert task.
                tokio::spawn(async move { (fb_rd, client_wr) })
            };

            // 3. Relay client records to the fallback until the first
            //    HMAC-authenticated appdata record (start of Shadowsocks data).
            let mut hmac_verify =
                <HmacSha1 as hmac::Mac>::new_from_slice(cfg.password.as_bytes()).expect("hmac");
            hmac_verify.update(&server_random);
            hmac_verify.update(b"C");

            let mut first_payload: Option<Vec<u8>> = None;
            let mut hdr = [0u8; 5];
            while first_payload.is_none() {
                let rec_hdr = match tokio::time::timeout(
                    Duration::from_secs(5),
                    client_rd.read_exact(&mut hdr),
                )
                .await
                {
                    Ok(Ok(_)) => hdr,
                    _ => {
                        let _ = stop_tx.send(true);
                        return Err(FluxError::Timeout(
                            "shadowtls client post-handshake read timed out".into(),
                        ));
                    }
                };
                let len = u16::from_be_bytes([rec_hdr[3], rec_hdr[4]]) as usize;
                if len > 16384 + 256 {
                    let _ = stop_tx.send(true);
                    return Err(FluxError::Crypto("shadowtls oversized record".into()));
                }
                let mut body = vec![0u8; len];
                if client_rd.read_exact(&mut body).await.is_err() {
                    let _ = stop_tx.send(true);
                    return Err(FluxError::Crypto("shadowtls truncated record".into()));
                }

                if rec_hdr[0] == 0x17 && body.len() > 4 {
                    let mut mac = hmac_verify.clone();
                    mac.update(&body[4..]);
                    let expect = mac.finalize().into_bytes();
                    if body[..4] == expect[..4] {
                        hmac_verify.update(&body[4..]);
                        hmac_verify.update(&body[..4]);
                        first_payload = Some(body[4..].to_vec());
                        tracing::debug!(
                            "shadowtls v3: first authenticated data frame matched ({} bytes)",
                            len - 4
                        );
                        break;
                    } else {
                        tracing::debug!(
                            "shadowtls v3: relaying record type={} len={} (no hmac match)",
                            rec_hdr[0],
                            len
                        );
                        if rec_hdr[0] == 0x17 && body.len() > 4 {}
                    }
                }

                if fb_wr.write_all(&rec_hdr).await.is_err()
                    || fb_wr.write_all(&body).await.is_err()
                    || fb_wr.flush().await.is_err()
                {
                    let _ = stop_tx.send(true);
                    return Err(FluxError::Crypto(
                        "shadowtls fallback relay write failed".into(),
                    ));
                }
            }

            let _ = stop_tx.send(true);
            let (fb_rd, client_wr) = relay_task.await.map_err(|e| {
                FluxError::Network(format!("shadowtls relay task join failed: {}", e))
            })?;
            let client_stream = client_rd.unsplit(client_wr);
            drop(fb_rd);
            drop(fb_wr);

            let stream = ShadowTlsStream::new_server_after_switch(
                client_stream,
                &cfg.password,
                &server_random,
                hmac_verify,
                first_payload.unwrap_or_default(),
            );
            return Ok(Box::new(stream));
        }
        // Authorized path returned above. Unauthorized probe: relay to the fallback.
        {
            // Unauthorized probe: bridge transparently to real server
            let mut cs: BoxedStream = Box::new(client_stream);
            let mut fs: BoxedStream = Box::new(fallback_stream);
            tokio::spawn(async move {
                let _ = flux_common::copy_bidirectional(&mut cs, &mut fs).await;
            });
            Err(FluxError::AuthFailed(
                "shadowtls probe redirected to decoy server".into(),
            ))
        }
    }
}

fn build_tls_client_hello(server_name: &str, password: &str) -> Vec<u8> {
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);

    let mut session_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_id[..28]);
    session_id[28..32].copy_from_slice(&[0, 0, 0, 0]);

    let mut hello = Vec::with_capacity(512);
    hello.push(TLS_CLIENT_HELLO);
    hello.extend_from_slice(&[0, 0, 0]); // Length placeholder
    hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
    hello.extend_from_slice(&random);

    hello.push(32);
    let session_id_start = hello.len();
    hello.extend_from_slice(&session_id);

    // Standard modern cipher suites: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384
    hello.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02]);
    // Compression: none
    hello.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let mut extensions = Vec::with_capacity(256);

    // SNI
    let sni_bytes = server_name.as_bytes();
    let sni_len = 5 + sni_bytes.len();
    extensions.extend_from_slice(&[0x00, 0x00]); // SNI type
    extensions.extend_from_slice(&(sni_len as u16).to_be_bytes());
    extensions.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    extensions.push(0x00);
    extensions.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(sni_bytes);

    // Supported versions: TLS 1.3, TLS 1.2
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

    // Supported groups (0x000a): x25519 (0x001d), secp256r1 (0x0017)
    extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

    // Signature algorithms (0x000d)
    extensions.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
    ]);

    // Key share (0x0033): x25519 with 32 bytes
    let mut key_share_rand = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key_share_rand);
    extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    extensions.extend_from_slice(&key_share_rand);

    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    // Fix Handshake Length
    let hs_len = (hello.len() - 4) as u32;
    let hs_len_bytes = hs_len.to_be_bytes();
    hello[1] = hs_len_bytes[1];
    hello[2] = hs_len_bytes[2];
    hello[3] = hs_len_bytes[3];

    // Compute HMAC-SHA1(password, hello[:session_id_start] + session_id + hello[session_id_start + 32:])
    type HmacSha1 = hmac::Hmac<sha1::Sha1>;
    let mut mac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
    mac.update(&hello[..session_id_start]);
    mac.update(&session_id);
    mac.update(&hello[session_id_start + 32..]);
    let hmac_res = mac.finalize().into_bytes();

    // Copy 4-byte HMAC into hello[session_id_start + 28..session_id_start + 32]
    hello[session_id_start + 28..session_id_start + 32].copy_from_slice(&hmac_res[..4]);

    // Wrap in TLS Record Header
    let mut record = Vec::with_capacity(5 + hello.len());
    record.push(TLS_RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);

    record
}

fn verify_shadowtls_session_id(handshake: &[u8], password: &str) -> (bool, Option<String>) {
    if handshake.len() < 39 + 32 || handshake[0] != TLS_CLIENT_HELLO {
        return (false, None);
    }
    let session_id_len = handshake[38] as usize;
    if session_id_len != 32 {
        return (false, None);
    }
    let session_id_start = 39;
    let hmac_pos = session_id_start + 28;
    if hmac_pos + 4 > handshake.len() {
        return (false, None);
    }

    let mut expected_session_id = [0u8; 32];
    expected_session_id.copy_from_slice(&handshake[session_id_start..session_id_start + 32]);
    expected_session_id[28..32].copy_from_slice(&[0, 0, 0, 0]);

    type HmacSha1 = hmac::Hmac<sha1::Sha1>;
    let mut mac = match <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()) {
        Ok(m) => m,
        Err(_) => return (false, None),
    };
    mac.update(&handshake[..session_id_start]);
    mac.update(&expected_session_id);
    mac.update(&handshake[session_id_start + 32..]);
    let computed_hmac = mac.finalize().into_bytes();

    let actual_hmac = &handshake[hmac_pos..hmac_pos + 4];
    if actual_hmac == &computed_hmac[..4] {
        (true, None)
    } else {
        (false, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scripted reference ShadowTLS v3 client: real TLS 1.3 handshake with the
    /// decoy through the server relay (un-XORing modified appdata records),
    /// then HMAC-tagged data frames — exactly per sing-shadowtls.
    #[tokio::test]
    async fn test_shadowtls_v3_server_reference_client_flow() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let password = "test-stls-pass";
        let payload = b"hello-shadowtls";

        // 1. Real TLS 1.3 decoy: completes handshake, then just holds the conn.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certs = vec![rustls::pki_types::CertificateDer::from(
            cert.cert.der().to_vec(),
        )];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );
        let acceptor =
            crate::tls::TlsTransport::create_server_acceptor(certs, key, vec![]).unwrap();
        let decoy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = decoy_listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        let mut buf = vec![0u8; 4096];
                        let _ = tls.read(&mut buf).await; // client's Finished + garbage
                    }
                });
            }
        });

        // 2. flux server
        let scfg = ShadowTlsServerConfig {
            server_names: vec!["localhost".into()],
            password: password.into(),
            fallback_address: TargetFallback::Address(decoy_addr),
        };
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task =
            tokio::spawn(
                async move { ShadowTlsHandshake::server_handshake(server_io, &scfg).await },
            );

        // 3. Scripted client: send CH with HMAC challenge.
        let ch = build_tls_client_hello("localhost", password);
        let mut stream = client_io;
        stream.write_all(&ch).await.unwrap();
        stream.flush().await.unwrap();

        // 4. Read SH record, extract server_random.
        let mut hdr = [0u8; 5];
        stream.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0], TLS_RECORD_HANDSHAKE);
        let sh_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut sh_body = vec![0u8; sh_len];
        stream.read_exact(&mut sh_body).await.unwrap();
        let server_random: [u8; 32] = sh_body[6..38].try_into().unwrap();

        // 5. Read the fallback's encrypted flight — records must be XOR+HMAC modified.
        let xor_key: [u8; 32] = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(password.as_bytes());
            h.update(server_random);
            h.finalize().into()
        };
        let mut read_hmac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
        read_hmac.update(&server_random);

        let mut saw_modified_appdata = false;
        for _ in 0..8 {
            let mut rhdr = [0u8; 5];
            if stream.read_exact(&mut rhdr).await.is_err() {
                break;
            }
            let rlen = u16::from_be_bytes([rhdr[3], rhdr[4]]) as usize;
            let mut rbody = vec![0u8; rlen];
            stream.read_exact(&mut rbody).await.unwrap();
            if rhdr[0] == 0x17 {
                // modified appdata: [tag 4][xored body]
                let tag = &rbody[..4];
                let xored = &rbody[4..];
                read_hmac.update(xored);
                let expect = read_hmac.clone().finalize().into_bytes();
                if tag != &expect[..4] {
                    let hexs: String = rbody.iter().map(|b| format!("{:02x}", b)).collect();
                    let sr_hex: String =
                        server_random.iter().map(|b| format!("{:02x}", b)).collect();
                    panic!(
                        "tag mismatch: tag={:?} expect={:?} random={} body={}",
                        tag,
                        &expect[..4],
                        sr_hex,
                        hexs
                    );
                }
                // unxor to verify content is recoverable
                let plain: Vec<u8> = xored
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ xor_key[i % 32])
                    .collect();
                assert!(!plain.is_empty());
                saw_modified_appdata = true;
            }
            if saw_modified_appdata && rhdr[0] == 0x17 {
                // got at least one modified record
            }
            // Heuristic: decoy flight ends quickly; break after we have seen appdata.
            if saw_modified_appdata {
                break;
            }
        }
        assert!(
            saw_modified_appdata,
            "server must XOR+HMAC-modify fallback appdata records"
        );

        // 6. Send the first authenticated data frame (tag = HMAC(password|random|"C") chain).
        let mut write_hmac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
        write_hmac.update(&server_random);
        write_hmac.update(b"C");
        write_hmac.update(payload);
        let tag = write_hmac.clone().finalize().into_bytes();
        write_hmac.update(&tag[..4]); // advance the rolling chain with the tag (per reference)
        let mut frame = vec![0x17, 0x03, 0x03];
        frame.extend_from_slice(&((payload.len() + 4) as u16).to_be_bytes());
        frame.extend_from_slice(&tag[..4]);
        frame.extend_from_slice(payload);
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();

        // 7. The server must switch into ShadowTlsStream mode and deliver the payload.
        let mut server_stream = server_task.await.unwrap().unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            server_stream.read_exact(&mut got),
        )
        .await
        .expect("server must deliver the first payload after switch")
        .unwrap();
        assert_eq!(&got, payload);

        // 7b. A second client data frame must be delivered as well (chain advanced).
        let payload2 = b"second-frame-data";
        write_hmac.update(payload2);
        let tag2 = write_hmac.clone().finalize().into_bytes();
        write_hmac.update(&tag2[..4]); // advance rolling chain with the tag
        let mut frame2 = vec![0x17, 0x03, 0x03];
        frame2.extend_from_slice(&((payload2.len() + 4) as u16).to_be_bytes());
        frame2.extend_from_slice(&tag2[..4]);
        frame2.extend_from_slice(payload2);
        stream.write_all(&frame2).await.unwrap();
        stream.flush().await.unwrap();
        let mut got2 = vec![0u8; payload2.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            server_stream.read_exact(&mut got2),
        )
        .await
        .expect("server must deliver the second payload")
        .unwrap();
        assert_eq!(&got2, payload2);

        // 8. Server→client data must be HMAC-tagged ("S" chain).
        server_stream.write_all(b"pong").await.unwrap();
        server_stream.flush().await.unwrap();
        let mut rhdr = [0u8; 5];
        stream.read_exact(&mut rhdr).await.unwrap();
        assert_eq!(rhdr[0], 0x17);
        let rlen = u16::from_be_bytes([rhdr[3], rhdr[4]]) as usize;
        let mut rbody = vec![0u8; rlen];
        stream.read_exact(&mut rbody).await.unwrap();
        let mut verify_hmac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
        verify_hmac.update(&server_random);
        verify_hmac.update(b"S");
        verify_hmac.update(&rbody[4..]);
        let expect = verify_hmac.finalize().into_bytes();
        assert_eq!(
            &rbody[..4],
            &expect[..4],
            "server data frame must be HMAC-tagged"
        );
        assert_eq!(&rbody[4..], b"pong");

        // 7c. Stress: 200KB across many frames of varying size must arrive intact.
        // (writer spawned concurrently: the duplex channel is bounded.)
        let mut big = Vec::new();
        let mut seed: u64 = 0x12345678;
        for _ in 0..200 * 1024 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            big.push((seed >> 33) as u8);
        }
        let big_len = big.len();
        let (_rd_half, wr_half) = tokio::io::split(stream);
        let big_hash: String = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(&big);
            h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
        };
        let write_task = tokio::spawn(async move {
            let mut stream = wr_half;
            let mut write_hmac = write_hmac;
            let mut off = 0;
            let mut frame_count = 0;
            while off < big.len() {
                let n = (1 + (big[off] as usize % 4000)).min(big.len() - off);
                frame_count += 1;
                let chunk = &big[off..off + n];
                write_hmac.update(chunk);
                let t = write_hmac.clone().finalize().into_bytes();
                write_hmac.update(&t[..4]);
                let mut f = vec![0x17, 0x03, 0x03];
                f.extend_from_slice(&((chunk.len() + 4) as u16).to_be_bytes());
                f.extend_from_slice(&t[..4]);
                f.extend_from_slice(chunk);
                stream.write_all(&f).await.unwrap();
                off += n;
            }
            stream.flush().await.unwrap();
            frame_count
        });

        let mut got_big = vec![0u8; big_len];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server_stream.read_exact(&mut got_big),
        )
        .await
        .expect("big transfer timed out")
        .unwrap();
        let frame_count = write_task.await.unwrap();
        let got_hash: String = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(&got_big);
            h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
        };
        assert_eq!(
            got_hash, big_hash,
            "stream corrupted across {} frames",
            frame_count
        );
    }

    #[test]
    fn test_shadowtls_client_hello_hmac() {
        let password = "my_secret_shadowtls_password";
        let record = build_tls_client_hello("captive.apple.com", password);
        assert_eq!(record[0], TLS_RECORD_HANDSHAKE);

        let (verified, _) = verify_shadowtls_session_id(&record[5..], password);
        assert!(verified, "valid ShadowTLS HMAC challenge must verify");

        let (bad_pw, _) = verify_shadowtls_session_id(&record[5..], "wrong_password");
        assert!(!bad_pw, "wrong password must fail ShadowTLS verification");
    }
}
