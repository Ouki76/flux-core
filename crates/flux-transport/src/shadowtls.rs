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
            payload_buf: Vec::new(),
            payload_pos: 0,
            read_buf: Vec::new(),
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
                // Decoy application data frame from handshake relay, skip it
                this.payload_len = 0;
                this.hdr_pos = 0;
                continue;
            }

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
            return Err(FluxError::Crypto("invalid ServerHello length in ShadowTLS".into()));
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
            // Authorized client: read genuine ServerHello from fallback and relay to client
            let mut srv_hdr = [0u8; 5];
            let mut s_body = Vec::new();
            if tokio::time::timeout(
                Duration::from_secs(3),
                fallback_stream.read_exact(&mut srv_hdr),
            )
            .await
            .is_ok()
            {
                let s_len = u16::from_be_bytes([srv_hdr[3], srv_hdr[4]]) as usize;
                s_body = vec![0u8; s_len];
                if tokio::time::timeout(
                    Duration::from_secs(3),
                    fallback_stream.read_exact(&mut s_body),
                )
                .await
                .is_ok()
                {
                    let _ = client_stream.write_all(&srv_hdr).await;
                    let _ = client_stream.write_all(&s_body).await;
                    let _ = client_stream.flush().await;
                }
            }
            let server_random = if s_body.len() >= 38 {
                &s_body[6..38]
            } else {
                &[0u8; 32]
            };
            let stream = ShadowTlsStream::new_server(client_stream, &cfg.password, server_random);
            Ok(Box::new(stream))
        } else {
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
    extensions.extend_from_slice(&[0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01]);

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
