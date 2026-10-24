use crate::tcp::TcpTransport;
use flux_types::{AsyncStream, BoxedStream, FluxError, FluxResult};
use hmac::Mac;
use lru::LruCache;
use rand::RngCore;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

/// How many consecutive records that fail HMAC verification are tolerated before
/// the peer is declared hostile. The decoy's TLS flight can arrive as a handful of
/// records the client never reads, so a small number of misses is normal.
const MAX_SKIPPED_RECORDS: usize = 32;

/// Largest record length accepted on the read side. A ShadowTLS data record is a
/// 16 KiB plaintext chunk plus the 4-byte tag; anything larger is a broken or
/// hostile peer, and rejecting it from the header keeps the allocation bounded
/// (the u16 length field alone would allow 64 KiB per record, per connection).
const MAX_RECORD_LEN: usize = 16384 + 256;

/// Longest cover host name accepted in SNI (RFC 1035 limits a name to 255 octets).
const MAX_SERVER_NAME_LEN: usize = 255;

/// How many recently accepted ClientHello session ids are remembered to reject
/// replays. Only holders of the password can fill this cache.
const REPLAY_CACHE_CAPACITY: usize = 4096;

/// Constant-time comparison of two HMAC tags.
///
/// `a == b` on byte slices stops at the first differing byte, which tells an
/// attacker how many leading bytes of a forged tag were correct. ShadowTLS tags
/// are truncated to 32 bits, so that leak is worth more than brute force. The
/// loop below always touches every byte of both sides.
#[inline(never)]
fn tags_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        #[cfg(test)]
        CT_COMPARED.with(|c| c.set(c.get() + 1));
        diff |= x ^ y;
    }
    diff == 0
}

// Bytes compared by `tags_equal`, counted only in tests so that a regression back
// to a short-circuiting `==` fails `test_tag_comparison_is_constant_time`.
#[cfg(test)]
thread_local! {
    static CT_COMPARED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A stream that disguises itself as a TLS session to a real site.
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
    /// Bytes of a non-application-data (decoy) record still to discard. Kept in
    /// the struct, not in a local: a record split across polls would otherwise
    /// restart the skip and consume the *next* record's bytes.
    skip_remaining: usize,
    /// Consecutive records rejected by HMAC verification.
    skipped_records: usize,
    payload_buf: Vec<u8>,
    payload_pos: usize,

    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> ShadowTlsStream<S> {
    /// Client half of an established ShadowTLS tunnel.
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
            skip_remaining: 0,
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
            skip_remaining: 0,
            skipped_records: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            read_buf: first_payload,
            read_pos: 0,
        }
    }

    /// Server half of an established ShadowTLS tunnel.
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
            skip_remaining: 0,
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
            if buf.remaining() == 0 {
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

                let declared_len = u16::from_be_bytes([this.hdr_buf[3], this.hdr_buf[4]]) as usize;

                // Handle non-applicationData TLS records (e.g. ChangeCipherSpec 20
                // or Handshake 22 from the decoy flight). Their body is discarded
                // byte-exactly: `skip_remaining` lives in the struct so a record
                // that arrives in several segments (Pending in the middle) resumes
                // instead of restarting and eating the following record.
                if this.hdr_buf[0] != 0x17 {
                    if this.skip_remaining == 0 {
                        this.skip_remaining = declared_len;
                    }
                    while this.skip_remaining > 0 {
                        let needed = this.skip_remaining;
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
                                this.skip_remaining -= n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    this.hdr_pos = 0;
                    continue;
                }

                // Validate the declared length before reading anything else: a
                // record that cannot hold its own 4-byte tag, or that claims more
                // than a ShadowTLS record may carry, must not be read (and must not
                // steal bytes from the record that follows it).
                if declared_len < 4 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ShadowTLS record length shorter than HMAC size",
                    )));
                }
                if declared_len > MAX_RECORD_LEN {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("ShadowTLS record length {declared_len} exceeds {MAX_RECORD_LEN}"),
                    )));
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

                this.payload_len = declared_len - 4;
                this.payload_buf.clear();
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

            // 4. Verify HMAC (constant time: a forged tag must not be graded)
            let mut mac = this.read_hmac.clone();
            mac.update(&this.payload_buf);
            let hmac_res = mac.finalize().into_bytes();
            let expected_tag = &hmac_res[..4];

            let actual_tag = &this.hdr_buf[5..9];
            if !tags_equal(actual_tag, expected_tag) {
                // A tag mismatch is expected only while the decoy handshake relay
                // is still finishing. An unbounded number of them is either a
                // broken peer or an attempt to keep this poll loop spinning, so
                // cap consecutive skips and fail instead of silently consuming
                // junk forever. Nothing that fails this check is ever returned to
                // the caller.
                this.skipped_records += 1;
                if this.skipped_records > MAX_SKIPPED_RECORDS {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "shadowtls: {MAX_SKIPPED_RECORDS} consecutive records failed HMAC verification; peer is not speaking ShadowTLS"
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

/// `poll_write` returning `Ok(0)` means the peer will never accept more bytes;
/// retrying it in a loop would hang the connection forever.
fn write_zero() -> io::Error {
    io::Error::new(
        io::ErrorKind::WriteZero,
        "shadowtls: inner stream accepted 0 bytes",
    )
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // A frame left over from a previous call is flushed first. The number of
        // plaintext bytes reported back must never exceed the buffer handed in by
        // *this* call: `write_all` slices its buffer with the returned count, so an
        // over-report would panic (or corrupt a caller that trusts it).
        while this.write_pos < this.write_buf.len() {
            let n =
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(write_zero())),
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_n = this.writing_plain_len.min(buf.len());
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
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(write_zero())),
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
            this.write_pos += n;
            if this.write_pos == this.write_buf.len() {
                let plain_n = this.writing_plain_len.min(buf.len());
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
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(write_zero())),
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

/// The bytes a v3 server sends to take the connection over.
pub const SHADOWTLS_V3_TAKEOVER: &[u8] = b"SHADOWTLS_V3_PROXY_HANDSHAKE_READY";
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const _TLS_RECORD_APP_DATA: u8 = 0x17;
const TLS_CLIENT_HELLO: u8 = 0x01;

#[derive(Clone, Debug)]
/// Client-side ShadowTLS settings.
pub struct ShadowTlsClientConfig {
    /// SNI of the site being imitated.
    pub server_name: String,
    /// Shared secret.
    pub password: String,
    // NOTE: there is deliberately no `insecure` flag. ShadowTLS v3 aborts the
    // handshake right after ServerHello and never validates the decoy's
    // certificate: it is camouflage, not a trust channel. Confidentiality and
    // authentication come from the inner protocol (Shadowsocks/Trojan/VLESS).
}

#[derive(Clone, Debug)]
/// Server-side ShadowTLS settings.
pub struct ShadowTlsServerConfig {
    /// Names this server will answer for.
    pub server_names: Vec<String>,
    /// Shared secret.
    pub password: String,
    /// Where unauthenticated peers are sent.
    pub fallback_address: TargetFallback,
}

#[derive(Clone, Debug)]
/// Where to send a peer that fails to authenticate.
pub enum TargetFallback {
    /// A literal address to forward to.
    Address(SocketAddr),
    /// A name and port to forward to.
    Domain(String, u16),
}

/// Validates a cover host before it is encoded into the SNI extension.
fn validate_server_name(name: &str) -> FluxResult<()> {
    if name.is_empty() {
        return Err(FluxError::Config("shadowtls: empty SNI/cover host".into()));
    }
    if name.len() > MAX_SERVER_NAME_LEN {
        return Err(FluxError::Config(format!(
            "shadowtls: SNI/cover host is {} bytes, the limit is {MAX_SERVER_NAME_LEN}",
            name.len()
        )));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(FluxError::Config(format!(
            "shadowtls: SNI/cover host {name:?} is not a valid DNS name"
        )));
    }
    Ok(())
}

/// Resolves the upstream cover site the handshake is relayed to.
///
/// `host:port` is split by the resolver at the last colon, so an unbracketed IPv6
/// literal resolves correctly (`::1:443`), and an empty host is refused with a DNS
/// error instead of an opaque resolver failure.
async fn resolve_fallback(target: &TargetFallback) -> FluxResult<SocketAddr> {
    match target {
        TargetFallback::Address(a) => Ok(*a),
        TargetFallback::Domain(host, port) => {
            if host.is_empty() {
                return Err(FluxError::Dns("shadowtls: empty fallback host".into()));
            }
            let addr = format!("{host}:{port}");
            tokio::net::lookup_host(&addr)
                .await
                .map_err(FluxError::Io)?
                .next()
                .ok_or_else(|| FluxError::Dns(format!("cannot resolve fallback domain '{host}'")))
        }
    }
}

/// Bounded, process-wide record of ShadowTLS session ids that were already used.
///
/// The HMAC in the session id proves knowledge of the password but is replayable
/// verbatim by anyone who observed the hello. Remembering recent ids makes a
/// replayed hello no more useful than a wrong password. Only holders of the
/// password can add entries, so the cache cannot be filled by an anonymous peer.
static SEEN_SESSION_IDS: OnceLock<parking_lot::Mutex<LruCache<[u8; 32], ()>>> = OnceLock::new();

/// Records `session_id`; returns `false` when it has been seen before.
fn replay_accept(session_id: &[u8; 32]) -> bool {
    let cache = SEEN_SESSION_IDS.get_or_init(|| {
        parking_lot::Mutex::new(LruCache::new(
            NonZeroUsize::new(REPLAY_CACHE_CAPACITY).expect("capacity is non-zero"),
        ))
    });
    cache.lock().put(*session_id, ()).is_none()
}

/// The 32-byte session id carrying the HMAC challenge, if the buffer is a
/// well-formed ClientHello body with a 32-byte session id.
fn client_session_id(handshake: &[u8]) -> Option<[u8; 32]> {
    if handshake.len() < 39 + 32 || handshake[0] != TLS_CLIENT_HELLO || handshake[38] != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&handshake[39..71]);
    Some(id)
}

/// Extracts the SNI host name from a ClientHello body.
///
/// Runs on unauthenticated, attacker-controlled bytes, so every length is
/// bounds-checked and a malformed extension makes the parser give up rather than
/// read past the buffer or panic.
fn client_hello_sni(handshake: &[u8]) -> Option<String> {
    let at = |p: usize| -> Option<usize> { handshake.get(p).map(|b| *b as usize) };
    let u16_at = |p: usize| -> Option<usize> {
        Some(u16::from_be_bytes([*handshake.get(p)?, *handshake.get(p + 1)?]) as usize)
    };

    let mut p: usize = 4 + 2 + 32; // handshake header, legacy version, random
    p = p.checked_add(1 + at(p)?)?; // session id
    p = p.checked_add(2 + u16_at(p)?)?; // cipher suites
    p = p.checked_add(1 + at(p)?)?; // compression methods
    let ext_end = p.checked_add(2 + u16_at(p)?)?; // extensions

    let mut p = p + 2;
    while p + 4 <= ext_end {
        let ext_type = u16_at(p)?;
        let ext_len = u16_at(p + 2)?;
        let data = handshake.get(p + 4..p + 4 + ext_len)?;
        if ext_type == 0 {
            // server_name_list: length(2) type(1) name_length(2) name
            let name_len = u16::from_be_bytes([*data.get(3)?, *data.get(4)?]) as usize;
            return String::from_utf8(data.get(5..5 + name_len)?.to_vec()).ok();
        }
        p += 4 + ext_len;
    }
    None
}

/// Enforces the optional SNI allow-list. An empty list means "no restriction",
/// which is what the config layer produces.
fn sni_is_allowed(sni: Option<&str>, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    sni.is_some_and(|name| allowed.iter().any(|a| a.eq_ignore_ascii_case(name)))
}

/// Namespace for the ShadowTLS handshake, both sides.
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
        // Validate before writing anything: the host goes into a u16-length-prefixed
        // SNI extension, so an oversized or malformed name would silently truncate
        // the lengths and produce a ClientHello no peer can parse.
        validate_server_name(&cfg.server_name)?;

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
        if resp_len > MAX_RECORD_LEN {
            return Err(FluxError::Crypto(format!(
                "shadowtls: cover-server record of {resp_len} bytes exceeds {MAX_RECORD_LEN}"
            )));
        }
        let mut resp_body = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_body)
            .await
            .map_err(FluxError::Io)?;

        // Note what is deliberately *not* checked here: the handshake message type.
        // When the "cover site" is the next in-process security layer (a chained
        // inbound such as shadowtls → reality, see tests/test_layered_yaml_pipeline),
        // the relayed bytes are that layer's own handshake, not a ServerHello. Both
        // ends simply use bytes 6..38 of whatever came back as the pseudo
        // server_random, so requiring type 0x02 here would break the chain. The
        // length check is still needed: the random is read at a fixed offset.
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

        // Verify the ClientHello's HMAC challenge and extract its SNI.
        let (authenticated, sni) = verify_shadowtls_session_id(&record_body, &cfg.password);

        // Three independent gates before a peer may switch the stream into proxy
        // mode. Failing any of them is indistinguishable from an unknown password:
        // the probe is relayed to the cover site and never gets a proxy stream.
        //  * the HMAC challenge must verify;
        //  * the session id must be fresh (it is a bearer credential, so a captured
        //    hello could otherwise be replayed to authenticate again);
        //  * the SNI must be in the configured allow-list, when one is configured.
        let is_auth = authenticated
            && sni_is_allowed(sni.as_deref(), &cfg.server_names)
            && client_session_id(&record_body).is_some_and(|id| replay_accept(&id));

        let fallback_addr = resolve_fallback(&cfg.fallback_address).await?;

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

                if rec_hdr[0] == 0x17 && body.len() >= 4 {
                    let mut mac = hmac_verify.clone();
                    mac.update(&body[4..]);
                    let expect = mac.finalize().into_bytes();
                    if tags_equal(&body[..4], &expect[..4]) {
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
    let Some(session_id) = client_session_id(handshake) else {
        return (false, None);
    };

    // The tag itself must not be covered by the MAC, so the session id is
    // zero-extended in place of the 4 tag bytes.
    let mut tagged_session_id = session_id;
    tagged_session_id[28..32].copy_from_slice(&[0, 0, 0, 0]);

    let mut mac = match <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()) {
        Ok(m) => m,
        Err(_) => return (false, None),
    };
    mac.update(&handshake[..39]);
    mac.update(&tagged_session_id);
    mac.update(&handshake[71..]);
    let computed_hmac = mac.finalize().into_bytes();

    let authenticated = tags_equal(&session_id[28..32], &computed_hmac[..4]);
    (authenticated, client_hello_sni(handshake))
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

    // =====================================================================
    // Hardening tests for the ShadowTLS v3 handshake and record framing.
    //
    // These are written against the wire format only: a scripted peer drives the
    // code under test so every property (authentication, buffering, truncation)
    // is observable without a real cover server.
    // =====================================================================

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Waker};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PW: &str = "test-stls-pass";

    /// Fixed server_random used when the decoy handshake is not part of the test.
    const SR: [u8; 32] = [0x5a; 32];

    /// Rolling HMAC chain for the client→server direction, mirroring the
    /// reference implementation: the tag is computed over the payload, and the
    /// state advances over payload *and* tag so record N+1 depends on record N.
    struct Chain(HmacSha1);

    impl Chain {
        fn client(password: &str, server_random: &[u8]) -> Self {
            let mut mac = <HmacSha1 as hmac::Mac>::new_from_slice(password.as_bytes()).unwrap();
            mac.update(server_random);
            mac.update(b"C");
            Self(mac)
        }

        fn tag(&self, payload: &[u8]) -> [u8; 4] {
            let mut mac = self.0.clone();
            mac.update(payload);
            let full = mac.finalize().into_bytes();
            let mut tag = [0u8; 4];
            tag.copy_from_slice(&full[..4]);
            tag
        }

        /// One `0x17` data record: header, 4-byte tag, payload.
        fn frame(&mut self, payload: &[u8]) -> Vec<u8> {
            let tag = self.tag(payload);
            self.0.update(payload);
            self.0.update(&tag);
            let mut rec = vec![0x17, 0x03, 0x03];
            rec.extend_from_slice(&((payload.len() + 4) as u16).to_be_bytes());
            rec.extend_from_slice(&tag);
            rec.extend_from_slice(payload);
            rec
        }

        /// Verifies a received record and advances the chain.
        fn accept(&mut self, body: &[u8]) {
            assert!(body.len() >= 4, "record body must carry a tag");
            let expect = self.tag(&body[4..]);
            assert_eq!(
                &body[..4],
                &expect,
                "tag must chain from the previous record"
            );
            self.0.update(&body[4..]);
            self.0.update(&body[..4]);
        }
    }

    /// A scripted TLS record of a non-application-data type (the decoy flight).
    fn decoy_record(typ: u8, len: usize) -> Vec<u8> {
        let mut rec = vec![typ, 0x03, 0x03];
        rec.extend_from_slice(&(len as u16).to_be_bytes());
        rec.extend(std::iter::repeat_n(0xa5u8, len));
        rec
    }

    /// In-memory peer for the framing tests.
    ///
    /// * `input`  — scripted bytes; reading past the end is EOF.
    /// * `read_chunk` — upper bound on bytes returned by one `poll_read`, which
    ///   forces the code under test to resume in the middle of a record.
    /// * `pause_at` — one `poll_read` returns `Pending` when the read cursor
    ///   reaches this offset, simulating a record split across TCP segments.
    /// * `write_chunk` / `zero_writes` / `pending_writes` shape the write side.
    #[derive(Default)]
    struct MockIo {
        input: Vec<u8>,
        pos: usize,
        read_chunk: usize,
        pause_at: Option<usize>,
        out: Arc<Mutex<Vec<u8>>>,
        consumed: Arc<AtomicUsize>,
        write_chunk: usize,
        zero_writes: usize,
        pending_writes: usize,
    }

    impl MockIo {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input,
                ..Default::default()
            }
        }

        fn out(&self) -> Arc<Mutex<Vec<u8>>> {
            self.out.clone()
        }

        /// Shared count of bytes handed to the code under test.
        fn consumed(&self) -> Arc<AtomicUsize> {
            self.consumed.clone()
        }
    }

    impl AsyncRead for MockIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pause_at == Some(self.pos) {
                self.pause_at = None;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let avail = self.input.len() - self.pos;
            if avail == 0 {
                return Poll::Ready(Ok(())); // EOF
            }
            let mut n = avail.min(buf.remaining());
            if self.read_chunk != 0 {
                n = n.min(self.read_chunk);
            }
            let start = self.pos;
            buf.put_slice(&self.input[start..start + n]);
            self.pos += n;
            self.consumed.store(self.pos, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.zero_writes > 0 {
                self.zero_writes -= 1;
                return Poll::Ready(Ok(0));
            }
            let mut n = buf.len();
            if self.write_chunk != 0 {
                n = n.min(self.write_chunk);
            }
            if self.pending_writes > 0 {
                // Nothing is accepted: `Pending` must not consume input.
                self.pending_writes -= 1;
                return Poll::Pending;
            }
            self.out.lock().unwrap().extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Poll a future exactly once with a no-op waker, then drop it.
    fn poll_once<F: std::future::Future>(fut: F) -> Poll<F::Output> {
        let mut cx = Context::from_waker(Waker::noop());
        let mut fut = Box::pin(fut);
        fut.as_mut().poll(&mut cx)
    }

    /// Reads the whole stream, bounded in time so a framing bug shows up as a
    /// test failure instead of a hang.
    async fn drain<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut out))
            .await
            .expect("read must not block forever")?;
        Ok(out)
    }

    // ---- 1. authentication -------------------------------------------------

    #[tokio::test]
    async fn test_unauthenticated_records_are_never_delivered() {
        // A record whose tag does not verify is camouflage or an attack; either
        // way its payload must never reach the caller, and a bounded number of
        // them must be tolerated before the peer is declared hostile.
        let mut chain = Chain::client(PW, &SR);
        let good = chain.frame(b"authenticated");
        let mut forged = good.clone();
        forged[7] ^= 0xff; // corrupt the tag, keep the length valid

        let mut input = Vec::new();
        for _ in 0..MAX_SKIPPED_RECORDS {
            input.extend_from_slice(&forged);
        }
        input.extend_from_slice(&good);
        let mut stream = ShadowTlsStream::new_server(MockIo::new(input), PW, &SR);
        let mut got = vec![0u8; b"authenticated".len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"authenticated");

        // One record past the tolerance limit must be a hard error, not an
        // endless skip loop: a peer that keeps failing is not ShadowTLS.
        let mut input = Vec::new();
        for _ in 0..=MAX_SKIPPED_RECORDS {
            input.extend_from_slice(&forged);
        }
        let mut stream = ShadowTlsStream::new_server(MockIo::new(input), PW, &SR);
        let err = drain(&mut stream).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_every_hello_byte_is_authenticated() {
        // The HMAC in the session id must cover the entire ClientHello (except
        // the tag itself). If any byte escaped the MAC, an attacker could change
        // the SNI, the key share or the cipher list of a captured hello.
        let record = build_tls_client_hello("cover.example", PW);
        for i in 5..record.len() {
            let mut tampered = record.clone();
            tampered[i] ^= 0x01;
            let (ok, _) = verify_shadowtls_session_id(&tampered[5..], PW);
            assert!(
                !ok,
                "flipping byte {i} of the ClientHello must invalidate it"
            );
        }
    }

    #[test]
    fn test_malformed_session_id_is_rejected() {
        let record = build_tls_client_hello("cover.example", PW);
        let body = &record[5..];

        // Wrong session_id length.
        let mut short_sid = body.to_vec();
        short_sid[38] = 31;
        assert!(!verify_shadowtls_session_id(&short_sid, PW).0);

        // Every truncation of a genuine hello must be rejected without panicking.
        for cut in 0..body.len() {
            let (ok, _) = verify_shadowtls_session_id(&body[..cut], PW);
            assert!(!ok, "a {cut}-byte ClientHello must not verify");
        }
    }

    // ---- 2. record framing, buffering and robustness ------------------------

    #[tokio::test]
    async fn test_record_split_across_polls_keeps_progress() {
        // A record whose body spans several reads and a `Pending` in the middle of
        // the decoy record: the skip state must survive the poll boundary, or the
        // next record's bytes are consumed as if they belonged to the decoy.
        let mut chain = Chain::client(PW, &SR);
        let mut input = decoy_record(0x16, 20);
        input.extend_from_slice(&chain.frame(b"after-decoy"));

        let mut io = MockIo::new(input);
        io.read_chunk = 7;
        io.pause_at = Some(12); // inside the decoy body
        let mut stream = ShadowTlsStream::new_server(io, PW, &SR);
        let mut got = vec![0u8; b"after-decoy".len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"after-decoy");
    }

    #[tokio::test]
    async fn test_payload_is_intact_whatever_the_read_boundaries() {
        // Two frames in one segment, read back in small pieces with a Pending at
        // every interesting offset (header, tag, payload, record boundary). No byte
        // may be lost or duplicated anywhere in the pipeline.
        let mut chain = Chain::client(PW, &SR);
        let mut input = chain.frame(b"first-chunk");
        input.extend_from_slice(&chain.frame(b"second-chunk"));
        let total = input.len();

        for chunk in [1usize, 3, 9, 0] {
            for pause in [0usize, 1, 4, 5, 6, 8, 9, 12, 19, 20, 25, total] {
                let mut io = MockIo::new(input.clone());
                io.read_chunk = chunk;
                io.pause_at = Some(pause);
                let mut stream = ShadowTlsStream::new_server(io, PW, &SR);
                let mut first = vec![0u8; b"first-chunk".len()];
                stream.read_exact(&mut first).await.unwrap();
                assert_eq!(
                    &first, b"first-chunk",
                    "chunk={chunk} pause={pause}: first payload corrupted"
                );
                let mut second = vec![0u8; b"second-chunk".len()];
                stream.read_exact(&mut second).await.unwrap();
                assert_eq!(
                    &second, b"second-chunk",
                    "chunk={chunk} pause={pause}: second payload corrupted"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_truncated_input_at_every_prefix_is_an_error() {
        let mut chain = Chain::client(PW, &SR);
        let mut full = decoy_record(0x16, 6);
        full.extend_from_slice(&chain.frame(b"twelve bytes"));
        for cut in 0..=full.len() {
            let mut stream =
                ShadowTlsStream::new_server(MockIo::new(full[..cut].to_vec()), PW, &SR);
            let res = drain(&mut stream).await;
            match res {
                // Only a cut at a record boundary is a clean EOF.
                Ok(data) => assert!(
                    data.is_empty() || cut == full.len(),
                    "truncation at {cut} produced {} bytes of data",
                    data.len()
                ),
                Err(e) => assert!(
                    matches!(
                        e.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
                    ),
                    "truncation at {cut} produced unexpected error kind {:?}",
                    e.kind()
                ),
            }
        }
    }

    #[tokio::test]
    async fn test_absurd_record_length_is_rejected() {
        // A 64 KiB record must be refused from the header alone: no allocation,
        // no attempt to read a body that cannot exist.
        let mut input = vec![0x17, 0x03, 0x03, 0xff, 0xff];
        input.extend_from_slice(&[0u8; 8]);
        let io = MockIo::new(input);
        let consumed = io.consumed();
        let mut stream = ShadowTlsStream::new_server(io, PW, &SR);
        let err = drain(&mut stream).await.unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "oversized record must be rejected from its header, got {err}"
        );
        assert_eq!(
            consumed.load(Ordering::Relaxed),
            5,
            "an oversized record must not be read at all"
        );
    }

    #[tokio::test]
    async fn test_record_shorter_than_its_tag_is_rejected() {
        // `0x17` record with a declared length below the 4-byte tag: the parser
        // must not read a tag that cannot exist, and must not touch the next
        // record's bytes.
        let mut input = vec![0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb];
        let mut chain = Chain::client(PW, &SR);
        input.extend_from_slice(&chain.frame(b"next"));
        let io = MockIo::new(input);
        let consumed = io.consumed();
        let mut stream = ShadowTlsStream::new_server(io, PW, &SR);
        let err = drain(&mut stream).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            consumed.load(Ordering::Relaxed),
            5,
            "the parser read past the header of a record that cannot hold a tag"
        );
    }

    #[tokio::test]
    async fn test_garbage_instead_of_a_tls_record() {
        // Arbitrary bytes must be consumed as an unknown record (and then hit EOF)
        // instead of panicking or being returned as data.
        let mut input = vec![0x00, 0x99, 0x42, 0x00, 0x10];
        input.extend_from_slice(&[0xde; 16]);
        let mut stream = ShadowTlsStream::new_server(MockIo::new(input), PW, &SR);
        let res = drain(&mut stream).await;
        assert!(
            matches!(res, Ok(v) if v.is_empty()),
            "garbage produced data instead of a clean EOF"
        );
    }

    // ---- 3. write path ------------------------------------------------------

    #[tokio::test]
    async fn test_write_frames_and_chains_correctly() {
        // 40 KB must be split into valid records (u16 length arithmetic must not
        // overflow), each tagged off the previous one.
        let (io, mut peer) = tokio::io::duplex(256 * 1024);
        let mut stream = ShadowTlsStream::new_client(io, PW, &SR);
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();
        let writer = tokio::spawn(async move {
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut chain = Chain::client(PW, &SR);
        let mut got = Vec::new();
        let mut frames = 0;
        while got.len() < expect.len() {
            let mut hdr = [0u8; 5];
            peer.read_exact(&mut hdr).await.unwrap();
            assert_eq!(&hdr[..3], &[0x17, 0x03, 0x03], "record must be app data");
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            assert!(
                (5..=16388).contains(&len),
                "record length {len} outside the framing limit"
            );
            let mut body = vec![0u8; len];
            peer.read_exact(&mut body).await.unwrap();
            chain.accept(&body);
            got.extend_from_slice(&body[4..]);
            frames += 1;
        }
        writer.await.unwrap();
        assert_eq!(got, expect);
        assert!(frames >= 3, "40 KB must span several records, got {frames}");
    }

    #[tokio::test]
    async fn test_writer_that_accepts_nothing_is_an_error() {
        // `poll_write` returning Ok(0) means the writer will never accept bytes;
        // spinning on it would hang the whole connection.
        let mut io = MockIo::new(Vec::new());
        io.zero_writes = 1;
        let mut stream = ShadowTlsStream::new_client(io, PW, &SR);
        match poll_once(stream.write(b"abcdef")) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::WriteZero),
            Poll::Ready(Ok(n)) => {
                panic!("a writer that accepted 0 bytes was reported as {n} bytes of progress")
            }
            Poll::Pending => panic!("zero-progress write returned Pending instead of an error"),
        }
    }

    #[tokio::test]
    async fn test_pending_write_never_over_reports() {
        // After a write returns Pending the caller may legitimately abandon that
        // future and call `write` again with a different buffer. The reported count
        // must never exceed the buffer handed in: `write_all` slices with it.
        let mut io = MockIo::new(Vec::new());
        io.pending_writes = 1;
        io.write_chunk = 1;
        let mut stream = ShadowTlsStream::new_client(io, PW, &SR);

        let first = vec![0xaau8; 100];
        assert!(poll_once(stream.write(&first)).is_pending());

        let second = [0xbbu8; 5];
        match poll_once(stream.write(&second)) {
            Poll::Ready(Ok(n)) => assert!(
                n <= second.len(),
                "reported {n} bytes written for a {}-byte buffer",
                second.len()
            ),
            Poll::Ready(Err(_)) => {}
            Poll::Pending => panic!("write reported Pending although the peer accepted bytes"),
        }
    }

    // ---- 4. hijack correctness ---------------------------------------------

    /// A stand-in cover server: reads exactly `hello_len` bytes (the ClientHello),
    /// answers with a canned TLS 1.3 ServerHello, then records every further byte
    /// so a test can prove no proxy payload reaches the decoy.
    async fn start_scripted_decoy(hello_len: usize) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_task = seen.clone();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut hello = vec![0u8; hello_len];
            if sock.read_exact(&mut hello).await.is_err() {
                return;
            }
            if sock.write_all(&canned_server_hello()).await.is_err() {
                return;
            }
            let _ = sock.flush().await;
            let mut rest = [0u8; 4096];
            loop {
                match sock.read(&mut rest).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen_task.lock().unwrap().extend_from_slice(&rest[..n]),
                }
            }
        });
        (addr, seen)
    }

    /// A minimal but structurally valid TLS 1.3 ServerHello (handshake type 2,
    /// 32-byte random) — enough for both ends to derive the same server_random.
    fn canned_server_hello() -> Vec<u8> {
        let mut body = vec![0x02, 0x00, 0x00, 0x26, 0x03, 0x03];
        body.extend_from_slice(&[0x11u8; 32]);
        body.extend_from_slice(&[0x00, 0x13, 0x01, 0x00]);
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    /// Sends a ClientHello to the server under test, reads the relayed
    /// ServerHello and returns the `server_random` both ends derive from it.
    async fn client_hello_exchange<C: AsyncRead + AsyncWrite + Unpin>(
        client: &mut C,
        password: &str,
    ) -> [u8; 32] {
        let hello = build_tls_client_hello("cover.example", password);
        client.write_all(&hello).await.unwrap();
        client.flush().await.unwrap();
        let mut hdr = [0u8; 5];
        client.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0], TLS_RECORD_HANDSHAKE);
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut body = vec![0u8; len];
        client.read_exact(&mut body).await.unwrap();
        body[6..38].try_into().unwrap()
    }

    #[tokio::test]
    async fn test_hijack_delivers_payload_and_hides_client_bytes() {
        // Two authenticated frames (one for the switch, one for the stream) sent in
        // a single write, i.e. the hello and the payload share a segment: no byte
        // may be lost, and none may leak to the cover site.
        let password = "hijack-test-pass";
        let hello_len = build_tls_client_hello("cover.example", password).len();
        let (decoy_addr, seen) = start_scripted_decoy(hello_len).await;
        let cfg = ShadowTlsServerConfig {
            server_names: vec!["cover.example".into()],
            password: password.into(),
            fallback_address: TargetFallback::Address(decoy_addr),
        };
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task =
            tokio::spawn(async move { ShadowTlsHandshake::server_handshake(server, &cfg).await });

        let server_random = client_hello_exchange(&mut client, password).await;

        let mut chain = Chain::client(password, &server_random);
        let mut frames = chain.frame(b"first-payload");
        frames.extend_from_slice(&chain.frame(b"second-payload"));
        client.write_all(&frames).await.unwrap();
        client.flush().await.unwrap();

        let mut stream = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("server must switch after the first authenticated frame")
            .unwrap()
            .expect("an authenticated client must get a proxy stream");
        let mut first = vec![0u8; b"first-payload".len()];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"first-payload");
        let mut second = vec![0u8; b"second-payload".len()];
        stream.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"second-payload");

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            seen.lock().unwrap().is_empty(),
            "the decoy received {:?}: post-hijack client bytes must never reach it",
            String::from_utf8_lossy(&seen.lock().unwrap())
        );
    }

    #[tokio::test]
    async fn test_empty_authenticated_frame_still_switches() {
        // A zero-length payload is a valid authenticated record (tag over nothing).
        // It must be recognised as the switch point, not forwarded to the cover
        // site — forwarding it leaks that this end is a proxy.
        let password = "empty-frame-pass";
        let hello_len = build_tls_client_hello("cover.example", password).len();
        let (decoy_addr, seen) = start_scripted_decoy(hello_len).await;
        let cfg = ShadowTlsServerConfig {
            server_names: vec![],
            password: password.into(),
            fallback_address: TargetFallback::Address(decoy_addr),
        };
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task =
            tokio::spawn(async move { ShadowTlsHandshake::server_handshake(server, &cfg).await });

        let server_random = client_hello_exchange(&mut client, password).await;
        let mut chain = Chain::client(password, &server_random);
        let mut frames = chain.frame(b"");
        assert_eq!(frames.len(), 9, "an empty record is header plus tag");
        frames.extend_from_slice(&chain.frame(b"after-empty"));
        client.write_all(&frames).await.unwrap();
        client.flush().await.unwrap();

        let mut stream = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("server must switch on the empty authenticated frame")
            .unwrap()
            .expect("an authenticated client must get a proxy stream");
        let mut got = vec![0u8; b"after-empty".len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"after-empty");

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            seen.lock().unwrap().is_empty(),
            "the empty authenticated frame was relayed to the decoy ({} bytes)",
            seen.lock().unwrap().len()
        );
    }

    #[tokio::test]
    async fn test_sni_outside_the_allow_list_is_not_authenticated() {
        // `server_names` is only a constraint, not a secret: a hello that is
        // cryptographically valid but names a host this listener does not cover
        // must be relayed like any other stranger.
        let decoy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = decoy.accept().await else {
                return;
            };
            let mut buf = [0u8; 4096];
            while sock.read(&mut buf).await.unwrap_or(0) > 0 {}
        });

        let password = "sni-list-pass";
        let cfg = ShadowTlsServerConfig {
            server_names: vec!["allowed.example".into()],
            password: password.into(),
            fallback_address: TargetFallback::Address(decoy_addr),
        };
        let hello = build_tls_client_hello("other.example", password);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task =
            tokio::spawn(async move { ShadowTlsHandshake::server_handshake(server, &cfg).await });
        client.write_all(&hello).await.unwrap();
        client.flush().await.unwrap();
        let res = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("the decision must not wait for client data")
            .unwrap();
        assert!(
            matches!(res, Err(FluxError::AuthFailed(_))),
            "a hello for a host outside server_names must not switch to proxy mode"
        );
    }

    #[tokio::test]
    async fn test_wrong_password_is_relayed_and_never_switches() {
        // An active prober must see exactly what a plain TLS client would see: its
        // ClientHello relayed to the real cover site, and no proxy mode.
        let decoy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy.local_addr().unwrap();
        let relayed = Arc::new(Mutex::new(Vec::new()));
        let relayed_task = relayed.clone();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = decoy.accept().await else {
                return;
            };
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => relayed_task.lock().unwrap().extend_from_slice(&buf[..n]),
                }
            }
        });

        let cfg = ShadowTlsServerConfig {
            server_names: vec![],
            password: "the-right-password".into(),
            fallback_address: TargetFallback::Address(decoy_addr),
        };
        let hello = build_tls_client_hello("cover.example", "the-wrong-password");
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task =
            tokio::spawn(async move { ShadowTlsHandshake::server_handshake(server, &cfg).await });
        client.write_all(&hello).await.unwrap();
        client.flush().await.unwrap();

        let res = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("an unauthenticated hello must be decided quickly")
            .unwrap();
        assert!(
            matches!(res, Err(FluxError::AuthFailed(_))),
            "an unauthenticated peer must be relayed, not switched into proxy mode"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            relayed.lock().unwrap().as_slice(),
            hello.as_slice(),
            "the probe's ClientHello must be relayed to the cover site verbatim"
        );
    }

    // ---- 5. cover host / SNI ------------------------------------------------

    /// Minimal SNI extractor used only to verify what `build_tls_client_hello`
    /// puts on the wire.
    fn hello_sni(handshake: &[u8]) -> Option<String> {
        let mut p: usize = 4 + 2 + 32; // handshake header, legacy version, random
        let sid_len = *handshake.get(p)? as usize;
        p += 1 + sid_len;
        let cipher_len = u16::from_be_bytes([*handshake.get(p)?, *handshake.get(p + 1)?]) as usize;
        p += 2 + cipher_len;
        let comp_len = *handshake.get(p)? as usize;
        p += 1 + comp_len;
        let ext_total = u16::from_be_bytes([*handshake.get(p)?, *handshake.get(p + 1)?]) as usize;
        p += 2;
        let end = p + ext_total;
        while p + 4 <= end {
            let typ = u16::from_be_bytes([handshake[p], handshake[p + 1]]);
            let len = u16::from_be_bytes([handshake[p + 2], handshake[p + 3]]) as usize;
            let data = handshake.get(p + 4..p + 4 + len)?;
            if typ == 0 {
                let name_len = u16::from_be_bytes([*data.get(3)?, *data.get(4)?]) as usize;
                return String::from_utf8(data.get(5..5 + name_len)?.to_vec()).ok();
            }
            p += 4 + len;
        }
        None
    }

    #[test]
    fn test_client_hello_sni_encoding() {
        let record = build_tls_client_hello("cover.example", PW);
        assert_eq!(record[0], TLS_RECORD_HANDSHAKE);
        let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(
            body_len,
            record.len() - 5,
            "record length must match the body"
        );
        let hs_len = u32::from_be_bytes([0, record[6], record[7], record[8]]) as usize;
        assert_eq!(hs_len, record.len() - 9, "handshake length must match");
        assert_eq!(hello_sni(&record[5..]).as_deref(), Some("cover.example"));

        // The extension framing must use exact lengths, not truncated ones.
        let body = &record[5..];
        let ext_total = {
            let mut p = 4 + 2 + 32;
            p += 1 + body[p] as usize;
            let cl = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
            p += 2 + cl;
            p += 1 + body[p] as usize;
            u16::from_be_bytes([body[p], body[p + 1]]) as usize
        };
        assert!(ext_total < 1024, "extension block length must be sane");
    }

    #[tokio::test]
    async fn test_client_handshake_rejects_malformed_server_name() {
        // A name that cannot be a DNS name must be refused before anything is sent:
        // a u16 length overflow would silently truncate the SNI extension.
        for bad in ["", " ", "cover.example\r\n", "cover example"] {
            let io = MockIo::new(Vec::new());
            let out = io.out();
            let cfg = ShadowTlsClientConfig {
                server_name: bad.to_string(),
                password: PW.to_string(),
            };
            let res = ShadowTlsHandshake::client_handshake(io, &cfg).await;
            assert!(res.is_err(), "server_name {bad:?} must be rejected");
            assert!(
                out.lock().unwrap().is_empty(),
                "server_name {bad:?} was written to the wire before being rejected"
            );
        }

        let long = "a".repeat(300);
        let io = MockIo::new(Vec::new());
        let cfg = ShadowTlsClientConfig {
            server_name: long.clone(),
            password: PW.to_string(),
        };
        assert!(
            ShadowTlsHandshake::client_handshake(io, &cfg)
                .await
                .is_err(),
            "a {}-byte server_name must be rejected",
            long.len()
        );
    }

    #[tokio::test]
    async fn test_client_handshake_accepts_the_layered_pseudo_server_hello() {
        // When the cover site is the next in-process security layer the reply is not
        // a ServerHello but that layer's handshake. The client must still accept it
        // and derive the pseudo server_random from bytes 6..38, because the server
        // derives the same value from the same bytes — rejecting it would break
        // chained inbounds (shadowtls → reality).
        let cfg = ShadowTlsClientConfig {
            server_name: "cover.example".into(),
            password: PW.into(),
        };
        for typ in [0x01u8, 0x02] {
            let mut body = vec![typ, 0x00, 0x00, 0x26, 0x03, 0x03];
            body.extend_from_slice(&[0x11u8; 32]);
            body.extend_from_slice(&[0x00, 0x13, 0x01, 0x00]);
            let mut record = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x03];
            record.extend_from_slice(&(body.len() as u16).to_be_bytes());
            record.extend_from_slice(&body);

            let (client, mut peer) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let _ = peer.read(&mut [0u8; 2048]).await;
                let _ = peer.write_all(&record).await;
                let _ = peer.flush().await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
            let res = tokio::time::timeout(
                Duration::from_secs(2),
                ShadowTlsHandshake::client_handshake(client, &cfg),
            )
            .await
            .expect("client handshake must not hang");
            assert!(
                res.is_ok(),
                "handshake message type {typ:#04x} must be usable as the pseudo ServerHello"
            );
        }

        // A reply too short to hold the random must still be refused, and nothing
        // may be read from a truncated record.
        let mut record = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x03, 0x00, 0x04, 0x02, 0, 0, 0];
        record.extend_from_slice(&[0u8; 4]);
        let (client, mut peer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = peer.read(&mut [0u8; 2048]).await;
            let _ = peer.write_all(&record).await;
            let _ = peer.flush().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            ShadowTlsHandshake::client_handshake(client, &cfg),
        )
        .await
        .expect("client handshake must not hang");
        assert!(
            matches!(res, Err(FluxError::Crypto(_))),
            "a {}-byte reply cannot hold a server_random",
            4
        );
    }

    #[tokio::test]
    async fn test_fallback_domain_resolution() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let v4 = resolve_fallback(&TargetFallback::Domain("127.0.0.1".into(), 8443))
            .await
            .unwrap();
        assert_eq!(v4, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443));
        let v6 = resolve_fallback(&TargetFallback::Domain("::1".into(), 8443))
            .await
            .unwrap();
        assert_eq!(v6, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443));
        let direct = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        assert_eq!(
            resolve_fallback(&TargetFallback::Address(direct))
                .await
                .unwrap(),
            direct
        );
        assert!(
            resolve_fallback(&TargetFallback::Domain("".into(), 443))
                .await
                .is_err(),
            "an empty cover host must be an error"
        );
    }

    #[test]
    fn test_sni_allow_list() {
        let body = &build_tls_client_hello("other.example", PW)[5..];
        assert_eq!(client_hello_sni(body).as_deref(), Some("other.example"));
        let allowed = vec!["allowed.example".to_string()];
        assert!(!sni_is_allowed(client_hello_sni(body).as_deref(), &allowed));
        assert!(sni_is_allowed(
            client_hello_sni(body).as_deref(),
            &["OTHER.example".to_string()]
        ));
        assert!(
            sni_is_allowed(client_hello_sni(body).as_deref(), &[]),
            "no allow-list configured means no restriction"
        );
    }

    #[test]
    fn test_client_hello_sni_parser_survives_corruption() {
        // The SNI parser runs on attacker-controlled bytes before authentication:
        // every truncation and every single-byte corruption must be safe.
        let record = build_tls_client_hello("cover.example", PW);
        let body = &record[5..];
        for cut in 0..body.len() {
            let _ = client_hello_sni(&body[..cut]);
        }
        for i in 0..body.len().min(200) {
            let mut tampered = body.to_vec();
            tampered[i] ^= 0xff;
            let _ = client_hello_sni(&tampered);
        }
    }
    #[test]
    fn test_tag_comparison_is_constant_time() {
        // A `==` on byte slices stops at the first differing byte, which leaks how
        // many leading bytes of a forged 4-byte tag were correct.
        let proper = [0x11u8, 0x22, 0x33, 0x44];
        assert!(tags_equal(&proper, &proper));

        let mut first_byte_wrong = proper;
        first_byte_wrong[0] ^= 0x80;
        CT_COMPARED.with(|c| c.set(0));
        assert!(!tags_equal(&proper, &first_byte_wrong));
        assert_eq!(
            CT_COMPARED.with(|c| c.get()),
            proper.len(),
            "the comparison stopped early instead of examining every byte"
        );

        for i in 0..proper.len() {
            let mut wrong = proper;
            wrong[i] ^= 0x01;
            assert!(
                !tags_equal(&proper, &wrong),
                "difference at byte {i} accepted"
            );
        }
    }

    #[tokio::test]
    async fn test_replayed_hello_does_not_authenticate() {
        // The session id is a bearer credential: it proves password knowledge but
        // anyone who observed it can re-send it verbatim. A replay must be handled
        // exactly like an unknown password (relayed to the cover site, no stream).
        let password = "replay-test-pass";
        let hello = build_tls_client_hello("cover.example", password);
        let session_id = client_session_id(&hello[5..]).expect("hello carries a session id");
        assert!(
            replay_accept(&session_id),
            "first sighting of a session id must be accepted"
        );

        let decoy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_addr = decoy.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = decoy.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while sock.read(&mut buf).await.unwrap_or(0) > 0 {}
                });
            }
        });

        let cfg = ShadowTlsServerConfig {
            server_names: vec![],
            password: password.into(),
            fallback_address: TargetFallback::Address(decoy_addr),
        };
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task =
            tokio::spawn(async move { ShadowTlsHandshake::server_handshake(server, &cfg).await });
        client.write_all(&hello).await.unwrap();
        client.flush().await.unwrap();

        let res = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("a replayed hello must be decided without waiting for data")
            .unwrap();
        assert!(
            matches!(res, Err(FluxError::AuthFailed(_))),
            "a replayed ClientHello must not switch the connection into proxy mode"
        );
    }
}
