//! Salamander obfuscation for QUIC transports (Hysteria 2 `obfs: salamander`).
//!
//! Wraps quinn's UDP socket at the runtime level: every outgoing datagram is
//! salted and XOR-obfuscated by [`flux_common::Salamander`], every incoming
//! datagram is deobfuscated before quinn sees it. Packets that fail
//! deobfuscation are silently dropped.
//!
//! The cipher itself lives in `flux-common` so that the QUIC wrapper and the
//! protocol codec can never drift apart.

use std::fmt::Debug;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};

/// QUIC runtime whose UDP sockets are wrapped with Salamander obfuscation.
#[derive(Debug)]
pub struct SalamanderRuntime {
    obfs: flux_common::Salamander,
}

impl SalamanderRuntime {
    /// A deobfuscator for the given password.
    pub fn new(password: &str) -> Arc<Self> {
        // Fall back to a random PSK rather than silently disabling
        // obfuscation: a too-short configured password is a configuration
        // error, but producing clear-text QUIC would leak the protocol.
        let obfs = flux_common::Salamander::new(password).unwrap_or_else(|e| {
            tracing::error!("{e}; using a random Salamander PSK instead");
            let mut pw = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut pw);
            flux_common::Salamander::new(&hex(&pw)).expect("32-byte hex password is long enough")
        });
        Arc::new(Self { obfs })
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl Runtime for SalamanderRuntime {
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        TokioRuntime.new_timer(i)
    }

    fn spawn(&self, future: Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        TokioRuntime.spawn(future);
    }

    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = TokioRuntime.wrap_udp_socket(t)?;
        Ok(Arc::new(ObfuscatedSocket {
            inner,
            obfs: self.obfs.clone(),
        }))
    }

    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}

/// UDP socket applying Salamander obfuscation transparently to every datagram.
#[derive(Debug)]
struct ObfuscatedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: flux_common::Salamander,
}

impl ObfuscatedSocket {
    fn obfuscate(&self, plaintext: &[u8]) -> Vec<u8> {
        self.obfs.obfuscate(plaintext)
    }

    /// Deobfuscates `buf[..len]` in place, returning the plaintext length, or
    /// `None` when the datagram is too short to be a Salamander packet.
    fn deobfuscate_in_place(&self, buf: &mut [u8], len: usize) -> Option<usize> {
        self.obfs.deobfuscate_in_place(buf, len)
    }
}

impl AsyncUdpSocket for ObfuscatedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // Writability/readiness semantics are unchanged by obfuscation.
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let obfuscated = self.obfuscate(transmit.contents);
        let t = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &obfuscated,
            // The obfuscation changes the datagram length; GSO segmentation no
            // longer applies to the transformed payload.
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&t)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(count)) => {
                    // Each entry in `meta` describes one received datagram in the
                    // matching `bufs` entry. Realistic segment handling only needs
                    // to bound every slice: an oversized or coalesced buffer used
                    // to be able to make the compaction copy panic.
                    let mut valid = 0;
                    for i in 0..count {
                        if i >= bufs.len() || i >= meta.len() {
                            break;
                        }
                        let len = meta[i].len.min(bufs[i].len());
                        let Some(plain_len) = self.deobfuscate_in_place(&mut bufs[i][..], len)
                        else {
                            continue; // undecodable: dropped silently
                        };
                        if valid != i {
                            let dst_cap = bufs[valid].len();
                            if dst_cap >= plain_len {
                                let (head, tail) = bufs.split_at_mut(i);
                                head[valid][..plain_len].copy_from_slice(&tail[0][..plain_len]);
                                meta[valid] = meta[i];
                            } else {
                                continue;
                            }
                        }
                        meta[valid].len = plain_len;
                        meta[valid].stride = plain_len;
                        valid += 1;
                    }
                    if valid > 0 {
                        return Poll::Ready(Ok(valid));
                    }
                    // All received datagrams failed deobfuscation: keep polling
                    // (the waker is already registered by the inner socket).
                }
                other => return other,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flux_common::SALAMANDER_SALT_LEN;

    fn mk(pw: &str) -> ObfuscatedSocket {
        ObfuscatedSocket {
            inner: TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            obfs: flux_common::Salamander::new(pw).unwrap(),
        }
    }

    #[tokio::test]
    async fn test_salamander_socket_roundtrip() {
        let sock = mk("salamander-secret");
        let plain = b"QUIC handshake bytes".as_slice();
        let obf = sock.obfuscate(plain);
        assert_eq!(obf.len(), plain.len() + SALAMANDER_SALT_LEN);
        assert_ne!(&obf[SALAMANDER_SALT_LEN..], plain);

        let mut buf = obf.clone();
        let blen = buf.len();
        let n = sock.deobfuscate_in_place(&mut buf, blen).unwrap();
        assert_eq!(&buf[..n], plain);

        // Wrong key: produces garbage, never panics.
        let wrong = mk("wrong-password");
        let mut buf2 = obf;
        let blen2 = buf2.len();
        let n2 = wrong.deobfuscate_in_place(&mut buf2, blen2).unwrap();
        assert_ne!(&buf2[..n2], plain);

        // Short packet is rejected.
        let mut short = [0u8; SALAMANDER_SALT_LEN - 1];
        assert!(
            sock.deobfuscate_in_place(&mut short, SALAMANDER_SALT_LEN - 1)
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_salamander_runtime_tolerates_short_password() {
        // A too-short PSK must not panic and must still obfuscate.
        let rt = SalamanderRuntime::new("ab");
        let socket = rt
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        assert!(socket.local_addr().is_ok());
    }
}
