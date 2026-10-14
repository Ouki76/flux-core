//! Salamander obfuscation for QUIC transports (Hysteria 2 `obfs: salamander`).
//!
//! Wraps quinn's UDP socket at the runtime level: every outgoing datagram gets
//! a random 16-byte salt prefix and XOR keystream (blake3 keyed by the
//! password), every incoming datagram is deobfuscated before quinn sees it.
//! Packets that fail deobfuscation are silently dropped.

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
    key: [u8; 32],
}

impl SalamanderRuntime {
    pub fn new(password: &str) -> Arc<Self> {
        Arc::new(Self {
            key: *blake3::hash(password.as_bytes()).as_bytes(),
        })
    }
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
            key: self.key,
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
    key: [u8; 32],
}

impl ObfuscatedSocket {
    fn obfuscate(&self, plaintext: &[u8]) -> Vec<u8> {
        use rand::RngCore;
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(&salt);
        let mut xof = hasher.finalize_xof();

        let mut out = Vec::with_capacity(16 + plaintext.len());
        out.extend_from_slice(&salt);
        let mut keystream = vec![0u8; plaintext.len()];
        xof.fill(&mut keystream);
        out.extend(plaintext.iter().zip(keystream.iter()).map(|(p, k)| p ^ k));
        out
    }

    /// Deobfuscates `buf[..len]` in place, returning the plaintext length, or
    /// `None` when the datagram is not Salamander-obfuscated.
    fn deobfuscate_in_place(&self, buf: &mut [u8], len: usize) -> Option<usize> {
        if len < 16 {
            return None;
        }
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(&buf[..16]);
        let mut xof = hasher.finalize_xof();

        let plain_len = len - 16;
        let mut keystream = vec![0u8; plain_len];
        xof.fill(&mut keystream);
        for i in 0..plain_len {
            buf[i] = buf[16 + i] ^ keystream[i];
        }
        Some(plain_len)
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
                    // max_receive_segments == 1: each datagram occupies its own
                    // buffer starting at offset 0.
                    let mut valid = 0;
                    for i in 0..count {
                        let len = meta[i].len.min(bufs[i].len());
                        if let Some(plain_len) = self.deobfuscate_in_place(&mut bufs[i][..], len) {
                            // Compact valid datagrams to the front.
                            if valid != i {
                                let (head, tail) = bufs.split_at_mut(i);
                                head[valid][..plain_len].copy_from_slice(&tail[0][..plain_len]);
                                meta[valid] = meta[i];
                            }
                            meta[valid].len = plain_len;
                            meta[valid].stride = plain_len;
                            valid += 1;
                        }
                        // Undecodable datagrams are dropped silently.
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

    #[tokio::test]
    async fn test_salamander_socket_roundtrip() {
        let sock = ObfuscatedSocket {
            inner: TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            key: *blake3::hash(b"secret").as_bytes(),
        };
        let plain = b"QUIC handshake bytes".as_slice();
        let obf = sock.obfuscate(plain);
        assert_eq!(obf.len(), plain.len() + 16);
        assert_ne!(&obf[..16], &obf[16..32.min(obf.len())]);

        let mut buf = obf.clone();
        let blen = buf.len();
        let n = sock.deobfuscate_in_place(&mut buf, blen).unwrap();
        assert_eq!(&buf[..n], plain);

        // Wrong key: produces garbage, never panics.
        let wrong = ObfuscatedSocket {
            inner: TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            key: *blake3::hash(b"wrong").as_bytes(),
        };
        let mut buf2 = obf;
        let blen2 = buf2.len();
        let n2 = wrong.deobfuscate_in_place(&mut buf2, blen2).unwrap();
        assert_ne!(&buf2[..n2], plain);

        // Short packet is rejected.
        let mut short = [0u8; 10];
        assert!(sock.deobfuscate_in_place(&mut short, 10).is_none());
    }
}
