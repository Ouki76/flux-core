use async_trait::async_trait;
use flux_dns::DnsResolver;
use flux_protocol::mux::{MuxClient, MuxConfig, mux_destination};
use flux_protocol::shadowsocks::{
    CipherKind, ShadowsocksCipher, ShadowsocksStream, TAG_LEN, derive_master_key_for_kind,
    derive_subkey, encode_ss_address,
};
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, StreamDialer,
    TargetAddress, UdpPacket,
};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

pub struct ShadowsocksOutbound {
    tag: String,
    password: String,
    master_key: Vec<u8>,
    cipher_kind: CipherKind,
    dialer: Option<Arc<dyn StreamDialer>>,
    server_address: TargetAddress,
    resolver: Arc<DnsResolver>,
    /// Stream multiplexer, when `multiplex.enabled` is set on the node.
    mux: Option<Arc<MuxClient>>,
}

impl ShadowsocksOutbound {
    pub fn new(
        tag: impl Into<String>,
        server_address: TargetAddress,
        password: &str,
        resolver: Arc<DnsResolver>,
        dialer: Arc<dyn StreamDialer>,
    ) -> Self {
        let cipher_kind = CipherKind::ChaCha20IetfPoly1305;
        let master_key = derive_master_key_for_kind(password, cipher_kind);
        Self {
            tag: tag.into(),
            password: password.to_string(),
            master_key,
            cipher_kind,
            dialer: Some(dialer),
            server_address,
            resolver,
            mux: None,
        }
    }

    pub fn new_datagram(
        tag: impl Into<String>,
        server_address: TargetAddress,
        password: &str,
        resolver: Arc<DnsResolver>,
    ) -> Self {
        let cipher_kind = CipherKind::ChaCha20IetfPoly1305;
        let master_key = derive_master_key_for_kind(password, cipher_kind);
        Self {
            tag: tag.into(),
            password: password.to_string(),
            master_key,
            cipher_kind,
            dialer: None,
            server_address,
            resolver,
            mux: None,
        }
    }

    pub fn with_cipher_kind(mut self, kind: CipherKind) -> Self {
        self.cipher_kind = kind;
        self.master_key = derive_master_key_for_kind(&self.password, kind);
        self
    }

    /// Enables multiplexing over a shared smux session.
    ///
    /// Requires a stream dialer (a datagram-only outbound cannot carry a muxed
    /// TCP session).
    pub fn with_mux(mut self, config: MuxConfig) -> FluxResult<Self> {
        let Some(dialer) = self.dialer.clone() else {
            return Err(FluxError::Config(
                "multiplex requires a tcp carrier (datagram-only shadowsocks outbound)".into(),
            ));
        };
        let mux_dialer = Arc::new(ShadowsocksMuxDialer {
            outbound: ShadowsocksCarrier {
                master_key: self.master_key.clone(),
                cipher_kind: self.cipher_kind,
                dialer,
            },
        });
        self.mux = Some(MuxClient::new(mux_dialer, config));
        Ok(self)
    }
}

/// The carrier part of a shadowsocks outbound, shared by the normal dial path
/// and the multiplex session path.
struct ShadowsocksCarrier {
    master_key: Vec<u8>,
    cipher_kind: CipherKind,
    dialer: Arc<dyn StreamDialer>,
}

impl ShadowsocksCarrier {
    async fn open(&self, destination: &TargetAddress) -> FluxResult<BoxedStream> {
        let mut stream = self.dialer.dial().await?;

        if let CipherKind::Ss2022(method) = self.cipher_kind {
            let key_bytes = &self.master_key[..method.key_len()];
            let ss_stream = flux_protocol::shadowsocks2022::Ss2022Protocol::client_handshake(
                stream,
                method,
                key_bytes,
                destination,
            )
            .await?;
            return Ok(Box::new(ss_stream));
        }

        // 1. Generate client salt
        let salt_len = self.cipher_kind.salt_len();
        let mut salt = vec![0u8; salt_len];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        stream.write_all(&salt).await.map_err(FluxError::Io)?;

        // 2. Derive subkey and cipher
        let subkey = derive_subkey(&self.master_key, &salt);
        let mut enc = ShadowsocksCipher::with_kind(self.cipher_kind, &subkey);

        // 3. Encrypt target address as the first payload
        let addr_bytes = encode_ss_address(destination);
        let len_buf = (addr_bytes.len() as u16).to_be_bytes();

        let enc_len = enc.encrypt(&len_buf)?;
        let enc_addr = enc.encrypt(&addr_bytes)?;

        stream.write_all(&enc_len).await.map_err(FluxError::Io)?;
        stream.write_all(&enc_addr).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        Ok(Box::new(ShadowsocksStream::new(
            stream,
            enc,
            None,
            &self.master_key,
        )))
    }
}

/// Opens the physical carrier for a multiplexed session.
struct ShadowsocksMuxDialer {
    outbound: ShadowsocksCarrier,
}

#[async_trait]
impl StreamDialer for ShadowsocksMuxDialer {
    async fn dial(&self) -> FluxResult<BoxedStream> {
        self.outbound.open(&mux_destination()).await
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &'static str {
        "shadowsocks"
    }

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        if let Some(mux) = &self.mux {
            return mux.dial_stream(&meta.destination).await;
        }
        let dialer = self.dialer.as_ref().ok_or_else(|| FluxError::Protocol {
            protocol: "shadowsocks",
            message: "datagram-only outbound does not support stream dialing".into(),
        })?;
        let mut stream = dialer.dial().await?;

        if let CipherKind::Ss2022(method) = self.cipher_kind {
            let key_bytes = &self.master_key[..method.key_len()];
            let ss_stream = flux_protocol::shadowsocks2022::Ss2022Protocol::client_handshake(
                stream,
                method,
                key_bytes,
                &meta.destination,
            )
            .await?;
            return Ok(Box::new(ss_stream));
        }

        // 1. Generate client salt
        let salt_len = self.cipher_kind.salt_len();
        let mut salt = vec![0u8; salt_len];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        stream.write_all(&salt).await.map_err(FluxError::Io)?;

        // 2. Derive subkey and cipher
        let subkey = derive_subkey(&self.master_key, &salt);
        let mut enc = ShadowsocksCipher::with_kind(self.cipher_kind, &subkey);

        // 3. Encrypt target address as the first payload
        let addr_bytes = encode_ss_address(&meta.destination);
        let len_buf = (addr_bytes.len() as u16).to_be_bytes();

        let enc_len = enc.encrypt(&len_buf)?;
        let enc_addr = enc.encrypt(&addr_bytes)?;

        stream.write_all(&enc_len).await.map_err(FluxError::Io)?;
        stream.write_all(&enc_addr).await.map_err(FluxError::Io)?;
        stream.flush().await.map_err(FluxError::Io)?;

        let ss_stream = ShadowsocksStream::new(stream, enc, None, &self.master_key);
        Ok(Box::new(ss_stream))
    }

    async fn dial_packet(&self, meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
        if let Some(mux) = &self.mux {
            return mux.dial_packet(&meta.destination).await;
        }
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let is_v6 = server_addr.is_ipv6();
        let udp_socket = if is_v6 {
            match UdpSocket::bind("[::]:0").await {
                Ok(s) => s,
                Err(_) => UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?,
            }
        } else {
            UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?
        };

        let inner = match self.cipher_kind {
            CipherKind::Ss2022(method) => {
                let psk = &self.master_key[..method.key_len()];
                let cipher =
                    flux_protocol::shadowsocks2022::Ss2022UdpPacketCipher::new(method, psk);
                ShadowsocksPacketEndpointInner::Ss2022(Arc::new(cipher))
            }
            legacy_kind => ShadowsocksPacketEndpointInner::Legacy {
                master_key: self.master_key.clone(),
                cipher_kind: legacy_kind,
            },
        };

        Ok(Box::new(ShadowsocksPacketEndpoint {
            udp_socket: Arc::new(udp_socket),
            server_addr,
            inner,
            salt_cipher: parking_lot::Mutex::new(None),
        }))
    }
}

enum ShadowsocksPacketEndpointInner {
    Legacy {
        master_key: Vec<u8>,
        cipher_kind: CipherKind,
    },
    Ss2022(Arc<flux_protocol::shadowsocks2022::Ss2022UdpPacketCipher>),
}

pub struct ShadowsocksPacketEndpoint {
    udp_socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    inner: ShadowsocksPacketEndpointInner,
    /// One-entry cache of the receive cipher for the peer's current salt.
    salt_cipher: parking_lot::Mutex<Option<(Vec<u8>, ShadowsocksCipher)>>,
}

#[async_trait]
impl PacketEndpoint for ShadowsocksPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let out = match &self.inner {
            ShadowsocksPacketEndpointInner::Ss2022(cipher) => {
                cipher.encrypt_packet(&packet.destination, &packet.payload)?
            }
            ShadowsocksPacketEndpointInner::Legacy {
                master_key,
                cipher_kind,
            } => {
                let salt_len = cipher_kind.salt_len();
                let mut salt = vec![0u8; salt_len];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                let subkey = derive_subkey(master_key, &salt);
                let mut cipher = ShadowsocksCipher::with_kind(*cipher_kind, &subkey);

                // Build `salt || addr || payload` in one buffer and seal the
                // address+payload region in place: the previous shape allocated a
                // plaintext Vec, a ciphertext Vec and then copied both, i.e. three
                // allocations and two copies per datagram.
                let addr_bytes = encode_ss_address(&packet.destination);
                let mut out = Vec::with_capacity(
                    salt_len + addr_bytes.len() + packet.payload.len() + TAG_LEN,
                );
                out.extend_from_slice(&salt);
                out.extend_from_slice(&addr_bytes);
                out.extend_from_slice(&packet.payload);
                cipher.encrypt_tail(&mut out, salt_len)?;
                out
            }
        };

        self.udp_socket
            .send_to(&out, self.server_addr)
            .await
            .map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        // A single malformed datagram from the network must not be fatal: the
        // caller drives exactly one reply pump for this endpoint, and returning
        // `Err` there would tear the pump down and silently kill all further
        // UDP replies for this outbound. Log and keep reading instead.
        loop {
            let mut guard = flux_common::BufferPool::packet_pool().acquire_guard();
            let (len, from) = self
                .udp_socket
                .recv_from(&mut guard)
                .await
                .map_err(FluxError::Io)?;

            match self.decode_datagram(&guard[..len], from).await {
                Ok(pkt) => return Ok(pkt),
                Err(e) => {
                    tracing::debug!(
                        "shadowsocks UDP: dropping undecodable datagram from {} ({} bytes): {}",
                        from,
                        len,
                        e
                    );
                    continue;
                }
            }
        }
    }
}

impl ShadowsocksPacketEndpoint {
    /// Decodes one received datagram into a `UdpPacket`.
    async fn decode_datagram(
        &self,
        buf: &[u8],
        from: std::net::SocketAddr,
    ) -> FluxResult<UdpPacket> {
        let len = buf.len();
        let guard = buf;
        match &self.inner {
            ShadowsocksPacketEndpointInner::Ss2022(cipher) => {
                let (target, payload) = cipher.decrypt_packet(&guard[..len]).await?;
                Ok(UdpPacket::new(payload, TargetAddress::Ip(from), target))
            }
            ShadowsocksPacketEndpointInner::Legacy {
                master_key,
                cipher_kind,
            } => {
                let salt_len = cipher_kind.salt_len();
                if len < salt_len + TAG_LEN {
                    return Err(FluxError::Protocol {
                        protocol: "shadowsocks-udp",
                        message: "received packet too short".into(),
                    });
                }

                let salt = &guard[..salt_len];
                // Peers reuse one salt for a session, so cache the derived cipher:
                // HKDF-SHA1 plus the AES key schedule otherwise run per datagram.
                // The guard is scoped so it is released before the `await` below —
                // a `parking_lot` guard held across an await is not `Send`.
                let plain = {
                    let mut cache = self.salt_cipher.lock();
                    if cache.as_ref().map(|(s, _)| s.as_slice()) != Some(salt) {
                        let subkey = derive_subkey(master_key, salt);
                        let cipher = ShadowsocksCipher::with_kind(*cipher_kind, &subkey);
                        *cache = Some((salt.to_vec(), cipher));
                    }
                    let cipher = &mut cache.as_mut().expect("just populated").1;
                    cipher.decrypt(&guard[salt_len..len])?
                };
                if plain.is_empty() {
                    return Err(FluxError::Protocol {
                        protocol: "shadowsocks-udp",
                        message: "empty payload after decrypt".into(),
                    });
                }

                let atyp = plain[0];
                let mut cursor = std::io::Cursor::new(&plain[1..]);
                let target =
                    flux_protocol::socks5::Socks5Handshake::read_address(&mut cursor, atyp).await?;
                let pos = 1 + cursor.position() as usize;
                if pos > plain.len() {
                    return Err(FluxError::Protocol {
                        protocol: "shadowsocks-udp",
                        message: "address header overruns payload".into(),
                    });
                }
                let payload = bytes::Bytes::copy_from_slice(&plain[pos..]);

                Ok(UdpPacket::new(payload, TargetAddress::Ip(from), target))
            }
        }
    }
}
