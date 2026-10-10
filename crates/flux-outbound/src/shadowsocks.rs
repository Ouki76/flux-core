use async_trait::async_trait;
use flux_dns::DnsResolver;
use flux_protocol::shadowsocks::{
    CipherKind, SALT_LEN, ShadowsocksCipher, ShadowsocksStream, TAG_LEN, derive_master_key,
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
    master_key: [u8; 32],
    cipher_kind: CipherKind,
    dialer: Option<Arc<dyn StreamDialer>>,
    server_address: TargetAddress,
    resolver: Arc<DnsResolver>,
}

impl ShadowsocksOutbound {
    pub fn new(
        tag: impl Into<String>,
        server_address: TargetAddress,
        password: &str,
        resolver: Arc<DnsResolver>,
        dialer: Arc<dyn StreamDialer>,
    ) -> Self {
        Self {
            tag: tag.into(),
            master_key: derive_master_key(password),
            cipher_kind: CipherKind::ChaCha20IetfPoly1305,
            dialer: Some(dialer),
            server_address,
            resolver,
        }
    }

    pub fn new_datagram(
        tag: impl Into<String>,
        server_address: TargetAddress,
        password: &str,
        resolver: Arc<DnsResolver>,
    ) -> Self {
        Self {
            tag: tag.into(),
            master_key: derive_master_key(password),
            cipher_kind: CipherKind::ChaCha20IetfPoly1305,
            dialer: None,
            server_address,
            resolver,
        }
    }

    pub fn with_cipher_kind(mut self, kind: CipherKind) -> Self {
        self.cipher_kind = kind;
        self
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
        let mut salt = [0u8; SALT_LEN];
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

        let ss_stream = ShadowsocksStream::new(stream, enc, None, self.master_key);
        Ok(Box::new(ss_stream))
    }

    async fn dial_packet(&self, _meta: &SessionMeta) -> FluxResult<Box<dyn PacketEndpoint>> {
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
                master_key: self.master_key,
                cipher_kind: legacy_kind,
            },
        };

        Ok(Box::new(ShadowsocksPacketEndpoint {
            udp_socket: Arc::new(udp_socket),
            server_addr,
            inner,
        }))
    }
}

enum ShadowsocksPacketEndpointInner {
    Legacy {
        master_key: [u8; 32],
        cipher_kind: CipherKind,
    },
    Ss2022(Arc<flux_protocol::shadowsocks2022::Ss2022UdpPacketCipher>),
}

pub struct ShadowsocksPacketEndpoint {
    udp_socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    inner: ShadowsocksPacketEndpointInner,
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
                let mut salt = [0u8; SALT_LEN];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                let subkey = derive_subkey(master_key, &salt);
                let mut cipher = ShadowsocksCipher::with_kind(*cipher_kind, &subkey);

                let addr_bytes = encode_ss_address(&packet.destination);
                let mut plain = Vec::with_capacity(addr_bytes.len() + packet.payload.len());
                plain.extend_from_slice(&addr_bytes);
                plain.extend_from_slice(&packet.payload);

                let ciphertext = cipher.encrypt(&plain)?;

                let mut out = Vec::with_capacity(SALT_LEN + ciphertext.len());
                out.extend_from_slice(&salt);
                out.extend_from_slice(&ciphertext);
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
        let mut guard = flux_common::BufferPool::packet_pool().acquire_guard();
        let (len, from) = self
            .udp_socket
            .recv_from(&mut guard)
            .await
            .map_err(FluxError::Io)?;

        match &self.inner {
            ShadowsocksPacketEndpointInner::Ss2022(cipher) => {
                let (target, payload) = cipher.decrypt_packet(&guard[..len]).await?;
                Ok(UdpPacket::new(payload, TargetAddress::Ip(from), target))
            }
            ShadowsocksPacketEndpointInner::Legacy {
                master_key,
                cipher_kind,
            } => {
                if len < SALT_LEN + TAG_LEN {
                    return Err(FluxError::Protocol {
                        protocol: "shadowsocks-udp",
                        message: "received packet too short".into(),
                    });
                }

                let mut salt = [0u8; SALT_LEN];
                salt.copy_from_slice(&guard[..SALT_LEN]);
                let subkey = derive_subkey(master_key, &salt);
                let mut cipher = ShadowsocksCipher::with_kind(*cipher_kind, &subkey);

                let plain = cipher.decrypt(&guard[SALT_LEN..len])?;
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
                let payload = bytes::Bytes::copy_from_slice(&plain[pos..]);

                Ok(UdpPacket::new(payload, TargetAddress::Ip(from), target))
            }
        }
    }
}
