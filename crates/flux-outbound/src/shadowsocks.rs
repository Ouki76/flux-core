use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
    UdpPacket,
};
use flux_dns::DnsResolver;
use flux_protocol::shadowsocks::{
    derive_master_key, derive_subkey, encode_ss_address, CipherKind, ShadowsocksCipher,
    ShadowsocksStream, SALT_LEN, TAG_LEN,
};
use flux_transport::tcp::TcpTransport;

pub struct ShadowsocksOutbound {
    tag: String,
    server_address: TargetAddress,
    master_key: [u8; 32],
    cipher_kind: CipherKind,
    resolver: Arc<DnsResolver>,
    connect_timeout: Duration,
}

impl ShadowsocksOutbound {
    pub fn new(
        tag: impl Into<String>,
        server_address: TargetAddress,
        password: &str,
        resolver: Arc<DnsResolver>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address,
            master_key: derive_master_key(password),
            cipher_kind: CipherKind::ChaCha20IetfPoly1305,
            resolver,
            connect_timeout: Duration::from_secs(10),
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

    async fn dial_stream(&self, meta: &SessionMeta) -> FluxResult<BoxedStream> {
        let server_addr = self.resolver.resolve(&self.server_address).await?;
        let mut stream = TcpTransport::connect(server_addr, self.connect_timeout).await?;

        // 1. Generate client salt
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
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
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await.map_err(FluxError::Io)?;

        Ok(Box::new(ShadowsocksPacketEndpoint {
            udp_socket: Arc::new(udp_socket),
            server_addr,
            master_key: self.master_key,
            cipher_kind: self.cipher_kind,
        }))
    }
}

pub struct ShadowsocksPacketEndpoint {
    udp_socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    master_key: [u8; 32],
    cipher_kind: CipherKind,
}

#[async_trait]
impl PacketEndpoint for ShadowsocksPacketEndpoint {
    async fn send_packet(&self, packet: UdpPacket) -> FluxResult<()> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let subkey = derive_subkey(&self.master_key, &salt);
        let mut cipher = ShadowsocksCipher::with_kind(self.cipher_kind, &subkey);

        let addr_bytes = encode_ss_address(&packet.destination);
        let mut plain = Vec::with_capacity(addr_bytes.len() + packet.payload.len());
        plain.extend_from_slice(&addr_bytes);
        plain.extend_from_slice(&packet.payload);

        let ciphertext = cipher.encrypt(&plain)?;

        let mut out = Vec::with_capacity(SALT_LEN + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&ciphertext);

        self.udp_socket
            .send_to(&out, self.server_addr)
            .await
            .map_err(FluxError::Io)?;
        Ok(())
    }

    async fn recv_packet(&self) -> FluxResult<UdpPacket> {
        let mut buf = vec![0u8; 65535];
        let (len, from) = self.udp_socket.recv_from(&mut buf).await.map_err(FluxError::Io)?;
        if len < SALT_LEN + TAG_LEN {
            return Err(FluxError::Protocol {
                protocol: "shadowsocks-udp",
                message: "received packet too short".into(),
            });
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[..SALT_LEN]);
        let subkey = derive_subkey(&self.master_key, &salt);
        let mut cipher = ShadowsocksCipher::with_kind(self.cipher_kind, &subkey);

        let plain = cipher.decrypt(&buf[SALT_LEN..len])?;
        if plain.is_empty() {
            return Err(FluxError::Protocol {
                protocol: "shadowsocks-udp",
                message: "empty payload after decrypt".into(),
            });
        }

        let atyp = plain[0];
        let mut cursor = std::io::Cursor::new(&plain[1..]);
        let target = flux_protocol::socks5::Socks5Handshake::read_address(&mut cursor, atyp).await?;
        let pos = 1 + cursor.position() as usize;
        let payload = bytes::Bytes::copy_from_slice(&plain[pos..]);

        Ok(UdpPacket::new(
            payload,
            TargetAddress::Ip(from),
            target,
        ))
    }
}
