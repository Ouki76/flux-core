use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use flux_types::{
    BoxedStream, FluxError, FluxResult, Outbound, PacketEndpoint, SessionMeta, TargetAddress,
};
use flux_dns::DnsResolver;
use flux_protocol::shadowsocks::{
    derive_master_key, derive_subkey, encode_ss_address, ShadowsocksCipher, ShadowsocksStream,
    SALT_LEN,
};
use flux_transport::tcp::TcpTransport;

pub struct ShadowsocksOutbound {
    tag: String,
    server_address: TargetAddress,
    master_key: [u8; 32],
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
            resolver,
            connect_timeout: Duration::from_secs(10),
        }
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
        let mut enc = ShadowsocksCipher::new(&subkey);

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
        Err(FluxError::Protocol {
            protocol: "shadowsocks-out",
            message: "Shadowsocks UDP outbound not yet configured".into(),
        })
    }
}
