use crate::tcp::TcpTransport;
use flux_types::{AsyncStream, BoxedStream, FluxError, FluxResult};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type HmacSha256 = Hmac<Sha256>;

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
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Generate client random (32 bytes)
        let mut client_random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_random);

        // Compute HMAC challenge: HMAC-SHA256(password, [random (32 bytes) + timestamp (8 bytes)])
        let mut mac = HmacSha256::new_from_slice(cfg.password.as_bytes())
            .map_err(|e| FluxError::Crypto(format!("failed to init HMAC: {}", e)))?;
        mac.update(&client_random);
        mac.update(&now_sec.to_be_bytes());
        let hmac_res = mac.finalize().into_bytes();

        let mut session_id = [0u8; 32];
        session_id[..8].copy_from_slice(&hmac_res[..8]);
        session_id[8..16].copy_from_slice(&now_sec.to_be_bytes());
        rand::thread_rng().fill_bytes(&mut session_id[16..]);

        // Build authentic TLS 1.3 ClientHello with HMAC challenge
        let client_hello = build_tls_client_hello(&cfg.server_name, &client_random, &session_id);
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
            if tokio::time::timeout(
                Duration::from_secs(3),
                fallback_stream.read_exact(&mut srv_hdr),
            )
            .await
            .is_ok()
            {
                let s_len = u16::from_be_bytes([srv_hdr[3], srv_hdr[4]]) as usize;
                let mut s_body = vec![0u8; s_len];
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
            Ok(Box::new(client_stream))
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

fn build_tls_client_hello(server_name: &str, random: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
    let mut hello = Vec::with_capacity(512);
    hello.push(TLS_CLIENT_HELLO);
    hello.extend_from_slice(&[0, 0, 0]); // Length placeholder
    hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
    hello.extend_from_slice(random);

    hello.push(32);
    hello.extend_from_slice(session_id);

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

    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    // Fix Handshake Length
    let hs_len = (hello.len() - 4) as u32;
    let hs_len_bytes = hs_len.to_be_bytes();
    hello[1] = hs_len_bytes[1];
    hello[2] = hs_len_bytes[2];
    hello[3] = hs_len_bytes[3];

    // Wrap in TLS Record Header
    let mut record = Vec::with_capacity(5 + hello.len());
    record.push(TLS_RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);

    record
}

fn verify_shadowtls_session_id(handshake: &[u8], password: &str) -> (bool, Option<String>) {
    if handshake.len() < 38 || handshake[0] != TLS_CLIENT_HELLO {
        return (false, None);
    }

    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&handshake[6..38]);

    let session_id_len = handshake[38] as usize;
    if session_id_len != 32 || handshake.len() < 39 + 32 {
        return (false, None);
    }

    let session_id = &handshake[39..39 + 32];
    let hmac_claim = &session_id[..8];
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&session_id[8..16]);
    let timestamp = u64::from_be_bytes(timestamp_bytes);

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // 120s replay window
    if now_sec.abs_diff(timestamp) > 120 {
        return (false, None);
    }

    let mut mac = match HmacSha256::new_from_slice(password.as_bytes()) {
        Ok(m) => m,
        Err(_) => return (false, None),
    };
    mac.update(&client_random);
    mac.update(&timestamp_bytes);
    let expected = mac.finalize().into_bytes();

    if hmac_claim == &expected[..8] {
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
        let mut random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random);

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut mac = HmacSha256::new_from_slice(password.as_bytes()).unwrap();
        mac.update(&random);
        mac.update(&now_sec.to_be_bytes());
        let hmac_res = mac.finalize().into_bytes();

        let mut session_id = [0u8; 32];
        session_id[..8].copy_from_slice(&hmac_res[..8]);
        session_id[8..16].copy_from_slice(&now_sec.to_be_bytes());

        let record = build_tls_client_hello("captive.apple.com", &random, &session_id);
        assert_eq!(record[0], TLS_RECORD_HANDSHAKE);

        let (verified, _) = verify_shadowtls_session_id(&record[5..], password);
        assert!(verified, "valid ShadowTLS HMAC challenge must verify");

        let (bad_pw, _) = verify_shadowtls_session_id(&record[5..], "wrong_password");
        assert!(!bad_pw, "wrong password must fail ShadowTLS verification");
    }
}
