use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::rngs::OsRng;
use flux_types::{FluxError, FluxResult};

pub const REALITY_INFO: &[u8] = b"REALITY";

#[derive(Clone, Debug)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RealityServerConfig {
    pub server_names: Vec<String>,
    pub private_key: [u8; 32],
    pub short_ids: Vec<Vec<u8>>,
}

pub struct RealityHandshake;

impl RealityHandshake {
    /// Client-side: perform REALITY authentication over a stream.
    /// Sends ephemeral public key + encrypted short_id auth block.
    pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        cfg: &RealityClientConfig,
    ) -> FluxResult<ChaCha20Poly1305> {
        let server_pub = X25519PublicKey::from(cfg.public_key);
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pub = X25519PublicKey::from(&client_secret);

        let shared_secret = client_secret.diffie_hellman(&server_pub);

        // Derive AEAD key using HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(client_pub.as_bytes()), shared_secret.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(REALITY_INFO, &mut okm).map_err(|_| {
            FluxError::Crypto("HKDF expansion failed in Reality".into())
        })?;

        let cipher = ChaCha20Poly1305::new_from_slice(&okm).map_err(|e| {
            FluxError::Crypto(format!("failed to init cipher: {}", e))
        })?;

        // Encrypt auth block: short_id (variable len)
        let nonce = Nonce::from([0u8; 12]);
        let ciphertext = cipher.encrypt(&nonce, cfg.short_id.as_slice()).map_err(|e| {
            FluxError::Crypto(format!("failed to encrypt reality auth: {}", e))
        })?;

        // Frame: [client_pub (32 bytes)] + [auth_len (2 bytes)] + [ciphertext]
        let mut frame = Vec::with_capacity(32 + 2 + ciphertext.len());
        frame.extend_from_slice(client_pub.as_bytes());
        frame.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        frame.extend_from_slice(&ciphertext);

        stream.write_all(&frame).await?;
        stream.flush().await?;

        // Read server acknowledgment (16 bytes auth verification)
        let mut server_ack = [0u8; 16];
        stream.read_exact(&mut server_ack).await.map_err(|e| {
            FluxError::Crypto(format!("failed to read reality server ack: {}", e))
        })?;

        Ok(cipher)
    }

    /// Server-side: authenticate incoming REALITY client.
    pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        cfg: &RealityServerConfig,
    ) -> FluxResult<ChaCha20Poly1305> {
        let server_secret = StaticSecret::from(cfg.private_key);

        let mut client_pub_bytes = [0u8; 32];
        stream.read_exact(&mut client_pub_bytes).await.map_err(|e| {
            FluxError::Crypto(format!("failed to read client public key: {}", e))
        })?;

        let client_pub = X25519PublicKey::from(client_pub_bytes);
        let shared_secret = server_secret.diffie_hellman(&client_pub);

        let hk = Hkdf::<Sha256>::new(Some(client_pub.as_bytes()), shared_secret.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(REALITY_INFO, &mut okm).map_err(|_| {
            FluxError::Crypto("HKDF expansion failed in Reality server".into())
        })?;

        let cipher = ChaCha20Poly1305::new_from_slice(&okm).map_err(|e| {
            FluxError::Crypto(format!("failed to init cipher: {}", e))
        })?;

        let mut auth_len_bytes = [0u8; 2];
        stream.read_exact(&mut auth_len_bytes).await.map_err(|e| {
            FluxError::Crypto(format!("failed to read reality auth len: {}", e))
        })?;
        let auth_len = u16::from_be_bytes(auth_len_bytes) as usize;

        let mut ciphertext = vec![0u8; auth_len];
        stream.read_exact(&mut ciphertext).await.map_err(|e| {
            FluxError::Crypto(format!("failed to read reality ciphertext: {}", e))
        })?;

        let nonce = Nonce::from([0u8; 12]);
        let decrypted_short_id = cipher.decrypt(&nonce, ciphertext.as_slice()).map_err(|_| {
            FluxError::AuthFailed("reality auth tag decryption failed".into())
        })?;

        // Check if decrypted short_id is permitted
        if !cfg.short_ids.is_empty() && !cfg.short_ids.iter().any(|id| id == &decrypted_short_id) {
            return Err(FluxError::AuthFailed("invalid reality short_id".into()));
        }

        // Send server ack
        stream.write_all(b"REALITY_ACK_OK!!").await?;
        stream.flush().await?;

        Ok(cipher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reality_handshake() {
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = X25519PublicKey::from(&server_secret);

        let short_id = vec![0x12, 0x34, 0x56, 0x78];

        let client_cfg = RealityClientConfig {
            server_name: "gateway.icloud.com".into(),
            public_key: *server_public.as_bytes(),
            short_id: short_id.clone(),
        };

        let server_cfg = RealityServerConfig {
            server_names: vec!["gateway.icloud.com".into()],
            private_key: server_secret.to_bytes(),
            short_ids: vec![short_id],
        };

        let (mut client_stream, mut server_stream) = tokio::io::duplex(1024);

        let srv = tokio::spawn(async move {
            RealityHandshake::server_handshake(&mut server_stream, &server_cfg)
                .await
                .unwrap();
        });

        let cli = tokio::spawn(async move {
            RealityHandshake::client_handshake(&mut client_stream, &client_cfg)
                .await
                .unwrap();
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }
}
