use flux_types::{FluxError, FluxResult, TargetAddress};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::time::sleep;

pub const HYSTERIA2_VERSION: u8 = 2;
pub const HYSTERIA2_CMD_TCP: u8 = 1;
pub const HYSTERIA2_CMD_UDP: u8 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hysteria2Config {
    pub server: String,
    pub ports: Vec<u16>,
    pub password: String,
    pub up_mbps: u64,
    pub down_mbps: u64,
    #[serde(default = "default_hop_interval_secs")]
    pub hop_interval_secs: u64,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub obfs: Option<String>,
    /// ALPN protocols for the QUIC TLS handshake (default: ["h3", "hysteria2"]).
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub h3: bool,
}

#[derive(Clone, Debug)]
pub struct SalamanderObfs {
    key: [u8; 32],
}

impl SalamanderObfs {
    pub fn new(password: &str) -> Self {
        let key = blake3::hash(password.as_bytes());
        Self {
            key: *key.as_bytes(),
        }
    }

    pub fn obfuscate(&self, packet: &[u8]) -> Vec<u8> {
        use rand::RngCore;
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(&salt);
        let mut xof = hasher.finalize_xof();

        let mut out = Vec::with_capacity(16 + packet.len());
        out.extend_from_slice(&salt);

        let mut keystream = vec![0u8; packet.len()];
        xof.fill(&mut keystream);

        for (p, k) in packet.iter().zip(keystream.iter()) {
            out.push(p ^ k);
        }
        out
    }

    pub fn deobfuscate(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 16 {
            return None;
        }
        let salt = &data[..16];
        let payload = &data[16..];

        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(salt);
        let mut xof = hasher.finalize_xof();

        let mut keystream = vec![0u8; payload.len()];
        xof.fill(&mut keystream);

        let mut out = Vec::with_capacity(payload.len());
        for (p, k) in payload.iter().zip(keystream.iter()) {
            out.push(p ^ k);
        }
        Some(out)
    }
}

fn default_hop_interval_secs() -> u64 {
    30
}

/// Brutal Congestion Control fixed-rate pacer.
/// Enforces aggressive line-rate pacing regardless of packet loss.
pub struct BrutalPacer {
    rate_bps: u64,
    last_send: Instant,
    accumulated_tokens: f64,
}

impl BrutalPacer {
    pub fn new(mbps: u64) -> Self {
        let rate_bps = (mbps.max(1)) * 1_000_000;
        Self {
            rate_bps,
            last_send: Instant::now(),
            accumulated_tokens: 0.0,
        }
    }

    /// Paces the transmission of `bytes_to_send` bytes, sleeping if burst limit is reached.
    pub async fn pace(&mut self, bytes_to_send: usize) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_send).as_secs_f64();
        self.last_send = now;

        let tokens_per_sec = (self.rate_bps / 8) as f64;
        self.accumulated_tokens =
            (self.accumulated_tokens + elapsed * tokens_per_sec).min(tokens_per_sec * 0.1); // 100ms max burst

        let needed = bytes_to_send as f64;
        if self.accumulated_tokens < needed {
            let deficit = needed - self.accumulated_tokens;
            let wait_secs = deficit / tokens_per_sec;
            if wait_secs > 0.0005 {
                sleep(Duration::from_secs_f64(wait_secs)).await;
                self.last_send = Instant::now();
                self.accumulated_tokens = 0.0;
                return;
            }
        }
        self.accumulated_tokens -= needed;
    }
}

/// Port-Hopper for Hysteria 2 to defeat port-based firewall throttling.
#[derive(Clone, Debug)]
pub struct PortHopper {
    ports: Vec<u16>,
    hop_interval: Duration,
    last_hop: Instant,
    current_idx: usize,
}

impl PortHopper {
    pub fn new(ports: Vec<u16>, hop_interval_secs: u64) -> Self {
        let clean_ports = if ports.is_empty() { vec![443] } else { ports };
        Self {
            ports: clean_ports,
            hop_interval: Duration::from_secs(hop_interval_secs.max(5)),
            last_hop: Instant::now(),
            current_idx: 0,
        }
    }

    /// Returns the currently active UDP port, automatically hopping when interval elapses.
    pub fn current_port(&mut self) -> u16 {
        if self.ports.len() > 1 && self.last_hop.elapsed() >= self.hop_interval {
            self.current_idx = (self.current_idx + 1) % self.ports.len();
            self.last_hop = Instant::now();
        }
        self.ports[self.current_idx]
    }
}

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub struct Hysteria2Protocol;

impl Hysteria2Protocol {
    /// Encodes a uint64 into RFC 9000 QUIC variable-length integer format.
    pub fn put_quic_varint(val: u64, buf: &mut Vec<u8>) {
        if val <= 63 {
            buf.push(val as u8);
        } else if val <= 16383 {
            let be = (val as u16) | 0x4000;
            buf.extend_from_slice(&be.to_be_bytes());
        } else if val <= 1073741823 {
            let be = (val as u32) | 0x80000000;
            buf.extend_from_slice(&be.to_be_bytes());
        } else {
            let be = val | 0xc000000000000000;
            buf.extend_from_slice(&be.to_be_bytes());
        }
    }

    /// Reads an RFC 9000 QUIC variable-length integer from an asynchronous stream.
    pub async fn read_quic_varint<R: tokio::io::AsyncRead + Unpin>(
        reader: &mut R,
    ) -> FluxResult<u64> {
        use tokio::io::AsyncReadExt;
        let mut first = [0u8; 1];
        reader.read_exact(&mut first).await.map_err(FluxError::Io)?;
        let prefix = first[0] >> 6;
        let len = match prefix {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let mut val = (first[0] & 0x3f) as u64;
        for _ in 1..len {
            let mut b = [0u8; 1];
            reader.read_exact(&mut b).await.map_err(FluxError::Io)?;
            val = (val << 8) | (b[0] as u64);
        }
        Ok(val)
    }

    /// Encodes a standard Hysteria 2 TCPRequest frame (0x401).
    pub fn encode_tcp_request(target: &TargetAddress) -> Vec<u8> {
        let addr_str = match target {
            TargetAddress::Ip(sa) => sa.to_string(),
            TargetAddress::Domain(d, p) => format!("{}:{}", d, p),
        };
        let mut buf = Vec::with_capacity(32 + addr_str.len());
        Self::put_quic_varint(0x401, &mut buf);
        Self::put_quic_varint(addr_str.len() as u64, &mut buf);
        buf.extend_from_slice(addr_str.as_bytes());
        Self::put_quic_varint(0, &mut buf); // padding length = 0
        buf
    }

    /// Reads and verifies a standard Hysteria 2 TCPResponse frame.
    pub async fn read_tcp_response<R: tokio::io::AsyncRead + Unpin>(
        reader: &mut R,
    ) -> FluxResult<()> {
        use tokio::io::AsyncReadExt;
        let mut status = [0u8; 1];
        reader
            .read_exact(&mut status)
            .await
            .map_err(FluxError::Io)?;
        let msg_len = Self::read_quic_varint(reader).await?;
        if msg_len > 0 {
            let mut msg_buf = vec![0u8; msg_len as usize];
            reader
                .read_exact(&mut msg_buf)
                .await
                .map_err(FluxError::Io)?;
        }
        let pad_len = Self::read_quic_varint(reader).await?;
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len as usize];
            reader
                .read_exact(&mut pad_buf)
                .await
                .map_err(FluxError::Io)?;
        }
        if status[0] != 0 {
            return Err(FluxError::AuthFailed(
                "Hysteria 2 server rejected TCP request".into(),
            ));
        }
        Ok(())
    }

    /// Reads and parses an incoming standard Hysteria 2 TCPRequest frame (0x401).
    pub async fn read_tcp_request<R: tokio::io::AsyncRead + Unpin>(
        reader: &mut R,
    ) -> FluxResult<TargetAddress> {
        let frame_type = Self::read_quic_varint(reader).await?;
        if frame_type != 0x401 {
            return Err(FluxError::Protocol {
                protocol: "hysteria2",
                message: format!("unexpected frame type: {:#x}", frame_type),
            });
        }
        Self::read_tcp_request_body(reader).await
    }

    /// Reads a TCPRequest body when the 0x401 frame type was already consumed.
    pub async fn read_tcp_request_body<R: tokio::io::AsyncRead + Unpin>(
        reader: &mut R,
    ) -> FluxResult<TargetAddress> {
        use tokio::io::AsyncReadExt;
        let addr_len = Self::read_quic_varint(reader).await? as usize;
        let mut addr_buf = vec![0u8; addr_len];
        reader
            .read_exact(&mut addr_buf)
            .await
            .map_err(FluxError::Io)?;
        let addr_str = std::str::from_utf8(&addr_buf).map_err(|e| FluxError::Protocol {
            protocol: "hysteria2",
            message: e.to_string(),
        })?;
        let pad_len = Self::read_quic_varint(reader).await? as usize;
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len];
            reader
                .read_exact(&mut pad_buf)
                .await
                .map_err(FluxError::Io)?;
        }
        if let Ok(sa) = addr_str.parse::<SocketAddr>() {
            Ok(TargetAddress::Ip(sa))
        } else if let Some((d, p_str)) = addr_str.rsplit_once(':')
            && let Ok(p) = p_str.parse::<u16>()
        {
            Ok(TargetAddress::domain(d, p))
        } else {
            Err(FluxError::Protocol {
                protocol: "hysteria2",
                message: format!("invalid target address: {}", addr_str),
            })
        }
    }

    /// Encodes a standard Hysteria 2 TCPResponse frame.
    pub fn encode_tcp_response(ok: bool, msg: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + msg.len());
        buf.push(if ok { 0 } else { 1 });
        Self::put_quic_varint(msg.len() as u64, &mut buf);
        buf.extend_from_slice(msg.as_bytes());
        Self::put_quic_varint(0, &mut buf); // padding length = 0
        buf
    }

    /// Authenticates client with Hysteria 2 server using HTTP/3, returning a keeper that keeps HTTP/3 alive.
    pub async fn client_authenticate_h3(
        conn: quinn::Connection,
        password: &str,
    ) -> FluxResult<Box<dyn std::any::Any + Send + Sync>> {
        let auth_fut = async {
            let h3_conn = h3_quinn::Connection::new(conn);
            let (driver, mut send_request) =
                h3::client::new(h3_conn)
                    .await
                    .map_err(|e| FluxError::Protocol {
                        protocol: "hysteria2",
                        message: format!("HTTP/3 client init failed: {}", e),
                    })?;

            tokio::spawn(async move {
                let mut d = driver;
                let _ = std::future::poll_fn(|cx| d.poll_close(cx)).await;
            });

            let req = http::Request::builder()
                .method("POST")
                .uri("https://hysteria/auth")
                .header("Hysteria-Auth", password)
                .header("Hysteria-CC-RX", "0")
                .body(())
                .map_err(|e| FluxError::Protocol {
                    protocol: "hysteria2",
                    message: e.to_string(),
                })?;

            let mut stream =
                send_request
                    .send_request(req)
                    .await
                    .map_err(|e| FluxError::Protocol {
                        protocol: "hysteria2",
                        message: format!("HTTP/3 send_request failed: {}", e),
                    })?;

            let resp = stream
                .recv_response()
                .await
                .map_err(|e| FluxError::Protocol {
                    protocol: "hysteria2",
                    message: format!("HTTP/3 auth response failed: {}", e),
                })?;

            if resp.status().as_u16() != 233 {
                return Err(FluxError::AuthFailed(format!(
                    "Hysteria 2 authentication rejected with HTTP status {}",
                    resp.status()
                )));
            }

            Ok(Box::new(send_request) as Box<dyn std::any::Any + Send + Sync>)
        };

        tokio::time::timeout(Duration::from_millis(500), auth_fut)
            .await
            .map_err(|_| FluxError::Timeout("HTTP/3 authentication timed out".into()))?
    }

    /// Formats a client authentication frame for Hysteria 2.
    pub fn build_auth_frame(password: &str) -> Vec<u8> {
        let pw_bytes = password.as_bytes();
        let mut buf = Vec::with_capacity(3 + pw_bytes.len());
        buf.push(HYSTERIA2_VERSION);
        buf.extend_from_slice(&(pw_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(pw_bytes);
        buf
    }

    /// Parses and validates a client authentication frame.
    pub fn parse_auth_frame(data: &[u8], expected_password: &str) -> FluxResult<()> {
        if data.len() < 3 {
            return Err(FluxError::Protocol {
                protocol: "hysteria2",
                message: "auth frame too short".into(),
            });
        }

        if data[0] != HYSTERIA2_VERSION {
            return Err(FluxError::Protocol {
                protocol: "hysteria2",
                message: format!("unsupported hysteria2 version: {}", data[0]),
            });
        }

        let pw_len = u16::from_be_bytes([data[1], data[2]]) as usize;
        if data.len() < 3 + pw_len {
            return Err(FluxError::Protocol {
                protocol: "hysteria2",
                message: "truncated password in auth frame".into(),
            });
        }

        let pw = std::str::from_utf8(&data[3..3 + pw_len]).map_err(|e| FluxError::Protocol {
            protocol: "hysteria2",
            message: format!("invalid utf-8 in password: {}", e),
        })?;

        if !constant_time_eq_str(pw, expected_password) {
            return Err(FluxError::AuthFailed("invalid hysteria2 password".into()));
        }

        Ok(())
    }

    /// Parses an incoming stream request frame (TCP / UDP destination).
    pub fn parse_request_frame(data: &[u8]) -> FluxResult<(u8, TargetAddress)> {
        if data.len() < 4 {
            return Err(FluxError::Protocol {
                protocol: "hysteria2",
                message: "request frame too short".into(),
            });
        }

        let command = data[0];
        let port = u16::from_be_bytes([data[1], data[2]]);
        let atyp = data[3];

        let target = match atyp {
            1 => {
                if data.len() < 4 + 4 {
                    return Err(FluxError::Protocol {
                        protocol: "hysteria2",
                        message: "truncated ipv4 in request frame".into(),
                    });
                }
                let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                TargetAddress::Ip(SocketAddr::new(ip.into(), port))
            }
            2 => {
                if data.len() < 5 {
                    return Err(FluxError::Protocol {
                        protocol: "hysteria2",
                        message: "missing domain length".into(),
                    });
                }
                let len = data[4] as usize;
                if data.len() < 5 + len {
                    return Err(FluxError::Protocol {
                        protocol: "hysteria2",
                        message: "truncated domain in request frame".into(),
                    });
                }
                let domain = std::str::from_utf8(&data[5..5 + len])
                    .map_err(|e| FluxError::Protocol {
                        protocol: "hysteria2",
                        message: format!("invalid domain utf-8: {}", e),
                    })?
                    .to_string();
                TargetAddress::Domain(domain, port)
            }
            3 => {
                if data.len() < 4 + 16 {
                    return Err(FluxError::Protocol {
                        protocol: "hysteria2",
                        message: "truncated ipv6 in request frame".into(),
                    });
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[4..20]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                TargetAddress::Ip(SocketAddr::new(ip.into(), port))
            }
            other => {
                return Err(FluxError::Protocol {
                    protocol: "hysteria2",
                    message: format!("unsupported atyp {}", other),
                });
            }
        };

        Ok((command, target))
    }

    /// Formats a stream request frame (TCP / UDP destination).
    pub fn build_request_frame(command: u8, target: &TargetAddress) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.push(command);
        buf.extend_from_slice(&target.port().to_be_bytes());

        match target {
            TargetAddress::Ip(SocketAddr::V4(v4)) => {
                buf.push(1); // IPv4
                buf.extend_from_slice(&v4.ip().octets());
            }
            TargetAddress::Ip(SocketAddr::V6(v6)) => {
                buf.push(3); // IPv6
                buf.extend_from_slice(&v6.ip().octets());
            }
            TargetAddress::Domain(domain, _) => {
                buf.push(2); // Domain
                let d_bytes = domain.as_bytes();
                buf.push(d_bytes.len() as u8);
                buf.extend_from_slice(d_bytes);
            }
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hysteria2_auth_and_request() {
        let frame = Hysteria2Protocol::build_auth_frame("my_hy2_password");
        assert!(Hysteria2Protocol::parse_auth_frame(&frame, "my_hy2_password").is_ok());
        assert!(Hysteria2Protocol::parse_auth_frame(&frame, "wrong").is_err());

        let target = TargetAddress::domain("example.com", 443);
        let req = Hysteria2Protocol::build_request_frame(HYSTERIA2_CMD_TCP, &target);
        assert_eq!(req[0], HYSTERIA2_CMD_TCP);

        let (parsed_cmd, parsed_dst) = Hysteria2Protocol::parse_request_frame(&req).unwrap();
        assert_eq!(parsed_cmd, HYSTERIA2_CMD_TCP);
        assert_eq!(parsed_dst, target);
    }

    #[test]
    fn test_port_hopper_cycle() {
        let mut hopper = PortHopper::new(vec![40000, 40001, 40002], 0);
        assert_eq!(hopper.current_port(), 40000);
        // Force hop elapsed
        hopper.last_hop = Instant::now() - Duration::from_secs(10);
        assert_eq!(hopper.current_port(), 40001);
    }

    #[test]
    fn test_salamander_obfs_roundtrip() {
        let obfs = SalamanderObfs::new("my-salamander-secret");
        let plain = b"QUIC Initial Packet Data Simulated";
        let scrambled = obfs.obfuscate(plain);
        assert_ne!(&scrambled[16..], plain);
        let recovered = obfs.deobfuscate(&scrambled).unwrap();
        assert_eq!(&recovered, plain);
    }

    #[test]
    fn test_salamander_obfs_edge_cases() {
        let obfs = SalamanderObfs::new("my-salamander-secret");

        // 1. Truncated packet less than 16 bytes returns None
        assert_eq!(obfs.deobfuscate(&[]), None);
        assert_eq!(obfs.deobfuscate(&[1, 2, 3, 4, 5]), None);
        assert_eq!(obfs.deobfuscate(&[0u8; 15]), None);

        // 2. Empty payload (length 16 bytes: exactly salt)
        let empty_scrambled = obfs.obfuscate(&[]);
        assert_eq!(empty_scrambled.len(), 16);
        let recovered_empty = obfs.deobfuscate(&empty_scrambled).unwrap();
        assert!(recovered_empty.is_empty());

        // 3. Different calls produce distinct salts / ciphertexts
        let plain = b"Sensitive QUIC Frame Data";
        let c1 = obfs.obfuscate(plain);
        let c2 = obfs.obfuscate(plain);
        assert_ne!(c1, c2);
        assert_ne!(&c1[..16], &c2[..16]);
        assert_eq!(obfs.deobfuscate(&c1).unwrap(), plain);
        assert_eq!(obfs.deobfuscate(&c2).unwrap(), plain);

        // 4. Large payload (64 KB)
        let large_plain = vec![0x42u8; 65536];
        let large_scrambled = obfs.obfuscate(&large_plain);
        assert_eq!(large_scrambled.len(), 16 + 65536);
        assert_ne!(&large_scrambled[16..], &large_plain[..]);
        assert_eq!(obfs.deobfuscate(&large_scrambled).unwrap(), large_plain);

        // 5. Wrong key deobfuscation produces garbled data
        let wrong_obfs = SalamanderObfs::new("wrong-password");
        let wrong_recovered = wrong_obfs.deobfuscate(&c1).unwrap();
        assert_ne!(&wrong_recovered, plain);
    }
}
