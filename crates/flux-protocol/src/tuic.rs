use flux_types::{FluxError, FluxResult, TargetAddress};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const TUIC_V5_VERSION: u8 = 5;
pub const TUIC_CMD_CONNECT: u8 = 0x01;
pub const TUIC_CMD_PACKET: u8 = 0x02;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TuicV5Config {
    pub server: String,
    pub server_port: u16,
    pub uuid: Uuid,
    pub password: String,
    #[serde(default = "default_congestion")]
    pub congestion_control: String,
    #[serde(default = "default_zero_rtt")]
    pub zero_rtt: bool,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub server_name: Option<String>,
}

fn default_congestion() -> String {
    "bbr".into()
}
fn default_zero_rtt() -> bool {
    true
}

fn constant_time_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub struct TuicV5Protocol;

impl TuicV5Protocol {
    /// Builds TUIC v5 authentication token: HMAC-SHA256(password, [UUID + timestamp])
    pub fn build_auth_token(uuid: &Uuid, password: &str, timestamp: u64) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(password.as_bytes()).unwrap();
        mac.update(uuid.as_bytes());
        mac.update(&timestamp.to_be_bytes());
        let res = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res[..32]);
        out
    }

    /// Builds a TUIC v5 authenticate frame:
    /// [Version (1 byte) + UUID (16 bytes) + Timestamp (8 bytes) + Auth Token (32 bytes)]
    pub fn build_auth_frame(uuid: &Uuid, password: &str) -> Vec<u8> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let token = Self::build_auth_token(uuid, password, now);

        let mut buf = Vec::with_capacity(1 + 16 + 8 + 32);
        buf.push(TUIC_V5_VERSION);
        buf.extend_from_slice(uuid.as_bytes());
        buf.extend_from_slice(&now.to_be_bytes());
        buf.extend_from_slice(&token);
        buf
    }

    /// Verifies incoming TUIC v5 authentication frame.
    pub fn verify_auth_frame(
        data: &[u8],
        password: &str,
        valid_uuids: &[Uuid],
    ) -> FluxResult<Uuid> {
        if data.len() < 1 + 16 + 8 + 32 {
            return Err(FluxError::Protocol {
                protocol: "tuic5",
                message: "auth frame too short".into(),
            });
        }

        if data[0] != TUIC_V5_VERSION {
            return Err(FluxError::Protocol {
                protocol: "tuic5",
                message: format!("unsupported tuic version {}", data[0]),
            });
        }

        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&data[1..17]);
        let uuid = Uuid::from_bytes(uuid_bytes);

        if !valid_uuids.is_empty() && !valid_uuids.contains(&uuid) {
            return Err(FluxError::AuthFailed(format!(
                "unauthorized tuic uuid: {}",
                uuid
            )));
        }

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&data[17..25]);
        let ts = u64::from_be_bytes(ts_bytes);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now.abs_diff(ts) > 120 {
            return Err(FluxError::AuthFailed("tuic auth timestamp expired".into()));
        }

        let expected_token = Self::build_auth_token(&uuid, password, ts);
        if !constant_time_eq_slice(&data[25..57], expected_token.as_slice()) {
            return Err(FluxError::AuthFailed(
                "tuic token verification failed".into(),
            ));
        }

        Ok(uuid)
    }

    /// Encodes a TUIC v5 Command frame (CONNECT or PACKET):
    /// [Command (1 byte) + Port (2 bytes) + ATYP (1 byte) + Addr]
    pub fn build_command_frame(command: u8, target: &TargetAddress) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.push(command);
        buf.extend_from_slice(&target.port().to_be_bytes());

        match target {
            TargetAddress::Ip(SocketAddr::V4(v4)) => {
                buf.push(1); // IPv4
                buf.extend_from_slice(&v4.ip().octets());
            }
            TargetAddress::Ip(SocketAddr::V6(v6)) => {
                buf.push(4); // IPv6
                buf.extend_from_slice(&v6.ip().octets());
            }
            TargetAddress::Domain(domain, _) => {
                buf.push(3); // Domain
                let d_bytes = domain.as_bytes();
                buf.push(d_bytes.len() as u8);
                buf.extend_from_slice(d_bytes);
            }
        }
        buf
    }

    /// Decodes a TUIC v5 Command frame.
    pub fn parse_command_frame(data: &[u8]) -> FluxResult<(u8, TargetAddress)> {
        if data.len() < 4 {
            return Err(FluxError::Protocol {
                protocol: "tuic5",
                message: "command frame too short".into(),
            });
        }

        let cmd = data[0];
        let port = u16::from_be_bytes([data[1], data[2]]);
        let atyp = data[3];

        let target = match atyp {
            1 => {
                if data.len() < 4 + 4 {
                    return Err(FluxError::Protocol {
                        protocol: "tuic5",
                        message: "truncated ipv4".into(),
                    });
                }
                let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                TargetAddress::Ip(SocketAddr::new(ip.into(), port))
            }
            3 => {
                if data.len() < 5 {
                    return Err(FluxError::Protocol {
                        protocol: "tuic5",
                        message: "missing domain length".into(),
                    });
                }
                let len = data[4] as usize;
                if data.len() < 5 + len {
                    return Err(FluxError::Protocol {
                        protocol: "tuic5",
                        message: "truncated domain".into(),
                    });
                }
                let domain = std::str::from_utf8(&data[5..5 + len])
                    .map_err(|e| FluxError::Protocol {
                        protocol: "tuic5",
                        message: format!("invalid domain: {}", e),
                    })?
                    .to_string();
                TargetAddress::Domain(domain, port)
            }
            4 => {
                if data.len() < 4 + 16 {
                    return Err(FluxError::Protocol {
                        protocol: "tuic5",
                        message: "truncated ipv6".into(),
                    });
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[4..20]);
                let ip = Ipv6Addr::from(ip_bytes);
                TargetAddress::Ip(SocketAddr::new(ip.into(), port))
            }
            other => {
                return Err(FluxError::Protocol {
                    protocol: "tuic5",
                    message: format!("unknown atyp {}", other),
                });
            }
        };

        Ok((cmd, target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuic_auth_and_command() {
        let uuid = Uuid::new_v4();
        let pw = "tuic_secret_123";

        let auth_pkt = TuicV5Protocol::build_auth_frame(&uuid, pw);
        let verified = TuicV5Protocol::verify_auth_frame(&auth_pkt, pw, &[uuid]).unwrap();
        assert_eq!(verified, uuid);

        let target = TargetAddress::domain("example.com", 443);
        let cmd_pkt = TuicV5Protocol::build_command_frame(TUIC_CMD_CONNECT, &target);
        let (cmd, parsed_target) = TuicV5Protocol::parse_command_frame(&cmd_pkt).unwrap();
        assert_eq!(cmd, TUIC_CMD_CONNECT);
        assert_eq!(parsed_target, target);
    }
}
