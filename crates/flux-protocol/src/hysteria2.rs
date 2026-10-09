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
}
