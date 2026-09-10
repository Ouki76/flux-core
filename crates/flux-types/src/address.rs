use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::error::FluxError;

/// Target address representation supporting both IP addresses and domain names.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetAddress {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddress {
    pub fn ip(ip: IpAddr, port: u16) -> Self {
        Self::Ip(SocketAddr::new(ip, port))
    }

    pub fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port))
    }

    pub fn domain(domain: impl Into<String>, port: u16) -> Self {
        Self::Domain(domain.into(), port)
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Ip(addr) => addr.ip().to_string(),
            Self::Domain(domain, _) => domain.clone(),
        }
    }

    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::Ip(SocketAddr::V4(_)))
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::Ip(SocketAddr::V6(_)))
    }

    pub fn is_domain(&self) -> bool {
        matches!(self, Self::Domain(..))
    }
}

impl fmt::Display for TargetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{}", addr),
            Self::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

impl fmt::Debug for TargetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<SocketAddr> for TargetAddress {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

impl FromStr for TargetAddress {
    type Err = FluxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(Self::Ip(addr));
        }

        // Parse host:port
        if let Some((host, port_str)) = s.rsplit_once(':') {
            let port = port_str.parse::<u16>().map_err(|_| {
                FluxError::InvalidAddress(format!("invalid port in address: {}", s))
            })?;

            let host_clean = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = host_clean.parse::<IpAddr>() {
                Ok(Self::Ip(SocketAddr::new(ip, port)))
            } else {
                Ok(Self::Domain(host_clean.to_string(), port))
            }
        } else {
            Err(FluxError::InvalidAddress(format!("missing port in address: {}", s)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_address_parsing() {
        let addr1: TargetAddress = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(addr1.port(), 8080);
        assert!(addr1.is_ipv4());

        let addr2: TargetAddress = "[::1]:9090".parse().unwrap();
        assert_eq!(addr2.port(), 9090);
        assert!(addr2.is_ipv6());

        let addr3: TargetAddress = "example.com:443".parse().unwrap();
        assert_eq!(addr3.port(), 443);
        assert!(addr3.is_domain());
        assert_eq!(addr3.host(), "example.com");
    }
}
