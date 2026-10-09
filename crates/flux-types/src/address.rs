use crate::error::FluxError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

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
        let clean = s.trim();
        if let Ok(addr) = clean.parse::<SocketAddr>() {
            return Ok(Self::Ip(addr));
        }

        // Bracketed IPv6 like "[::1]:8080"
        if clean.starts_with('[')
            && let Some((host_part, port_str)) = clean.split_once("]:")
        {
            let ip_str = host_part.trim_start_matches('[');
            let port = port_str.parse::<u16>().map_err(|_| {
                FluxError::InvalidAddress(format!(
                    "invalid port in bracketed IPv6 address: {}",
                    clean
                ))
            })?;
            let ip = ip_str.parse::<IpAddr>().map_err(|_| {
                FluxError::InvalidAddress(format!("invalid IPv6 in bracketed address: {}", clean))
            })?;
            return Ok(Self::Ip(SocketAddr::new(ip, port)));
        }

        // Parse host:port
        if let Some((host, port_str)) = clean.rsplit_once(':') {
            // If host contains colons and is not bracketed, it's an unbracketed IPv6 address without port
            if host.contains(':') {
                return Err(FluxError::InvalidAddress(format!(
                    "IPv6 address must be enclosed in brackets with port '[::1]:port': {}",
                    clean
                )));
            }

            let port = port_str.parse::<u16>().map_err(|_| {
                FluxError::InvalidAddress(format!("invalid port in address: {}", clean))
            })?;

            let host_clean = host.trim();
            if host_clean.is_empty() {
                return Err(FluxError::InvalidAddress(format!(
                    "empty host in address: {}",
                    clean
                )));
            }

            if let Ok(ip) = host_clean.parse::<IpAddr>() {
                Ok(Self::Ip(SocketAddr::new(ip, port)))
            } else {
                Ok(Self::Domain(host_clean.to_string(), port))
            }
        } else {
            Err(FluxError::InvalidAddress(format!(
                "missing port in address: {}",
                clean
            )))
        }
    }
}

/// Parses an HTTP or HTTPS probe/healthcheck URL into (TargetAddress, host_header, request_path, is_tls).
/// Correctly defaults port to 443 for https:// and 80 for http://.
pub fn parse_probe_url(url: &str) -> (TargetAddress, String, String, bool) {
    let is_tls = url.starts_with("https://");
    let clean = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    let (host_port, path) = match clean.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (clean, "/".to_string()),
    };

    let default_port = if is_tls { 443 } else { 80 };
    let (host, port) = if host_port.starts_with('[') {
        if let Some((h, p)) = host_port.split_once("]:") {
            (format!("{}]", h), p.parse::<u16>().unwrap_or(default_port))
        } else {
            (host_port.to_string(), default_port)
        }
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
    } else {
        (host_port.to_string(), default_port)
    };

    let host_clean = host.trim_start_matches('[').trim_end_matches(']');
    let target = if let Ok(ip) = host_clean.parse::<IpAddr>() {
        TargetAddress::ip(ip, port)
    } else {
        TargetAddress::domain(host.clone(), port)
    };

    (target, host, path, is_tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_probe_url() {
        let (target, host, path, is_tls) =
            parse_probe_url("https://cp.cloudflare.com/generate_204");
        assert_eq!(target.port(), 443);
        assert_eq!(host, "cp.cloudflare.com");
        assert_eq!(path, "/generate_204");
        assert!(is_tls);

        let (target2, host2, path2, is_tls2) = parse_probe_url("http://example.com:8080/test");
        assert_eq!(target2.port(), 8080);
        assert_eq!(host2, "example.com");
        assert_eq!(path2, "/test");
        assert!(!is_tls2);

        let (target3, host3, path3, is_tls3) = parse_probe_url("http://1.1.1.1/generate_204");
        assert_eq!(target3.port(), 80);
        assert_eq!(host3, "1.1.1.1");
        assert_eq!(path3, "/generate_204");
        assert!(target3.is_ipv4());
        assert!(!is_tls3);

        let (target4, host4, path4, is_tls4) = parse_probe_url("http://[::1]:8080/test");
        assert_eq!(target4.port(), 8080);
        assert_eq!(host4, "[::1]");
        assert_eq!(path4, "/test");
        assert!(target4.is_ipv6());
        assert!(!is_tls4);
    }

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

        // Bare unbracketed IPv6 address without port must be rejected
        assert!("2001:db8::1".parse::<TargetAddress>().is_err());
    }
}
