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

/// Converts a hostname to its ASCII (punycode) form and lowercases it.
///
/// Returns the input unchanged when it is already ASCII and cannot be mistaken for
/// anything else, so the common path allocates nothing beyond the `String` the
/// caller already had. A name that IDNA rejects (an empty or over-long label, a
/// disallowed character) is returned trimmed and lowercased rather than dropped:
/// a connection to a nonsense name should fail in DNS, not vanish here.
pub fn normalize_domain(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_ascii() {
        return trimmed.to_ascii_lowercase();
    }
    match idna::domain_to_ascii(trimmed) {
        Ok(ascii) => ascii,
        Err(_) => trimmed.to_lowercase(),
    }
}

impl TargetAddress {
    pub fn ip(ip: IpAddr, port: u16) -> Self {
        Self::Ip(SocketAddr::new(ip, port))
    }

    pub fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port))
    }

    /// Builds a domain destination, normalising the name on the way in.
    ///
    /// Everything downstream — rule matching, the Fake-IP map, the DNS cache —
    /// compares names as ASCII, and a client is free to send the Unicode form in a
    /// SOCKS5 or HTTP CONNECT request. Converting once here means a Cyrillic or
    /// Chinese name is routed by the same rule as its `xn--` form instead of
    /// silently taking `final`.
    pub fn domain(domain: impl Into<String>, port: u16) -> Self {
        Self::Domain(normalize_domain(&domain.into()), port)
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

            // A trailing root dot is legal in a DNS name and meaningless on a
            // literal, but `"1.2.3.4.".parse::<IpAddr>()` fails — so without this
            // the address became a `Domain("1.2.3.4.")`, every `IP-CIDR` rule
            // silently stopped applying to it, and the dial path would have tried
            // to resolve it.
            let ip_candidate = host_clean.strip_suffix('.').unwrap_or(host_clean);
            if let Ok(ip) = ip_candidate.parse::<IpAddr>() {
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

#[cfg(test)]
mod address_literal_tests {
    use super::*;
    use std::str::FromStr;

    /// `1.2.3.4.:80` is an IP with a root dot, not a domain: as a domain it never
    /// matches an `IP-CIDR` rule and the dial path tries to resolve it.
    #[test]
    fn an_ip_literal_with_a_root_dot_is_still_an_ip() {
        for (input, expected) in [
            ("1.2.3.4.:80", "1.2.3.4:80"),
            ("192.168.0.1.:443", "192.168.0.1:443"),
        ] {
            match TargetAddress::from_str(input).expect("must parse") {
                TargetAddress::Ip(addr) => assert_eq!(addr.to_string(), expected),
                other => panic!("{input} parsed as {other:?}, expected an Ip"),
            }
        }
    }

    /// A real domain must keep its root dot and stay a domain.
    #[test]
    fn a_domain_with_a_root_dot_stays_a_domain() {
        match TargetAddress::from_str("example.com.:443").expect("must parse") {
            TargetAddress::Domain(host, port) => {
                assert_eq!(port, 443);
                assert!(host.starts_with("example.com"), "unexpected host {host}");
            }
            other => panic!("parsed as {other:?}, expected a Domain"),
        }
    }
}

#[cfg(test)]
mod idna_tests {
    use super::*;

    /// A Unicode name must be converted to the form every comparison uses, or a
    /// rule written for the ASCII name silently never matches.
    #[test]
    fn a_unicode_domain_becomes_its_ascii_form() {
        assert_eq!(normalize_domain("пример.рф"), "xn--e1afmkfd.xn--p1ai");
        assert_eq!(normalize_domain("例え.テスト"), "xn--r8jz45g.xn--zckzah");
        assert_eq!(
            TargetAddress::domain("пример.рф", 443).host(),
            "xn--e1afmkfd.xn--p1ai"
        );
    }

    /// The common path must not change what it did before.
    #[test]
    fn ascii_names_are_trimmed_and_lowercased() {
        assert_eq!(normalize_domain("Example.COM."), "example.com");
        assert_eq!(normalize_domain(" example.com "), "example.com");
        assert_eq!(normalize_domain("127.0.0.1"), "127.0.0.1");
    }

    /// A name IDNA rejects is passed through rather than dropped: the connection
    /// should fail in DNS, not vanish in the router.
    #[test]
    fn a_name_idna_rejects_survives_the_conversion() {
        let weird = "exa\u{0000}mple.com";
        assert!(normalize_domain(weird).contains("mple.com"));
        // Over-long label (64 chars) is invalid; the input is still returned.
        let long = format!("{}.com", "a".repeat(70));
        assert!(normalize_domain(&long).ends_with(".com"));
    }
}
