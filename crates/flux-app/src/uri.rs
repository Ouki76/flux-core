use crate::config::{OutboundConfig, OutboundRealityConfig, OutboundTlsConfig, TransportConfig};
use base64::Engine;
use flux_types::{FluxError, FluxResult};
use std::collections::HashMap;

/// Canonical specification of a proxy outbound node built from URI links.
#[derive(Clone, Debug, Default)]
pub struct ProxySpec {
    pub tag: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub auth: Option<String>,     // uuid for vless, password for trojan/ss
    pub username: Option<String>, // socks/http username
    pub password: Option<String>, // socks/http/trojan password
    pub method: Option<String>,   // cipher method for ss
    pub flow: Option<String>,     // flow for vless (e.g. xtls-rprx-vision)
    pub tls: Option<OutboundTlsConfig>,
    pub reality: Option<OutboundRealityConfig>,
    pub transport: Option<TransportConfig>,
}

impl ProxySpec {
    pub fn new(
        tag: impl Into<String>,
        protocol: impl Into<String>,
        server: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            tag: tag.into(),
            protocol: protocol.into(),
            server: server.into(),
            port,
            ..Default::default()
        }
    }

    /// Builds canonical `OutboundConfig` from this proxy specification.
    pub fn build(self) -> FluxResult<OutboundConfig> {
        let proto = self.protocol.trim().to_ascii_lowercase();
        match proto.as_str() {
            "vless" => {
                let uuid = self.auth.or(self.password).ok_or_else(|| {
                    FluxError::Config(format!("outbound '{}': missing uuid for vless", self.tag))
                })?;
                Ok(OutboundConfig::Vless {
                    tag: self.tag,
                    server: self.server,
                    server_port: self.port,
                    uuid,
                    flow: self.flow,
                    tls: self.tls,
                    reality: self.reality,
                    transport: self.transport,
                })
            }
            "trojan" => {
                let password = self.auth.or(self.password).unwrap_or_default();
                Ok(OutboundConfig::Trojan {
                    tag: self.tag,
                    server: self.server,
                    server_port: self.port,
                    password,
                    tls: self.tls,
                    transport: self.transport,
                })
            }
            "ss" | "shadowsocks" => {
                let password = self.auth.or(self.password).unwrap_or_default();
                Ok(OutboundConfig::Shadowsocks {
                    tag: self.tag,
                    server: self.server,
                    server_port: self.port,
                    password,
                    method: self.method,
                    tls: self.tls,
                    transport: self.transport,
                })
            }
            "socks" | "socks5" => Ok(OutboundConfig::Socks {
                tag: self.tag,
                server: self.server,
                server_port: self.port,
                username: self.username,
                password: self.password,
            }),
            "http" | "https" => Ok(OutboundConfig::Http {
                tag: self.tag,
                server: self.server,
                server_port: self.port,
                username: self.username,
                password: self.password,
            }),
            "direct" => Ok(OutboundConfig::Direct {
                tag: self.tag,
                tls_fragment: None,
            }),
            "block" => Ok(OutboundConfig::Block { tag: self.tag }),
            "tuic" => {
                let uuid = self.auth.ok_or_else(|| {
                    FluxError::Config(format!("outbound '{}': missing uuid for tuic", self.tag))
                })?;
                let password = self.password.unwrap_or_default();
                Ok(OutboundConfig::Tuic {
                    tag: self.tag,
                    server: self.server,
                    server_port: self.port,
                    uuid,
                    password,
                    congestion_control: None,
                    zero_rtt: None,
                    tls: self.tls,
                })
            }
            "hy2" | "hysteria2" => {
                let password = self.auth.or(self.password).unwrap_or_default();
                Ok(OutboundConfig::Hysteria2 {
                    tag: self.tag,
                    server: self.server,
                    server_port: Some(self.port),
                    ports: vec![self.port],
                    password,
                    up_mbps: 100,
                    down_mbps: 100,
                    hop_interval_secs: None,
                    tls: self.tls,
                })
            }
            other => {
                tracing::warn!(
                    "unsupported protocol '{}' for outbound '{}', falling back to direct",
                    other,
                    self.tag
                );
                Ok(OutboundConfig::Direct {
                    tag: self.tag,
                    tls_fragment: None,
                })
            }
        }
    }
}

/// Parses standard proxy sharing links (VLESS, Trojan, Shadowsocks, SOCKS5, HTTP)
/// into an `OutboundConfig`.
pub fn parse_proxy_uri(uri: &str) -> FluxResult<OutboundConfig> {
    let clean = uri.trim();
    if clean.starts_with("vless://") {
        parse_vless_uri(clean)
    } else if clean.starts_with("trojan://") {
        parse_trojan_uri(clean)
    } else if clean.starts_with("ss://") {
        parse_shadowsocks_uri(clean)
    } else if clean.starts_with("socks5://") || clean.starts_with("socks://") {
        parse_socks_uri(clean)
    } else if clean.starts_with("http://") || clean.starts_with("https://") {
        parse_http_uri(clean)
    } else if clean.starts_with("hy2://") || clean.starts_with("hysteria2://") {
        parse_hysteria2_uri(clean)
    } else if clean.starts_with("tuic://") {
        parse_tuic_uri(clean)
    } else {
        Err(FluxError::Config(format!(
            "unsupported or invalid proxy URI: {}",
            clean
        )))
    }
}

fn parse_vless_uri(uri: &str) -> FluxResult<OutboundConfig> {
    // vless://uuid@host:port?security=reality&sni=...&pbk=...&sid=...&flow=...#Tag
    let without_scheme = uri.strip_prefix("vless://").unwrap_or(uri);
    let (body, tag) = extract_tag(without_scheme, "vless-node");
    let (user_host_port, query) = body.split_once('?').unwrap_or((body, ""));
    let (uuid, host_port) = user_host_port
        .split_once('@')
        .ok_or_else(|| FluxError::Config("missing uuid in vless uri".into()))?;
    let (host, port) = parse_host_port(host_port, 443)?;

    let params = parse_query(query);

    let security = params.get("security").map(|s| s.as_str()).unwrap_or("none");
    let sni = params
        .get("sni")
        .cloned()
        .or_else(|| params.get("peer").cloned());
    let flow = params.get("flow").cloned();

    let fp = params
        .get("fp")
        .cloned()
        .or_else(|| params.get("utls").cloned());

    let tls_config = if security == "tls" || security == "reality" {
        Some(OutboundTlsConfig {
            enabled: true,
            server_name: sni.clone(),
            insecure: params
                .get("allowInsecure")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
            alpn: params
                .get("alpn")
                .map(|a| a.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            utls: fp,
        })
    } else {
        None
    };

    let reality_config = if security == "reality" {
        let public_key = params
            .get("pbk")
            .or_else(|| params.get("public_key"))
            .cloned()
            .ok_or_else(|| {
                FluxError::Config("missing pbk (public key) in reality vless uri".into())
            })?;
        let short_id = params
            .get("sid")
            .or_else(|| params.get("short_id"))
            .cloned();

        Some(OutboundRealityConfig {
            enabled: true,
            public_key,
            short_id,
        })
    } else {
        None
    };

    ProxySpec {
        tag,
        protocol: "vless".into(),
        server: host,
        port,
        auth: Some(uuid.to_string()),
        flow,
        tls: tls_config,
        reality: reality_config,
        ..Default::default()
    }
    .build()
}

fn parse_trojan_uri(uri: &str) -> FluxResult<OutboundConfig> {
    // trojan://password@host:port?sni=...#Tag
    let without_scheme = uri.strip_prefix("trojan://").unwrap_or(uri);
    let (body, tag) = extract_tag(without_scheme, "trojan-node");
    let (pass_host_port, query) = body.split_once('?').unwrap_or((body, ""));
    let (password, host_port) = pass_host_port
        .split_once('@')
        .ok_or_else(|| FluxError::Config("missing password in trojan uri".into()))?;
    let (host, port) = parse_host_port(host_port, 443)?;

    let params = parse_query(query);
    let sni = params
        .get("sni")
        .or_else(|| params.get("peer"))
        .cloned()
        .unwrap_or_else(|| host.clone());
    let insecure = params
        .get("allowInsecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    let fp = params
        .get("fp")
        .cloned()
        .or_else(|| params.get("utls").cloned());

    ProxySpec {
        tag,
        protocol: "trojan".into(),
        server: host,
        port,
        auth: Some(password.to_string()),
        tls: Some(OutboundTlsConfig {
            enabled: true,
            server_name: Some(sni),
            insecure,
            alpn: vec![],
            utls: fp,
        }),
        ..Default::default()
    }
    .build()
}

fn parse_shadowsocks_uri(uri: &str) -> FluxResult<OutboundConfig> {
    // ss://BASE64(method:password@host:port)#Tag
    // or ss://BASE64(method:password)@host:port#Tag
    let without_scheme = uri.strip_prefix("ss://").unwrap_or(uri);
    let (body, tag) = extract_tag(without_scheme, "ss-node");

    if let Some((userinfo_b64, host_port)) = body.split_once('@') {
        let (host, port) = parse_host_port(host_port, 8388)?;
        let decoded = decode_base64_or_plain(userinfo_b64)?;
        let (method, password) = decoded.split_once(':').ok_or_else(|| {
            FluxError::Config("invalid shadowsocks userinfo (expected method:password)".into())
        })?;

        ProxySpec {
            tag,
            protocol: "shadowsocks".into(),
            server: host,
            port,
            auth: Some(password.to_string()),
            method: Some(method.to_string()),
            ..Default::default()
        }
        .build()
    } else {
        // Full body base64
        let decoded = decode_base64_or_plain(body)?;
        let (userinfo, host_port) = decoded
            .split_once('@')
            .ok_or_else(|| FluxError::Config("invalid shadowsocks uri".into()))?;
        let (host, port) = parse_host_port(host_port, 8388)?;
        let (method, password) = userinfo.split_once(':').ok_or_else(|| {
            FluxError::Config("invalid shadowsocks userinfo (expected method:password)".into())
        })?;

        ProxySpec {
            tag,
            protocol: "shadowsocks".into(),
            server: host,
            port,
            auth: Some(password.to_string()),
            method: Some(method.to_string()),
            ..Default::default()
        }
        .build()
    }
}

fn parse_socks_uri(uri: &str) -> FluxResult<OutboundConfig> {
    let without_scheme = uri
        .strip_prefix("socks5://")
        .or_else(|| uri.strip_prefix("socks://"))
        .unwrap_or(uri);
    let (body, tag) = extract_tag(without_scheme, "socks-node");

    let (username, password, host, port) =
        if let Some((user_pass, host_port)) = body.split_once('@') {
            let (u, p) = user_pass.split_once(':').unwrap_or((user_pass, ""));
            let (h, port) = parse_host_port(host_port, 1080)?;
            (Some(u.to_string()), Some(p.to_string()), h, port)
        } else {
            let (h, port) = parse_host_port(body, 1080)?;
            (None, None, h, port)
        };

    ProxySpec {
        tag,
        protocol: "socks".into(),
        server: host,
        port,
        username,
        password,
        ..Default::default()
    }
    .build()
}

fn parse_http_uri(uri: &str) -> FluxResult<OutboundConfig> {
    let without_scheme = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .unwrap_or(uri);
    let (body, tag) = extract_tag(without_scheme, "http-node");

    let (username, password, host, port) =
        if let Some((user_pass, host_port)) = body.split_once('@') {
            let (u, p) = user_pass.split_once(':').unwrap_or((user_pass, ""));
            let (h, port) = parse_host_port(host_port, 8080)?;
            (Some(u.to_string()), Some(p.to_string()), h, port)
        } else {
            let (h, port) = parse_host_port(body, 8080)?;
            (None, None, h, port)
        };

    ProxySpec {
        tag,
        protocol: "http".into(),
        server: host,
        port,
        username,
        password,
        ..Default::default()
    }
    .build()
}

fn parse_hysteria2_uri(uri: &str) -> FluxResult<OutboundConfig> {
    let without_scheme = uri
        .strip_prefix("hysteria2://")
        .or_else(|| uri.strip_prefix("hy2://"))
        .unwrap_or(uri);
    let (body, tag) = extract_tag(without_scheme, "hy2-node");
    let (user_host_port, _query) = body.split_once('?').unwrap_or((body, ""));
    let (password, host_port) = user_host_port
        .split_once('@')
        .ok_or_else(|| FluxError::Config("missing password in hysteria2 uri".into()))?;
    let (host, port) = parse_host_port(host_port, 443)?;

    ProxySpec {
        tag,
        protocol: "hy2".into(),
        server: host,
        port,
        auth: Some(urlencoding_decode(password)),
        ..Default::default()
    }
    .build()
}

fn parse_tuic_uri(uri: &str) -> FluxResult<OutboundConfig> {
    let without_scheme = uri.strip_prefix("tuic://").unwrap_or(uri);
    let (body, tag) = extract_tag(without_scheme, "tuic-node");
    let (userinfo_host_port, _query) = body.split_once('?').unwrap_or((body, ""));
    let (userinfo, host_port) = userinfo_host_port
        .split_once('@')
        .ok_or_else(|| FluxError::Config("missing userinfo in tuic uri".into()))?;
    let (uuid, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let (host, port) = parse_host_port(host_port, 8443)?;

    ProxySpec {
        tag,
        protocol: "tuic".into(),
        server: host,
        port,
        auth: Some(uuid.to_string()),
        password: Some(urlencoding_decode(password)),
        ..Default::default()
    }
    .build()
}

fn extract_tag<'a>(s: &'a str, default_prefix: &str) -> (&'a str, String) {
    if let Some((body, tag_part)) = s.split_once('#') {
        let clean_tag = urlencoding_decode(tag_part.trim());
        (
            body,
            if clean_tag.is_empty() {
                default_prefix.to_string()
            } else {
                clean_tag
            },
        )
    } else {
        (s, default_prefix.to_string())
    }
}

fn parse_host_port(s: &str, default_port: u16) -> FluxResult<(String, u16)> {
    let clean = s.split('?').next().unwrap_or(s).trim();
    if let Some((h, p)) = clean.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|_| FluxError::Config(format!("invalid port '{}' in {}", p, s)))?;
        let host = h.trim_start_matches('[').trim_end_matches(']').to_string();
        Ok((host, port))
    } else {
        Ok((clean.to_string(), default_port))
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in q.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.trim().to_string(), urlencoding_decode(v.trim()));
        }
    }
    map
}

fn decode_base64_or_plain(s: &str) -> FluxResult<String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    if let Ok(bytes) = engine.decode(s)
        && let Ok(utf8) = String::from_utf8(bytes)
    {
        return Ok(utf8);
    }
    if let Ok(bytes) = url_engine.decode(s)
        && let Ok(utf8) = String::from_utf8(bytes)
    {
        return Ok(utf8);
    }
    Ok(s.to_string())
}

pub fn urlencoding_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes().peekable();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(c1), Some(c2)) = (h1, h2) {
                let hex_str = [c1, c2];
                if let Ok(str_slice) = std::str::from_utf8(&hex_str)
                    && let Ok(val) = u8::from_str_radix(str_slice, 16)
                {
                    bytes.push(val);
                    continue;
                }
                bytes.push(b'%');
                bytes.push(c1);
                bytes.push(c2);
                continue;
            }
            bytes.push(b'%');
            if let Some(c1) = h1 {
                bytes.push(c1);
            }
            if let Some(c2) = h2 {
                bytes.push(c2);
            }
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless_reality_uri() {
        let uri = "vless://a1b2c3d4-e5f6-7890-1234-56789abcdef0@1.2.3.4:443?security=reality&sni=www.microsoft.com&pbk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&sid=0123456789abcdef&flow=xtls-rprx-vision#My-Reality-Node";
        let out = parse_proxy_uri(uri).unwrap();
        assert_eq!(out.tag(), "My-Reality-Node");
        match out {
            OutboundConfig::Vless {
                server,
                server_port,
                reality,
                flow,
                ..
            } => {
                assert_eq!(server, "1.2.3.4");
                assert_eq!(server_port, 443);
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
                let r = reality.unwrap();
                assert!(r.enabled);
                assert_eq!(
                    r.public_key,
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                );
                assert_eq!(r.short_id.as_deref(), Some("0123456789abcdef"));
            }
            _ => panic!("expected vless outbound"),
        }
    }

    #[test]
    fn test_parse_trojan_uri() {
        let uri = "trojan://mypassword123@trojan.example.com:443?sni=trojan.example.com#Trojan-US";
        let out = parse_proxy_uri(uri).unwrap();
        assert_eq!(out.tag(), "Trojan-US");
        match out {
            OutboundConfig::Trojan {
                server,
                server_port,
                password,
                ..
            } => {
                assert_eq!(server, "trojan.example.com");
                assert_eq!(server_port, 443);
                assert_eq!(password, "mypassword123");
            }
            _ => panic!("expected trojan outbound"),
        }
    }

    #[test]
    fn test_parse_hysteria2_uri() {
        let uri = "hy2://mypassword@hy2.example.com:443?sni=hy2.example.com#Hy2-Fast";
        let out = parse_proxy_uri(uri).unwrap();
        assert_eq!(out.tag(), "Hy2-Fast");
        match out {
            OutboundConfig::Hysteria2 {
                server,
                server_port,
                password,
                ..
            } => {
                assert_eq!(server, "hy2.example.com");
                assert_eq!(server_port, Some(443));
                assert_eq!(password, "mypassword");
            }
            _ => panic!("expected hysteria2 outbound"),
        }
    }

    #[test]
    fn test_parse_tuic_uri() {
        let uri =
            "tuic://a1b2c3d4-e5f6-7890-1234-56789abcdef0:tuicpass@tuic.example.com:8443#TUIC-Node";
        let out = parse_proxy_uri(uri).unwrap();
        assert_eq!(out.tag(), "TUIC-Node");
        match out {
            OutboundConfig::Tuic {
                server,
                server_port,
                uuid,
                password,
                ..
            } => {
                assert_eq!(server, "tuic.example.com");
                assert_eq!(server_port, 8443);
                assert_eq!(uuid, "a1b2c3d4-e5f6-7890-1234-56789abcdef0");
                assert_eq!(password, "tuicpass");
            }
            _ => panic!("expected tuic outbound"),
        }
    }

    #[test]
    fn test_urlencoding_decode_utf8() {
        assert_eq!(urlencoding_decode("hello+world"), "hello world");
        assert_eq!(
            urlencoding_decode("%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82"),
            "привет"
        );
        assert_eq!(urlencoding_decode("node%201"), "node 1");
    }
}
