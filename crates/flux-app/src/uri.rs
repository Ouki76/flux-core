use crate::config::{
    CarrierConfig, FlexibleList, FramingConfig, LayeredOutboundNode, OutboundConfig,
    OutboundGroupConfig, ProtocolConfig, SecurityConfig,
};
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
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub utls: Option<String>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
    pub transport_type: Option<String>,
    pub transport_path: Option<String>,
    pub transport_service_name: Option<String>,
    pub transport_headers: HashMap<String, String>,
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
        let carrier = CarrierConfig::Tcp {
            address: None,
            server: Some(self.server),
            port: Some(self.port),
        };

        let protocol = match proto.as_str() {
            "vless" => {
                let uuid = self.auth.or(self.password).ok_or_else(|| {
                    FluxError::Config(format!("outbound '{}': missing uuid for vless", self.tag))
                })?;
                ProtocolConfig::Vless {
                    uuid,
                    flow: self.flow,
                }
            }
            "trojan" => {
                let password = self.auth.or(self.password).unwrap_or_default();
                ProtocolConfig::Trojan { password }
            }
            "ss" | "shadowsocks" => {
                let password = self.auth.or(self.password).unwrap_or_default();
                ProtocolConfig::Shadowsocks {
                    password,
                    method: self.method,
                }
            }
            "socks" | "socks5" => ProtocolConfig::Socks {
                username: self.username,
                password: self.password,
            },
            "http" | "https" => ProtocolConfig::Http {
                username: self.username,
                password: self.password,
            },
            "tuic" => {
                let uuid = self.auth.ok_or_else(|| {
                    FluxError::Config(format!("outbound '{}': missing uuid for tuic", self.tag))
                })?;
                let password = self.password.unwrap_or_default();
                ProtocolConfig::Tuic {
                    uuid,
                    password,
                    congestion_control: None,
                    zero_rtt: None,
                }
            }
            "hy2" | "hysteria2" => {
                let password = self.auth.or(self.password).unwrap_or_default();
                ProtocolConfig::Hysteria2 {
                    password,
                    up_mbps: 100,
                    down_mbps: 100,
                    hop_interval_secs: None,
                }
            }
            "direct" => {
                return Ok(OutboundConfig::Group(OutboundGroupConfig::Direct {
                    tag: self.tag,
                    tls_fragment: None,
                }));
            }
            "block" => {
                return Ok(OutboundConfig::Group(OutboundGroupConfig::Block {
                    tag: self.tag,
                }));
            }
            other => {
                tracing::warn!(
                    "unsupported protocol '{}' for outbound '{}', falling back to direct",
                    other,
                    self.tag
                );
                return Ok(OutboundConfig::Group(OutboundGroupConfig::Direct {
                    tag: self.tag,
                    tls_fragment: None,
                }));
            }
        };

        let security = if let Some(pub_k) = self.reality_public_key {
            Some(FlexibleList::Single(SecurityConfig::Reality {
                sni: self.sni,
                public_key: pub_k,
                short_id: self.reality_short_id,
            }))
        } else if self.sni.is_some() || self.insecure || !self.alpn.is_empty() {
            Some(FlexibleList::Single(SecurityConfig::Tls {
                sni: self.sni,
                alpn: self.alpn,
                insecure: self.insecure,
                utls: self.utls,
            }))
        } else {
            None
        };

        let framing = if let Some(tr_type) = self.transport_type {
            match tr_type.to_ascii_lowercase().as_str() {
                "ws" | "websocket" => Some(FlexibleList::Single(FramingConfig::WebSocket {
                    path: self.transport_path.unwrap_or_else(|| "/".into()),
                    headers: self.transport_headers,
                })),
                "httpupgrade" | "upgrade" => {
                    Some(FlexibleList::Single(FramingConfig::HttpUpgrade {
                        path: self.transport_path.unwrap_or_else(|| "/".into()),
                        headers: self.transport_headers,
                    }))
                }
                "h2" | "http2" => Some(FlexibleList::Single(FramingConfig::Http2 {
                    path: self.transport_path.unwrap_or_else(|| "/".into()),
                    headers: self.transport_headers,
                })),
                "grpc" | "gun" => Some(FlexibleList::Single(FramingConfig::Grpc {
                    service_name: self
                        .transport_service_name
                        .unwrap_or_else(|| "GunService".into()),
                    headers: self.transport_headers,
                })),
                _ => None,
            }
        } else {
            None
        };

        Ok(OutboundConfig::Node(Box::new(LayeredOutboundNode {
            tag: self.tag,
            carrier,
            protocol,
            security,
            framing,
        })))
    }
}

/// Parses standard proxy sharing links (VLESS, Trojan, Shadowsocks, SOCKS5, HTTP, Hysteria 2, TUIC)
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

    let (reality_pk, reality_sid) = if security == "reality" {
        let pk = params
            .get("pbk")
            .or_else(|| params.get("public_key"))
            .cloned()
            .ok_or_else(|| {
                FluxError::Config("missing pbk (public key) in reality vless uri".into())
            })?;
        let sid = params
            .get("sid")
            .or_else(|| params.get("short_id"))
            .cloned();
        (Some(pk), sid)
    } else {
        (None, None)
    };

    let alpn: Vec<String> = params
        .get("alpn")
        .map(|a| a.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let insecure = params
        .get("allowInsecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    ProxySpec {
        tag,
        protocol: "vless".into(),
        server: host,
        port,
        auth: Some(uuid.to_string()),
        flow,
        sni,
        insecure,
        alpn,
        utls: fp,
        reality_public_key: reality_pk,
        reality_short_id: reality_sid,
        ..Default::default()
    }
    .build()
}

fn parse_trojan_uri(uri: &str) -> FluxResult<OutboundConfig> {
    let without_scheme = uri.strip_prefix("trojan://").unwrap_or(uri);
    let (body, tag) = extract_tag(without_scheme, "trojan-node");
    let (user_host_port, query) = body.split_once('?').unwrap_or((body, ""));
    let (password, host_port) = user_host_port
        .split_once('@')
        .ok_or_else(|| FluxError::Config("missing password in trojan uri".into()))?;
    let (host, port) = parse_host_port(host_port, 443)?;

    let params = parse_query(query);
    let sni = params
        .get("sni")
        .or_else(|| params.get("peer"))
        .cloned()
        .unwrap_or_else(|| host.clone());
    let fp = params
        .get("fp")
        .cloned()
        .or_else(|| params.get("utls").cloned());
    let insecure = params
        .get("allowInsecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    ProxySpec {
        tag,
        protocol: "trojan".into(),
        server: host,
        port,
        auth: Some(password.to_string()),
        sni: Some(sni),
        insecure,
        utls: fp,
        ..Default::default()
    }
    .build()
}

fn parse_shadowsocks_uri(uri: &str) -> FluxResult<OutboundConfig> {
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
    let clean = s.trim();
    if clean.starts_with('[') {
        if let Some((h, p)) = clean.split_once("]:") {
            let port = p.parse::<u16>().map_err(|_| {
                FluxError::Config(format!("invalid port in IPv6 address: {}", clean))
            })?;
            return Ok((format!("{}]", h), port));
        } else if clean.ends_with(']') {
            return Ok((clean.to_string(), default_port));
        }
    }

    if let Some((h, p)) = clean.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|_| FluxError::Config(format!("invalid port in address: {}", clean)))?;
        Ok((h.to_string(), port))
    } else {
        Ok((clean.to_string(), default_port))
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.trim().to_string(), urlencoding_decode(v.trim()));
        }
    }
    map
}

fn decode_base64_or_plain(s: &str) -> FluxResult<String> {
    let clean = s.trim();
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(clean)
        && let Ok(decoded) = String::from_utf8(bytes)
    {
        return Ok(decoded);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(clean)
        && let Ok(decoded) = String::from_utf8(bytes)
    {
        return Ok(decoded);
    }
    Ok(clean.to_string())
}

pub fn urlencoding_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
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
            OutboundConfig::Node(node) => {
                assert_eq!(node.tag, "My-Reality-Node");
                match node.protocol {
                    ProtocolConfig::Vless { uuid, flow } => {
                        assert_eq!(uuid, "a1b2c3d4-e5f6-7890-1234-56789abcdef0");
                        assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
                    }
                    _ => panic!("expected vless protocol"),
                }
                let sec = node.security.unwrap().into_vec().pop().unwrap();
                match sec {
                    SecurityConfig::Reality {
                        sni,
                        public_key,
                        short_id,
                    } => {
                        assert_eq!(sni.as_deref(), Some("www.microsoft.com"));
                        assert_eq!(
                            public_key,
                            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        );
                        assert_eq!(short_id.as_deref(), Some("0123456789abcdef"));
                    }
                    _ => panic!("expected reality security"),
                }
            }
            _ => panic!("expected node outbound"),
        }
    }

    #[test]
    fn test_parse_trojan_uri() {
        let uri = "trojan://mypassword123@trojan.example.com:443?sni=trojan.example.com#Trojan-US";
        let out = parse_proxy_uri(uri).unwrap();
        assert_eq!(out.tag(), "Trojan-US");
        match out {
            OutboundConfig::Node(node) => {
                assert_eq!(node.tag, "Trojan-US");
                match node.protocol {
                    ProtocolConfig::Trojan { password } => {
                        assert_eq!(password, "mypassword123");
                    }
                    _ => panic!("expected trojan protocol"),
                }
                let sec = node.security.unwrap().into_vec().pop().unwrap();
                match sec {
                    SecurityConfig::Tls { sni, .. } => {
                        assert_eq!(sni.as_deref(), Some("trojan.example.com"));
                    }
                    _ => panic!("expected tls security"),
                }
            }
            _ => panic!("expected node outbound"),
        }
    }

    #[test]
    fn test_parse_hysteria2_uri() {
        let uri = "hy2://mypassword@hy2.example.com:443?sni=hy2.example.com#Hy2-Fast";
        let out = parse_proxy_uri(uri).unwrap();
        assert_eq!(out.tag(), "Hy2-Fast");
        match out {
            OutboundConfig::Node(node) => {
                assert_eq!(node.tag, "Hy2-Fast");
                match node.protocol {
                    ProtocolConfig::Hysteria2 { password, .. } => {
                        assert_eq!(password, "mypassword");
                    }
                    _ => panic!("expected hysteria2 protocol"),
                }
            }
            _ => panic!("expected node outbound"),
        }
    }

    #[test]
    fn test_parse_tuic_uri() {
        let uri =
            "tuic://a1b2c3d4-e5f6-7890-1234-56789abcdef0:tuicpass@tuic.example.com:8443#TUIC-Node";
        let out = parse_proxy_uri(uri).unwrap();
        assert_eq!(out.tag(), "TUIC-Node");
        match out {
            OutboundConfig::Node(node) => {
                assert_eq!(node.tag, "TUIC-Node");
                match node.protocol {
                    ProtocolConfig::Tuic { uuid, password, .. } => {
                        assert_eq!(uuid, "a1b2c3d4-e5f6-7890-1234-56789abcdef0");
                        assert_eq!(password, "tuicpass");
                    }
                    _ => panic!("expected tuic protocol"),
                }
            }
            _ => panic!("expected node outbound"),
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
