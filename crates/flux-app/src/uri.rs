//! Proxy share-link parsing.
//!
//! Design: a single structural URI parser decomposes any link into
//! scheme/userinfo/host/port/query/fragment, then the query string is mapped
//! **generically** onto a typed [`UriParams`] via serde (no hand-rolled
//! per-protocol query parsers). Only userinfo semantics remain per-scheme
//! (uuid vs password vs method:password), since they are protocol-defined.

use crate::config::{
    CarrierConfig, FlexibleList, FramingConfig, LayeredOutboundNode, OutboundConfig,
    OutboundGroupConfig, ProtocolConfig, SecurityConfig,
};
use base64::Engine;
use flux_types::{FluxError, FluxResult};
use serde::Deserialize;
use std::collections::HashMap;

/// Canonical specification of a proxy outbound node built from URI links.
#[derive(Clone, Debug, Default)]
pub struct ProxySpec {
    /// The tag this node is referred to by.
    pub tag: String,
    /// Scheme, e.g. `vless`.
    pub protocol: String,
    /// Server host.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// The credential: a UUID for VLESS/VMess, a password for the rest.
    pub auth: Option<String>, // uuid for vless, password for trojan/ss
    /// Account name, for the protocols that use one.
    pub username: Option<String>, // socks/http username
    /// Password, for the protocols that use one.
    pub password: Option<String>, // socks/http/trojan password
    /// Cipher method, for Shadowsocks.
    pub method: Option<String>, // cipher method for ss
    /// Flow to request, e.g. `xtls-rprx-vision`.
    pub flow: Option<String>, // flow for vless (e.g. xtls-rprx-vision)
    /// SNI to present.
    pub sni: Option<String>,
    /// Whether certificate verification is off.
    pub insecure: bool,
    /// ALPN protocols.
    pub alpn: Vec<String>,
    /// Browser profile to imitate.
    pub utls: Option<String>,
    /// REALITY public key, when the URI names it explicitly.
    pub reality_public_key: Option<String>,
    /// REALITY short id.
    pub reality_short_id: Option<String>,
    /// Transport named in the URI, e.g. `ws`.
    pub transport_type: Option<String>,
    /// Request path for the HTTP-shaped transports.
    pub transport_path: Option<String>,
    /// gRPC service name.
    pub transport_service_name: Option<String>,
    /// Extra headers for the HTTP-shaped transports.
    pub transport_headers: HashMap<String, String>,
    /// TLS security requested explicitly (`security=tls`) or implicitly (trojan).
    pub security_hint_tls: bool,
    /// Set when the URI requested `security=reality` without a public key;
    /// `build()` turns this into a configuration error.
    pub reality_missing_pbk: bool,
    // TUIC / Hysteria 2 extras (from generic query params).
    /// Congestion-control algorithm.
    pub congestion_control: Option<String>,
    /// Advertised upload bandwidth.
    pub up_mbps: Option<u64>,
    /// Advertised download bandwidth.
    pub down_mbps: Option<u64>,
    /// Seconds between port hops.
    pub hop_interval_secs: Option<u64>,
    /// Obfuscation type, e.g. `salamander`.
    pub obfs: Option<String>,
    /// Obfuscation password.
    pub obfs_password: Option<String>,
}

/// Typed query parameters shared by all share-link dialects (Xray, sing-box,
/// Clash). Parsed generically: any `?k=v&...` query is deserialized into this
/// struct; unknown keys land in `extra` instead of being dropped.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UriParams {
    #[serde(alias = "peer")]
    /// SNI to present.
    pub sni: Option<String>,
    /// Security layer named in the URI.
    pub security: Option<String>,
    /// Flow to request, e.g. `xtls-rprx-vision`.
    pub flow: Option<String>,
    #[serde(alias = "pbk", alias = "public_key", alias = "publicKey")]
    /// Public key, for REALITY.
    pub public_key: Option<String>,
    #[serde(alias = "sid", alias = "short_id", alias = "shortId")]
    /// REALITY short id.
    pub short_id: Option<String>,
    #[serde(alias = "fp", alias = "fingerprint", alias = "utls")]
    /// Browser profile to imitate.
    pub utls: Option<String>,
    #[serde(deserialize_with = "de_comma_list")]
    /// ALPN protocols.
    pub alpn: Vec<String>,
    #[serde(
        alias = "allowInsecure",
        alias = "allow_insecure",
        alias = "skip-cert-verify",
        deserialize_with = "de_bool"
    )]
    /// Whether certificate verification is off.
    pub insecure: bool,
    /// Transport/framing selector (`ws`, `httpupgrade`, `h2`, `grpc`, ...).
    #[serde(alias = "type", alias = "transport", alias = "headerType")]
    pub transport: Option<String>,
    /// Request path for the HTTP-shaped transports.
    pub path: Option<String>,
    /// WebSocket/H2 Host header.
    pub host: Option<String>,
    #[serde(alias = "serviceName", alias = "service_name")]
    /// gRPC service name.
    pub service_name: Option<String>,
    #[serde(alias = "congestion_control", alias = "congestionControl")]
    /// Congestion-control algorithm.
    pub congestion_control: Option<String>,
    /// Hysteria 2 bandwidth hints.
    #[serde(alias = "upmbps", deserialize_with = "de_opt_u64")]
    /// Advertised upload bandwidth.
    pub up_mbps: Option<u64>,
    #[serde(alias = "downmbps", deserialize_with = "de_opt_u64")]
    /// Advertised download bandwidth.
    pub down_mbps: Option<u64>,
    /// Hysteria 2 port-hopping list ("443,8000-9000") and interval.
    pub ports: Option<String>,
    #[serde(
        alias = "hop_interval",
        alias = "hopInterval",
        deserialize_with = "de_opt_u64"
    )]
    /// Seconds between port hops.
    pub hop_interval_secs: Option<u64>,
    /// Hysteria 2 Salamander obfuscation.
    pub obfs: Option<String>,
    #[serde(alias = "obfs-password", alias = "obfsPassword")]
    /// Obfuscation password.
    pub obfs_password: Option<String>,
    /// Everything else, preserved for forward compatibility.
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

fn de_bool<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(d)?;
    Ok(match v {
        serde_json::Value::Bool(b) => b,
        serde_json::Value::String(s) => matches!(s.as_str(), "1" | "true" | "yes"),
        serde_json::Value::Number(n) => n.as_u64() == Some(1),
        _ => false,
    })
}

fn de_comma_list<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        Some(serde_json::Value::String(s)) => s.split(',').map(|p| p.trim().to_string()).collect(),
        Some(serde_json::Value::Array(a)) => a
            .into_iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    })
}

fn de_opt_u64<'de, D>(d: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    })
}

/// Structural decomposition of any `scheme://userinfo@host:port/path?query#tag` link.
#[derive(Debug)]
struct GenericUri<'a> {
    /// Owned: the scheme is lower-cased during parsing.
    scheme: String,
    userinfo: Option<&'a str>,
    host: String,
    port: Option<u16>,
    query: Option<&'a str>,
    tag: String,
}

impl<'a> GenericUri<'a> {
    fn parse(uri: &'a str) -> FluxResult<Self> {
        let clean = uri.trim();
        let (scheme, rest) = clean.split_once("://").ok_or_else(|| {
            FluxError::Config(format!("invalid proxy URI (missing scheme): {}", clean))
        })?;
        let scheme = scheme.to_ascii_lowercase();

        // Fragment = tag.
        let (body, tag) = match rest.split_once('#') {
            Some((b, t)) => {
                let decoded = urlencoding_decode(t.trim());
                (b, decoded)
            }
            None => (rest, String::new()),
        };

        // Query string.
        let (authority_path, query) = match body.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (body, None),
        };

        // Split authority from path at the first '/'.
        let authority = authority_path.split('/').next().unwrap_or(authority_path);

        // userinfo@host:port — the LAST '@' wins (passwords may contain '@').
        let (userinfo, host_port) = match authority.rsplit_once('@') {
            Some((u, hp)) => (Some(u), hp),
            None => (None, authority),
        };

        let (host, port) = split_host_port(host_port)?;
        Ok(Self {
            scheme: scheme.to_string(),
            userinfo,
            host,
            port,
            query,
            tag,
        })
    }
}

/// Splits `host:port`, `host`, `[v6]:port`, `[v6]` into (host, Option<port>).
fn split_host_port(s: &str) -> FluxResult<(String, Option<u16>)> {
    let clean = s.trim();
    if clean.is_empty() {
        return Err(FluxError::Config("empty host in proxy URI".into()));
    }
    if let Some(rest) = clean.strip_prefix('[') {
        // IPv6 literal.
        if let Some((h, tail)) = rest.split_once(']') {
            let port = match tail.strip_prefix(':') {
                Some(p) => Some(p.parse::<u16>().map_err(|_| {
                    FluxError::Config(format!("invalid port in IPv6 address: {}", clean))
                })?),
                None if tail.is_empty() => None,
                None => {
                    return Err(FluxError::Config(format!(
                        "garbage after IPv6 literal: {}",
                        clean
                    )));
                }
            };
            return Ok((format!("[{}]", h), port));
        }
        return Err(FluxError::Config(format!(
            "unterminated IPv6 literal: {}",
            clean
        )));
    }
    match clean.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !p.is_empty() => {
            // A colon that is not followed by a valid port is an error: folding it
            // into the host name produced outbounds like `host:abc` that only fail
            // much later, at connect time.
            let port = p.parse::<u16>().map_err(|_| {
                FluxError::Config(format!(
                    "invalid port '{}' in address '{}' (expected a number 0-65535)",
                    p, clean
                ))
            })?;
            Ok((h.to_string(), Some(port)))
        }
        Some((h, _)) => Ok((h.to_string(), None)),
        None => Ok((clean.to_string(), None)),
    }
}

/// Parses a query string generically into typed [`UriParams`] via serde.
fn parse_params(query: Option<&str>) -> FluxResult<UriParams> {
    let mut map = serde_json::Map::new();
    if let Some(q) = query {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let key = k.trim();
            if key.is_empty() {
                continue;
            }
            // Query values are form-encoded, so `+` does mean a space here.
            map.insert(
                key.to_string(),
                serde_json::Value::String(urlencoding_decode_query(v.trim())),
            );
        }
    }
    serde_json::from_value(serde_json::Value::Object(map))
        .map_err(|e| FluxError::Config(format!("invalid query parameters in proxy URI: {}", e)))
}

impl ProxySpec {
    /// Parses a proxy URI into its parts.
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

    /// Applies generic query parameters (security, transport, flow, ...) to the spec.
    fn apply_params(&mut self, p: &UriParams) {
        self.sni = p.sni.clone();
        self.insecure = p.insecure;
        self.alpn = p.alpn.clone();
        self.utls = p.utls.clone();
        self.flow = p.flow.clone();
        self.transport_type = p.transport.clone();
        self.transport_path = p.path.clone();
        self.transport_service_name = p.service_name.clone();
        if let Some(h) = &p.host {
            self.transport_headers.insert("Host".into(), h.clone());
        }
        if p.security.as_deref() == Some("reality") {
            // A REALITY link without `pbk` cannot authenticate the server. The
            // previous behaviour silently fell back to *no* TLS layer, i.e. a
            // plaintext VLESS/Trojan stream — the exact silent downgrade the
            // unknown-scheme branch rejects. Refuse it instead.
            match &p.public_key {
                Some(pk) if !pk.trim().is_empty() => {
                    self.reality_public_key = Some(pk.clone());
                    self.reality_short_id = p.short_id.clone();
                }
                _ => {
                    self.reality_missing_pbk = true;
                }
            }
        } else if p.security.as_deref() == Some("tls")
            || p.security.as_deref() == Some("xtls")
            || self.sni.is_some()
        {
            // plain TLS (or SNI present without explicit security) → TLS layer
            self.security_hint_tls = true;
        }
    }

    /// Builds canonical `OutboundConfig` from this proxy specification.
    pub fn build(self) -> FluxResult<OutboundConfig> {
        if self.reality_missing_pbk {
            return Err(FluxError::Config(format!(
                "outbound '{}': security=reality requires the public key (`pbk=`)",
                self.tag
            )));
        }
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
            "vmess" => {
                let uuid = self.auth.ok_or_else(|| {
                    FluxError::Config(format!("outbound '{}': missing uuid for vmess", self.tag))
                })?;
                ProtocolConfig::Vmess {
                    uuid,
                    security: self.method.clone(),
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
                    congestion_control: self.congestion_control.clone(),
                    zero_rtt: None,
                }
            }
            "hy2" | "hysteria2" => {
                let password = self.auth.or(self.password).unwrap_or_default();
                ProtocolConfig::Hysteria2 {
                    password,
                    up_mbps: self.up_mbps.unwrap_or(100),
                    down_mbps: self.down_mbps.unwrap_or(100),
                    hop_interval_secs: self.hop_interval_secs,
                    h3: Some(false),
                    obfs: self.obfs.clone(),
                    obfs_password: self.obfs_password.clone(),
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
                // Strict: an unknown protocol must never silently degrade into an
                // unproxied direct connection (traffic leak / misconfiguration risk).
                return Err(FluxError::Config(format!(
                    "unsupported protocol '{}' for outbound '{}' (supported: vless, vmess, trojan, ss/shadowsocks, socks/socks5, http/https, hy2/hysteria2, tuic, direct, block)",
                    other, self.tag
                )));
            }
        };

        let security = if let Some(pub_k) = self.reality_public_key {
            Some(FlexibleList::Single(SecurityConfig::Reality {
                sni: self.sni,
                public_key: pub_k,
                short_id: self.reality_short_id,
            }))
        } else if self.security_hint_tls || self.insecure || !self.alpn.is_empty() {
            Some(FlexibleList::Single(SecurityConfig::Tls {
                sni: self.sni,
                alpn: self.alpn,
                insecure: self.insecure,
                utls: self.utls,
                ca_cert_path: vec![],
                // URI imports do not carry a native-TLS hint; the default is rustls.
                native_tls: false,
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
            multiplex: None,
        })))
    }
}

/// Parses standard proxy sharing links into an `OutboundConfig`.
///
/// Supported schemes: `vless://`, `vmess://`, `trojan://`, `ss://`,
/// `socks5://`/`socks://`, `http://`/`https://`, `hy2://`/`hysteria2://`,
/// `tuic://`.
pub fn parse_proxy_uri(uri: &str) -> FluxResult<OutboundConfig> {
    let g = GenericUri::parse(uri)?;
    // Fragment-less links must still get distinct tags: using the bare scheme
    // made two such outbounds collide, and `validate()` then rejected the config
    // with "duplicate outbound tag".
    let tag = if g.tag.is_empty() {
        static NEXT_LINK_ID: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT_LINK_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{}-{}-{}", g.scheme, g.host, n)
    } else {
        g.tag.clone()
    };

    let default_port: u16 = match g.scheme.as_str() {
        "vless" | "trojan" | "hy2" | "hysteria2" | "https" => 443,
        "ss" | "shadowsocks" => 8388,
        "socks" | "socks5" => 1080,
        "http" => 8080,
        "tuic" => 8443,
        "vmess" => 443,
        other => {
            return Err(FluxError::Config(format!(
                "unsupported or invalid proxy URI scheme '{}://' (supported: vless, vmess, trojan, ss, socks5, http(s), hy2, tuic)",
                other
            )));
        }
    };

    // vmess:// is a base64-encoded JSON object (VMessAEAD share format).
    if g.scheme == "vmess" {
        return parse_vmess_link(uri, tag);
    }

    let params = parse_params(g.query)?;
    let port = g.port.unwrap_or(default_port);

    let mut spec = ProxySpec {
        tag,
        protocol: match g.scheme.as_str() {
            "shadowsocks" => "ss",
            "socks5" => "socks",
            "hysteria2" => "hy2",
            s => s,
        }
        .to_string(),
        server: g.host.clone(),
        port,
        congestion_control: params.congestion_control.clone(),
        up_mbps: params.up_mbps,
        down_mbps: params.down_mbps,
        hop_interval_secs: params.hop_interval_secs,
        obfs: params.obfs.clone(),
        obfs_password: params.obfs_password.clone(),
        ..Default::default()
    };
    spec.apply_params(&params);

    // Per-scheme userinfo semantics (protocol-defined, not query-generic).
    match g.scheme.as_str() {
        "vless" => {
            let uuid = g
                .userinfo
                .ok_or_else(|| FluxError::Config("missing uuid in vless uri".into()))?;
            spec.auth = Some(urlencoding_decode(uuid));
        }
        "trojan" => {
            let password = g
                .userinfo
                .ok_or_else(|| FluxError::Config("missing password in trojan uri".into()))?;
            spec.auth = Some(urlencoding_decode(password));
            // Trojan is TLS-by-definition: default SNI to the server host.
            if spec.sni.is_none() {
                spec.sni = Some(g.host.clone());
            }
            spec.security_hint_tls = true;
        }
        "ss" | "shadowsocks" => {
            // SIP002: ss://base64(method:password)@host:port
            // Legacy: ss://base64(method:password@host:port)
            let decoded_full;
            let (userinfo, host, port): (String, String, u16) = if let Some(ui) = g.userinfo {
                (
                    decode_base64_or_plain(ui)?,
                    g.host.clone(),
                    g.port.unwrap_or(default_port),
                )
            } else {
                // Legacy format: decode the whole authority body.
                let body = uri
                    .trim()
                    .split_once("://")
                    .map(|(_, r)| r)
                    .unwrap_or(uri.trim());
                let body = body.split(['?', '#']).next().unwrap_or(body);
                decoded_full = decode_base64_or_plain(body)?;
                let (ui, hp) = decoded_full
                    .rsplit_once('@')
                    .ok_or_else(|| FluxError::Config("invalid shadowsocks uri".into()))?;
                let (h, p) = split_host_port(hp)?;
                (ui.to_string(), h, p.unwrap_or(default_port))
            };
            let (method, password) = userinfo.split_once(':').ok_or_else(|| {
                FluxError::Config("invalid shadowsocks userinfo (expected method:password)".into())
            })?;
            spec.method = Some(method.to_string());
            spec.auth = Some(urlencoding_decode(password));
            spec.server = host;
            spec.port = port;
        }
        "socks" | "socks5" | "http" | "https" => {
            if let Some(userinfo) = g.userinfo {
                let (u, p) = userinfo.split_once(':').unwrap_or((userinfo, ""));
                spec.username = Some(urlencoding_decode(u));
                spec.password = Some(urlencoding_decode(p));
            }
            if g.scheme == "https" {
                // `https://` means "HTTP proxy reached over TLS". Without this
                // hint the outbound is emitted with `security: None`, i.e. a
                // cleartext HTTP proxy on port 443 that would also send
                // `Proxy-Authorization` in the clear.
                spec.security_hint_tls = true;
                if spec.sni.is_none() {
                    spec.sni = Some(g.host.clone());
                }
            }
        }
        "hy2" | "hysteria2" => {
            let password = g
                .userinfo
                .ok_or_else(|| FluxError::Config("missing password in hysteria2 uri".into()))?;
            spec.auth = Some(urlencoding_decode(password));
        }
        "tuic" => {
            let userinfo = g
                .userinfo
                .ok_or_else(|| FluxError::Config("missing userinfo in tuic uri".into()))?;
            let (uuid, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
            spec.auth = Some(urlencoding_decode(uuid));
            spec.password = Some(urlencoding_decode(password));
        }
        other => {
            return Err(FluxError::Config(format!(
                "unsupported proxy URI scheme '{}://'",
                other
            )));
        }
    }

    spec.build()
}

/// VMess share links are base64-encoded JSON (VMessAEAD format).
fn parse_vmess_link(uri: &str, default_tag: String) -> FluxResult<OutboundConfig> {
    #[derive(Deserialize)]
    struct VmessLink {
        #[serde(default)]
        ps: String,
        add: String,
        #[serde(deserialize_with = "de_port")]
        port: u16,
        id: String,
        #[serde(default)]
        scy: Option<String>,
        #[serde(default)]
        net: Option<String>,
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        tls: Option<String>,
        #[serde(default)]
        alpn: Option<String>,
    }
    fn de_port<'de, D>(d: D) -> Result<u16, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|x| u16::try_from(x).ok())
                .ok_or_else(|| serde::de::Error::custom("invalid port")),
            serde_json::Value::String(s) => s
                .trim()
                .parse()
                .map_err(|_| serde::de::Error::custom("invalid port string")),
            _ => Err(serde::de::Error::custom("missing port")),
        }
    }

    let payload = uri
        .trim()
        .strip_prefix("vmess://")
        .ok_or_else(|| FluxError::Config("invalid vmess uri".into()))?;
    let json = decode_base64_or_plain(payload)?;
    let link: VmessLink = serde_json::from_str(&json)
        .map_err(|e| FluxError::Config(format!("invalid vmess link JSON: {}", e)))?;

    let tag = if link.ps.is_empty() {
        default_tag
    } else {
        link.ps
    };

    let mut spec = ProxySpec {
        tag,
        protocol: "vmess".into(),
        server: link.add,
        port: link.port,
        auth: Some(link.id),
        method: link.scy.filter(|s| s != "auto" && !s.is_empty()),
        transport_type: link.net.filter(|n| n != "tcp" && !n.is_empty()),
        transport_path: link.path.filter(|p| !p.is_empty()),
        sni: link.sni,
        ..Default::default()
    };
    if let Some(h) = link.host.filter(|h| !h.is_empty()) {
        spec.transport_headers.insert("Host".into(), h);
    }
    if let Some(alpn) = link.alpn {
        spec.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }
    if link.tls.as_deref() == Some("tls") {
        spec.security_hint_tls = true;
    }
    spec.build()
}

/// Decodes a form-encoded **query value**, where `+` means a space.
pub fn urlencoding_decode_query(s: &str) -> String {
    urlencoding_decode(&s.replace('+', "%20"))
}

/// Decodes `%XX` escapes in a URI component.
///
/// `+` is left alone: it is only a space in form-encoded query values, and this
/// decoder is also used for userinfo (where a password may legitimately contain
/// `+`). Use [`urlencoding_decode_query`] for query values.
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
            }
            bytes.push(b'%');
            if let Some(c1) = h1 {
                bytes.push(c1);
            }
            if let Some(c2) = h2 {
                bytes.push(c2);
            }
        } else {
            // NOTE: `+` is *not* decoded to a space here. It only means "space" in
            // `application/x-www-form-urlencoded` query values, and these decoders
            // are also applied to userinfo — decoding it there silently corrupts
            // every password containing `+`.
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// `https://` proxy links must carry a TLS security layer. Emitting a
    /// cleartext HTTP proxy for an `https://` link would send
    /// `Proxy-Authorization` unprotected to port 443.
    #[test]
    fn https_proxy_link_gets_tls() {
        let out = parse_proxy_uri("https://user:pass@proxy.example:443").unwrap();
        let node = node_of(out);
        assert!(
            node.security.is_some(),
            "https:// proxy link must produce a TLS security layer, got none"
        );
    }

    /// `security=reality` without `pbk` must fail loudly rather than silently
    /// degrading to a plaintext stream.
    #[test]
    fn reality_without_public_key_is_rejected() {
        let err = parse_proxy_uri(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=example.com",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("pbk"),
            "expected a pbk error, got: {err}"
        );
    }

    fn node_of(out: OutboundConfig) -> Box<LayeredOutboundNode> {
        match out {
            OutboundConfig::Node(n) => n,
            _ => panic!("expected node outbound"),
        }
    }

    fn server_of(node: &LayeredOutboundNode) -> (String, u16) {
        match &node.carrier {
            CarrierConfig::Tcp { server, port, .. } => {
                (server.clone().unwrap_or_default(), port.unwrap_or(0))
            }
            _ => panic!("expected tcp carrier"),
        }
    }

    #[test]
    fn test_parse_vless_reality_uri() {
        let uri = "vless://a1b2c3d4-e5f6-7890-1234-56789abcdef0@1.2.3.4:443?security=reality&sni=www.microsoft.com&pbk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&sid=0123456789abcdef&flow=xtls-rprx-vision#My-Reality-Node";
        let out = parse_proxy_uri(uri).unwrap();
        let node = node_of(out);
        assert_eq!(node.tag, "My-Reality-Node");
        match node.protocol {
            ProtocolConfig::Vless { uuid, flow } => {
                assert_eq!(uuid, "a1b2c3d4-e5f6-7890-1234-56789abcdef0");
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
            }
            _ => panic!("expected vless protocol"),
        }
        match node.security.unwrap().into_vec().pop().unwrap() {
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

    #[test]
    fn test_parse_trojan_uri() {
        let uri = "trojan://mypassword123@trojan.example.com:443?sni=trojan.example.com#Trojan-US";
        let node = node_of(parse_proxy_uri(uri).unwrap());
        assert_eq!(node.tag, "Trojan-US");
        match node.protocol {
            ProtocolConfig::Trojan { password } => assert_eq!(password, "mypassword123"),
            _ => panic!("expected trojan protocol"),
        }
        match node.security.unwrap().into_vec().pop().unwrap() {
            SecurityConfig::Tls { sni, .. } => {
                assert_eq!(sni.as_deref(), Some("trojan.example.com"))
            }
            _ => panic!("expected tls security"),
        }
    }

    #[test]
    fn test_trojan_defaults_sni_to_host() {
        let node = node_of(parse_proxy_uri("trojan://pw@example.org:443").unwrap());
        match node.security.unwrap().into_vec().pop().unwrap() {
            SecurityConfig::Tls { sni, .. } => assert_eq!(sni.as_deref(), Some("example.org")),
            _ => panic!("trojan must default to TLS with host SNI"),
        }
    }

    #[test]
    fn test_parse_hysteria2_uri() {
        let uri = "hy2://mypassword@hy2.example.com:443?sni=hy2.example.com#Hy2-Fast";
        let node = node_of(parse_proxy_uri(uri).unwrap());
        assert_eq!(node.tag, "Hy2-Fast");
        match node.protocol {
            ProtocolConfig::Hysteria2 { password, .. } => assert_eq!(password, "mypassword"),
            _ => panic!("expected hysteria2 protocol"),
        }
    }

    #[test]
    fn test_parse_hysteria2_full_params() {
        let uri = "hysteria2://pw@1.2.3.4:443?obfs=salamander&obfs-password=secret&upmbps=200&downmbps=500&ports=443,8000-9000&hop_interval=15#H";
        let node = node_of(parse_proxy_uri(uri).unwrap());
        match node.protocol {
            ProtocolConfig::Hysteria2 {
                up_mbps,
                down_mbps,
                hop_interval_secs,
                obfs,
                obfs_password,
                ..
            } => {
                assert_eq!(up_mbps, 200);
                assert_eq!(down_mbps, 500);
                assert_eq!(hop_interval_secs, Some(15));
                assert_eq!(obfs.as_deref(), Some("salamander"));
                assert_eq!(obfs_password.as_deref(), Some("secret"));
            }
            _ => panic!("expected hysteria2 protocol"),
        }
    }

    #[test]
    fn test_parse_tuic_uri() {
        let uri =
            "tuic://a1b2c3d4-e5f6-7890-1234-56789abcdef0:tuicpass@tuic.example.com:8443#TUIC-Node";
        let node = node_of(parse_proxy_uri(uri).unwrap());
        match node.protocol {
            ProtocolConfig::Tuic { uuid, password, .. } => {
                assert_eq!(uuid, "a1b2c3d4-e5f6-7890-1234-56789abcdef0");
                assert_eq!(password, "tuicpass");
            }
            _ => panic!("expected tuic protocol"),
        }
    }

    #[test]
    fn test_parse_ss_sip002_base64_userinfo() {
        // SIP002: ss://base64(method:password)@host:port#tag
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("chacha20-ietf-poly1305:mypassword");
        let uri = format!("ss://{}@1.2.3.4:8388#SS-Node", ui);
        let node = node_of(parse_proxy_uri(&uri).unwrap());
        assert_eq!(node.tag, "SS-Node");
        match node.protocol {
            ProtocolConfig::Shadowsocks { password, method } => {
                assert_eq!(password, "mypassword");
                assert_eq!(method.as_deref(), Some("chacha20-ietf-poly1305"));
            }
            _ => panic!("expected shadowsocks"),
        }
    }

    #[test]
    fn test_parse_ss_legacy_full_base64() {
        // Legacy: ss://base64(method:password@host:port)#tag
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("aes-256-gcm:secretpw@example.com:443");
        let uri = format!("ss://{}#Legacy", body);
        let node = node_of(parse_proxy_uri(&uri).unwrap());
        assert_eq!(server_of(&node), ("example.com".to_string(), 443));
        match node.protocol {
            ProtocolConfig::Shadowsocks { password, method } => {
                assert_eq!(password, "secretpw");
                assert_eq!(method.as_deref(), Some("aes-256-gcm"));
            }
            _ => panic!("expected shadowsocks"),
        }
    }

    #[test]
    fn test_parse_vmess_base64_json() {
        let json = r#"{"v":"2","ps":"VMess-Node","add":"vm.example.com","port":"443","id":"a1b2c3d4-e5f6-7890-1234-56789abcdef0","aid":"0","scy":"aes-128-gcm","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"vm.example.com"}"#;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let node = node_of(parse_proxy_uri(&format!("vmess://{}", b64)).unwrap());
        assert_eq!(node.tag, "VMess-Node");
        assert_eq!(server_of(&node).0, "vm.example.com");
        match node.protocol {
            ProtocolConfig::Vmess { uuid, security } => {
                assert_eq!(uuid, "a1b2c3d4-e5f6-7890-1234-56789abcdef0");
                assert_eq!(security.as_deref(), Some("aes-128-gcm"));
            }
            _ => panic!("expected vmess"),
        }
        assert!(node.security.is_some(), "tls must be enabled");
        match node.framing.unwrap().into_vec().pop().unwrap() {
            FramingConfig::WebSocket { path, headers } => {
                assert_eq!(path, "/ws");
                assert_eq!(
                    headers.get("Host").map(|s| s.as_str()),
                    Some("cdn.example.com")
                );
            }
            _ => panic!("expected websocket framing"),
        }
    }

    #[test]
    fn test_parse_socks_and_http_with_auth() {
        let node = node_of(parse_proxy_uri("socks5://user:p%40ss@1.2.3.4:1080").unwrap());
        match node.protocol {
            ProtocolConfig::Socks { username, password } => {
                assert_eq!(username.as_deref(), Some("user"));
                assert_eq!(password.as_deref(), Some("p@ss"));
            }
            _ => panic!("expected socks"),
        }
        let node = node_of(parse_proxy_uri("http://u:p@1.2.3.4:8080").unwrap());
        match node.protocol {
            ProtocolConfig::Http { username, password } => {
                assert_eq!(username.as_deref(), Some("u"));
                assert_eq!(password.as_deref(), Some("p"));
            }
            _ => panic!("expected http"),
        }
    }

    #[test]
    fn test_password_with_at_sign() {
        // rsplit_once('@'): the LAST '@' separates userinfo from host.
        let node = node_of(parse_proxy_uri("trojan://p@ss@host.example:443").unwrap());
        match &node.protocol {
            ProtocolConfig::Trojan { password } => assert_eq!(password, "p@ss"),
            _ => panic!("expected trojan"),
        }
        assert_eq!(server_of(&node).0, "host.example");
    }

    #[test]
    fn test_ipv6_host() {
        let node = node_of(
            parse_proxy_uri("vless://a1b2c3d4-e5f6-7890-1234-56789abcdef0@[2001:db8::1]:443")
                .unwrap(),
        );
        assert_eq!(server_of(&node), ("[2001:db8::1]".to_string(), 443));
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(
            server_of(&node_of(parse_proxy_uri("trojan://pw@h.example").unwrap())).1,
            443
        );
        assert_eq!(
            server_of(&node_of(parse_proxy_uri("socks5://1.2.3.4").unwrap())).1,
            1080
        );
    }

    #[test]
    fn test_vless_ws_transport_and_alpn() {
        let uri = "vless://a1b2c3d4-e5f6-7890-1234-56789abcdef0@h.example:443?security=tls&sni=s.example&type=ws&path=%2Flive&host=cdn.example&alpn=h2,http/1.1&fp=chrome";
        let node = node_of(parse_proxy_uri(uri).unwrap());
        match node.framing.unwrap().into_vec().pop().unwrap() {
            FramingConfig::WebSocket { path, headers } => {
                assert_eq!(path, "/live");
                assert_eq!(headers.get("Host").map(|s| s.as_str()), Some("cdn.example"));
            }
            _ => panic!("expected ws framing"),
        }
        match node.security.unwrap().into_vec().pop().unwrap() {
            SecurityConfig::Tls {
                sni, alpn, utls, ..
            } => {
                assert_eq!(sni.as_deref(), Some("s.example"));
                assert_eq!(alpn, vec!["h2", "http/1.1"]);
                assert_eq!(utls.as_deref(), Some("chrome"));
            }
            _ => panic!("expected tls"),
        }
    }

    #[test]
    fn test_unknown_scheme_rejected() {
        assert!(parse_proxy_uri("foobar://x@h:1").is_err());
        assert!(parse_proxy_uri("not a uri").is_err());
        assert!(
            parse_proxy_uri("vless://@h:443").is_err() || parse_proxy_uri("vless://h:443").is_err()
        );
    }

    #[test]
    fn test_unknown_query_params_preserved_not_fatal() {
        let uri = "vless://a1b2c3d4-e5f6-7890-1234-56789abcdef0@h:443?security=tls&futureParam=xyz&sni=a.example";
        parse_proxy_uri(uri).expect("unknown params must not break parsing");
    }

    #[test]
    fn test_urlencoding_decode_utf8() {
        // `+` is literal in userinfo/fragments (a password may contain it) and a
        // space only in form-encoded query values.
        assert_eq!(urlencoding_decode("hello+world"), "hello+world");
        assert_eq!(urlencoding_decode_query("hello+world"), "hello world");
        assert_eq!(
            urlencoding_decode("%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82"),
            "привет"
        );
        assert_eq!(urlencoding_decode("node%201"), "node 1");
    }
}

#[cfg(test)]
mod parser_hardening_tests {
    use super::*;

    fn node_of(out: OutboundConfig) -> Box<LayeredOutboundNode> {
        match out {
            OutboundConfig::Node(n) => n,
            _ => panic!("expected node outbound"),
        }
    }

    /// A password containing `+` must survive the round trip intact.
    #[test]
    fn password_plus_is_not_decoded_to_space() {
        // Trojan's whole userinfo is the password (there is no username field).
        let out = parse_proxy_uri("trojan://p%2Bss+word@example.com:443#t").unwrap();
        let node = node_of(out);
        match &node.protocol {
            crate::config::ProtocolConfig::Trojan { password } => {
                assert_eq!(password, "p+ss+word", "`+` must stay literal in userinfo");
            }
            other => panic!("unexpected protocol {other:?}"),
        }
    }

    /// Two fragment-less links must get distinct tags instead of colliding.
    #[test]
    fn fragment_less_links_get_unique_tags() {
        let a = node_of(parse_proxy_uri("socks5://127.0.0.1:1080").unwrap());
        let b = node_of(parse_proxy_uri("socks5://127.0.0.1:1080").unwrap());
        assert_ne!(
            a.tag, b.tag,
            "fragment-less links must get unique tags to survive validation"
        );
    }

    /// A non-numeric port must be an error rather than being folded into the host.
    #[test]
    fn non_numeric_port_is_rejected() {
        let err = parse_proxy_uri("socks5://example.com:abc").unwrap_err();
        assert!(
            err.to_string().contains("port") || err.to_string().contains("host"),
            "unexpected error: {err}"
        );
    }
}
