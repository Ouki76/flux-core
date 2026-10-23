use flux_router::{DomainMatch, PortRange, Rule};
use flux_types::{FluxError, FluxResult, NetworkType};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigFormat {
    Auto,
    Json,
    Yaml,
}

impl std::str::FromStr for ConfigFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" | "flux" | "flux-core" => Ok(Self::Auto),
            "json" | "jsonc" => Ok(Self::Json),
            "yaml" | "yml" => Ok(Self::Yaml),
            other => Err(format!(
                "unknown config format '{}' (supported: auto, json, yaml)",
                other
            )),
        }
    }
}

/// Parses a configuration string into a canonical `Config` based on the specified format.
pub fn parse_with_format(
    content: &str,
    format: ConfigFormat,
    ext_hint: Option<&str>,
) -> FluxResult<Config> {
    match format {
        ConfigFormat::Yaml => Config::from_yaml_str(content),
        ConfigFormat::Json | ConfigFormat::Auto => Config::from_str_auto(content, ext_hint),
    }
}

/// Loads a native flux-core configuration file (.json, .jsonc, .yaml, .yml)
/// with support for `$include` modular includes and env var expansion across all formats.
///
/// `format` forces the parser for the **root** file (the `--format` CLI flag);
/// `Auto` detects it from the extension. Included files are always detected from
/// their own extension, so a mixed-format tree keeps working.
pub fn load_config(path: impl AsRef<Path>, format: Option<ConfigFormat>) -> FluxResult<Config> {
    Config::load_with_includes_format(path, format.unwrap_or(ConfigFormat::Auto))
}

/// Alias for load_config.
pub fn load_any_config(path: impl AsRef<Path>, format: Option<ConfigFormat>) -> FluxResult<Config> {
    load_config(path, format)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
// Reject unknown keys: a typo (`fake_ip_range` instead of `fakeip.inet4_range`)
// used to be ignored silently, which silently disabled the feature the user
// thought they had configured.
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "include", alias = "$include")]
    pub include: Vec<String>,
    pub flux: Option<String>,
    pub log: Option<LogConfig>,
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default, deserialize_with = "deserialize_outbounds")]
    pub outbounds: Vec<OutboundConfig>,
    pub route: Option<RouteConfig>,
    pub api: Option<ApiConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    pub listen: Option<String>,
    pub secret: Option<String>,
    #[serde(default)]
    pub allow_insecure_api: bool,
}

fn deserialize_outbounds<'de, D>(deserializer: D) -> Result<Vec<OutboundConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RawOutbound {
        Uri(String),
        Structured(Box<OutboundConfig>),
    }

    let raw_list = Vec::<RawOutbound>::deserialize(deserializer)?;
    let mut result = Vec::with_capacity(raw_list.len());
    for raw in raw_list {
        match raw {
            RawOutbound::Uri(s) => {
                let out = crate::uri::parse_proxy_uri(&s).map_err(serde::de::Error::custom)?;
                result.push(out);
            }
            RawOutbound::Structured(cfg) => {
                result.push(*cfg);
            }
        }
    }
    Ok(result)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    pub level: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// Address to serve DNS on (e.g. `127.0.0.1:5353`). When set, a DNS inbound
    /// is started; with `fakeip.enabled` it hands out fake addresses so that
    /// domain-based routing also works for applications that resolve names
    /// themselves.
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub servers: Vec<String>,
    pub fakeip: Option<FakeIpConfig>,
    #[serde(default)]
    pub client_subnet: Option<String>,
    #[serde(default)]
    pub rules: Vec<DnsRuleConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsRuleConfig {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default)]
    pub client_subnet: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeIpConfig {
    pub enabled: Option<bool>,
    /// IPv4 range handed out for fake addresses (default `198.18.0.0/15`).
    #[serde(default)]
    pub inet4_range: Option<String>,
    /// IPv6 range for fake `AAAA` answers (default `fc00::/18`).
    ///
    /// Set to `"off"`/`"none"`/`"disabled"`/`""` to answer `AAAA` with NODATA
    /// instead. Without this field an `AAAA` query could never be served, which
    /// made half of the fake-IP implementation unreachable from configuration.
    #[serde(default)]
    pub inet6_range: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SocksUserConfig {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SystemInboundConfig {
    #[serde(rename = "tun")]
    Tun {
        tag: String,
        #[serde(default)]
        interface_name: Option<String>,
        #[serde(default)]
        mtu: Option<usize>,
    },
    #[serde(rename = "mixed")]
    Mixed {
        tag: String,
        listen: String,
        listen_port: u16,
        #[serde(default)]
        users: Vec<SocksUserConfig>,
        #[serde(default)]
        rate_limit: Option<RateLimitConfig>,
    },
    #[serde(rename = "redirect")]
    Redirect {
        tag: String,
        listen: String,
        listen_port: u16,
    },
    #[serde(rename = "tproxy")]
    Tproxy {
        tag: String,
        listen: String,
        listen_port: u16,
    },
    /// WireGuard / AmneziaWG server-side inbound (L3 tunnel over UDP).
    #[serde(rename = "wireguard")]
    WireGuard {
        tag: String,
        listen: String,
        listen_port: u16,
        /// Server static private key (32-byte hex or base64).
        private_key: String,
        /// Authorized peers; at least one is required.
        peers: Vec<WireGuardPeerConfig>,
        /// Inner IP MTU (default: 1420).
        #[serde(default)]
        mtu: Option<usize>,
        /// AmneziaWG obfuscation parameters (must match the peer's config).
        #[serde(default)]
        awg: Option<flux_protocol::wireguard::AwgConfig>,
    },
}

/// An authorized WireGuard peer of a server inbound.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireGuardPeerConfig {
    /// Peer static public key (32-byte hex or base64).
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// Allowed inner source IPs for this peer (CIDR). Empty = allow any.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

impl SystemInboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Tun { tag, .. }
            | Self::Mixed { tag, .. }
            | Self::Redirect { tag, .. }
            | Self::Tproxy { tag, .. }
            | Self::WireGuard { tag, .. } => tag,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InboundConfig {
    Node(Box<LayeredInboundNode>),
    System(SystemInboundConfig),
}

impl InboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Node(node) => &node.tag,
            Self::System(sys) => sys.tag(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CarrierConfig {
    #[serde(rename = "tcp")]
    Tcp {
        #[serde(default)]
        address: Option<String>,
        #[serde(default)]
        server: Option<String>,
        #[serde(default)]
        port: Option<u16>,
    },
    #[serde(rename = "udp")]
    Udp {
        #[serde(default)]
        address: Option<String>,
        #[serde(default)]
        server: Option<String>,
        #[serde(default)]
        port: Option<u16>,
    },
    /// Xray's mKCP: a reliable byte stream over UDP.
    #[serde(rename = "kcp", alias = "mkcp")]
    Kcp {
        #[serde(default)]
        address: Option<String>,
        #[serde(default)]
        server: Option<String>,
        #[serde(default)]
        port: Option<u16>,
        /// Conversation id. Omitted (or 0) means "pick one", and for a server it
        /// means "adopt whatever the peer chooses", which is what a real peer does.
        #[serde(default)]
        conv: Option<u16>,
        #[serde(default = "default_kcp_mtu")]
        mtu: usize,
        #[serde(default = "default_kcp_wnd")]
        snd_wnd: u16,
        #[serde(default = "default_kcp_wnd")]
        rcv_wnd: u16,
        #[serde(default = "default_kcp_interval")]
        interval_ms: u32,
        #[serde(default = "default_kcp_resend")]
        resend: u32,
        /// Header camouflage. Xray calls these `header-*`; `srtp` is the common one.
        #[serde(default = "default_kcp_header")]
        header: String,
    },
}

fn default_kcp_mtu() -> usize {
    1350
}
fn default_kcp_wnd() -> u16 {
    512
}
fn default_kcp_interval() -> u32 {
    10
}
fn default_kcp_resend() -> u32 {
    2
}
fn default_kcp_header() -> String {
    "srtp".to_string()
}

impl CarrierConfig {
    /// Builds the mKCP configuration for this carrier, if it is one.
    pub fn as_kcp(&self) -> FluxResult<Option<flux_transport::KcpConfig>> {
        let CarrierConfig::Kcp {
            conv,
            mtu,
            snd_wnd,
            rcv_wnd,
            interval_ms,
            resend,
            header,
            ..
        } = self
        else {
            return Ok(None);
        };
        let obfs = match header.to_ascii_lowercase().as_str() {
            "none" => flux_transport::KcpObfs::None,
            "srtp" => flux_transport::KcpObfs::Srtp,
            "utp" => flux_transport::KcpObfs::Utp,
            "wechat-video" | "wechatvideo" | "wechat" => flux_transport::KcpObfs::WechatVideo,
            "dtls" => flux_transport::KcpObfs::Dtls,
            "wireguard" | "wg" => flux_transport::KcpObfs::Wireguard,
            other => {
                return Err(FluxError::Config(format!(
                    "unknown kcp header '{other}'; expected none, srtp, utp, wechat-video, \
                     dtls or wireguard (Xray's seed/AES-GCM masks are not implemented)"
                )));
            }
        };
        Ok(Some(flux_transport::KcpConfig {
            conv: conv.unwrap_or(0) as u32,
            mtu: *mtu,
            snd_wnd: *snd_wnd,
            rcv_wnd: *rcv_wnd,
            interval_ms: *interval_ms,
            resend: *resend,
            no_congestion: true,
            obfs,
        }))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InboundCarrierConfig {
    #[serde(rename = "tcp")]
    Tcp {
        #[serde(default)]
        listen: Option<String>,
        #[serde(default)]
        listen_port: Option<u16>,
        #[serde(default)]
        address: Option<String>,
    },
    #[serde(rename = "udp")]
    Udp {
        #[serde(default)]
        listen: Option<String>,
        #[serde(default)]
        listen_port: Option<u16>,
        #[serde(default)]
        address: Option<String>,
    },
    /// Accepted so the error can be precise: the *client* side of mKCP works and is
    /// interoperable with Xray, but serving mKCP needs every inbound to accept an
    /// already-established stream instead of binding a TCP listener itself. Until
    /// that exists, saying so beats the untagged-enum message a user would otherwise
    /// get.
    #[serde(rename = "kcp", alias = "mkcp")]
    Kcp {
        #[serde(default)]
        listen: Option<String>,
        #[serde(default)]
        listen_port: Option<u16>,
        #[serde(default)]
        address: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SecurityConfig {
    #[serde(rename = "tls")]
    Tls {
        #[serde(default)]
        sni: Option<String>,
        #[serde(default)]
        alpn: Vec<String>,
        #[serde(default)]
        insecure: bool,
        #[serde(default)]
        utls: Option<String>,
        /// PEM file(s) with extra trust anchors, appended to the built-in roots.
        /// A private CA should be pinned here rather than disabling verification
        /// with `insecure: true`.
        #[serde(default)]
        ca_cert_path: Vec<String>,
    },
    #[serde(rename = "reality")]
    Reality {
        #[serde(default)]
        sni: Option<String>,
        public_key: String,
        #[serde(default)]
        short_id: Option<String>,
    },
    #[serde(rename = "shadowtls")]
    ShadowTls {
        /// Only v3 is implemented; anything else is refused at load time rather
        /// than silently served as v3.
        #[serde(default = "default_shadowtls_version")]
        version: u8,
        password: String,
        sni: String,
    },
    #[serde(rename = "fragment")]
    Fragment {
        #[serde(default = "default_length_min")]
        length_min: usize,
        #[serde(default = "default_length_max")]
        length_max: usize,
        #[serde(default = "default_interval_ms")]
        interval_ms: u64,
    },
}

/// ShadowTLS is only implemented at v3; this is the default when the config omits
/// the field, and any other value is rejected when the instance is built.
fn default_shadowtls_version() -> u8 {
    3
}

fn default_length_min() -> usize {
    1
}
fn default_length_max() -> usize {
    3
}
fn default_interval_ms() -> u64 {
    10
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InboundSecurityConfig {
    #[serde(rename = "tls")]
    Tls {
        #[serde(default)]
        server_name: Option<String>,
        #[serde(default)]
        certificate_path: Option<String>,
        #[serde(default)]
        key_path: Option<String>,
    },
    #[serde(rename = "reality")]
    Reality {
        server_names: Vec<String>,
        private_key: String,
        short_ids: Vec<String>,
        #[serde(default)]
        fallback: Option<String>,
    },
    #[serde(rename = "shadowtls")]
    ShadowTls {
        /// Only v3 is implemented; anything else is refused at load time.
        #[serde(default = "default_shadowtls_version")]
        version: u8,
        password: String,
        fallback: String,
        /// Cover host names this server will accept in the SNI. Empty disables
        /// the check (the previous behaviour); a configured list is fail-closed.
        #[serde(default)]
        server_names: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FramingConfig {
    #[serde(rename = "ws", alias = "websocket")]
    WebSocket {
        #[serde(default = "default_ws_path")]
        path: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    #[serde(rename = "httpupgrade", alias = "upgrade")]
    HttpUpgrade {
        #[serde(default = "default_ws_path")]
        path: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    #[serde(rename = "h2", alias = "http2")]
    Http2 {
        #[serde(default = "default_ws_path")]
        path: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    #[serde(rename = "grpc", alias = "gun")]
    Grpc {
        #[serde(default = "default_grpc_service")]
        service_name: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

fn default_ws_path() -> String {
    "/".into()
}
fn default_grpc_service() -> String {
    "GunService".into()
}

fn default_hy2_mbps() -> u64 {
    100
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InboundFramingConfig {
    #[serde(rename = "ws", alias = "websocket")]
    WebSocket {
        #[serde(default)]
        path: Option<String>,
    },
    #[serde(rename = "httpupgrade", alias = "upgrade")]
    HttpUpgrade {
        #[serde(default)]
        path: Option<String>,
    },
    #[serde(rename = "h2", alias = "http2")]
    Http2,
    #[serde(rename = "grpc", alias = "gun")]
    Grpc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProtocolConfig {
    #[serde(rename = "vless")]
    Vless {
        uuid: String,
        #[serde(default)]
        flow: Option<String>,
    },
    #[serde(rename = "shadowsocks", alias = "ss")]
    Shadowsocks {
        password: String,
        #[serde(default)]
        method: Option<String>,
    },
    #[serde(rename = "trojan")]
    Trojan { password: String },
    #[serde(rename = "vmess")]
    Vmess {
        uuid: String,
        #[serde(default)]
        security: Option<String>,
    },
    #[serde(rename = "socks", alias = "socks5")]
    Socks {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    #[serde(rename = "http")]
    Http {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    #[serde(rename = "wireguard", alias = "awg")]
    WireGuard {
        private_key: String,
        peer_public_key: String,
        #[serde(default)]
        preshared_key: Option<String>,
        /// Local tunnel IP used as source of encapsulated packets (e.g. "10.0.0.2").
        #[serde(default)]
        local_address: Option<String>,
        /// Persistent NAT keepalive interval in seconds (0 disables). Default: 25.
        #[serde(default)]
        keepalive_secs: Option<u64>,
        #[serde(default)]
        awg: Option<flux_protocol::wireguard::AwgConfig>,
    },
    #[serde(rename = "hysteria2", alias = "hy2")]
    Hysteria2 {
        password: String,
        #[serde(default = "default_hy2_mbps")]
        up_mbps: u64,
        #[serde(default = "default_hy2_mbps")]
        down_mbps: u64,
        #[serde(default)]
        hop_interval_secs: Option<u64>,
        /// Optional: authentication is always HTTP/3, so `true` is accepted (it
        /// states what the code does) and `false` is refused (it asks for
        /// something the implementation cannot do). Omitting it is fine.
        #[serde(default)]
        h3: Option<bool>,
        /// Salamander obfuscation mode ("salamander"); requires obfs_password.
        #[serde(default)]
        obfs: Option<String>,
        #[serde(default)]
        obfs_password: Option<String>,
    },
    #[serde(rename = "tuic", alias = "tuic5")]
    Tuic {
        uuid: String,
        password: String,
        #[serde(default)]
        congestion_control: Option<String>,
        #[serde(default)]
        zero_rtt: Option<bool>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FlexibleList<T> {
    Single(T),
    Multiple(Vec<T>),
}

impl<T> FlexibleList<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::Single(item) => vec![item],
            Self::Multiple(items) => items,
        }
    }

    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::Single(item) => std::slice::from_ref(item),
            Self::Multiple(items) => items.as_slice(),
        }
    }
}

/// Stream multiplexing for a node (sing-box compatible smux).
///
/// Off by default: enabling it changes the wire format, so both peers must
/// agree on it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiplexConfig {
    /// Enable multiplexing for this node.
    #[serde(default)]
    pub enabled: bool,
    /// Multiplex protocol. Only "smux" is implemented.
    #[serde(default = "default_mux_protocol")]
    pub protocol: String,
    /// Streams carried by one physical connection (0 = unlimited).
    ///
    /// Outbound: pooling target - another session is opened when one is full.
    /// Inbound: hard cap per session, excess streams are refused.
    #[serde(default = "default_mux_max_streams")]
    pub max_streams: u32,
    /// Client: pad the session preface and the first writes.
    /// Inbound: require the client to pad.
    #[serde(default)]
    pub padding: bool,
    /// Client: maximum number of physical sessions kept open (default 4).
    #[serde(default)]
    pub max_connections: Option<u32>,
    /// NOP keepalive interval in seconds (default 30, 0 disables).
    #[serde(default)]
    pub keepalive_secs: Option<u64>,
    /// Close a session that has had no streams for this many seconds
    /// (default 300, 0 disables).
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
}

fn default_mux_protocol() -> String {
    "smux".into()
}

fn default_mux_max_streams() -> u32 {
    128
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: default_mux_protocol(),
            max_streams: default_mux_max_streams(),
            padding: false,
            max_connections: None,
            keepalive_secs: None,
            idle_timeout_secs: None,
        }
    }
}

impl MultiplexConfig {
    /// Builds the runtime settings, or `None` when multiplexing is disabled.
    pub fn build(&self) -> FluxResult<Option<flux_protocol::mux::MuxConfig>> {
        if !self.enabled {
            return Ok(None);
        }
        let protocol = flux_protocol::mux::MuxProtocol::parse(&self.protocol).ok_or_else(|| {
            FluxError::Config(format!(
                "multiplex: unsupported protocol '{}' (only 'smux' is implemented)",
                self.protocol
            ))
        })?;
        let defaults = flux_protocol::mux::MuxConfig::default();
        let config = flux_protocol::mux::MuxConfig {
            protocol,
            max_streams: self.max_streams,
            max_connections: self.max_connections.unwrap_or(defaults.max_connections),
            padding: self.padding,
            keepalive: match self.keepalive_secs {
                Some(0) => None,
                Some(secs) => Some(std::time::Duration::from_secs(secs)),
                None => defaults.keepalive,
            },
            idle_timeout: match self.idle_timeout_secs {
                Some(0) => None,
                Some(secs) => Some(std::time::Duration::from_secs(secs)),
                None => defaults.idle_timeout,
            },
            ..defaults
        };
        config.validate()?;
        Ok(Some(config))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayeredOutboundNode {
    pub tag: String,
    pub carrier: CarrierConfig,
    pub protocol: ProtocolConfig,
    #[serde(default)]
    pub security: Option<FlexibleList<SecurityConfig>>,
    #[serde(default)]
    pub framing: Option<FlexibleList<FramingConfig>>,
    /// Optional stream multiplexing (off by default).
    #[serde(default)]
    pub multiplex: Option<MultiplexConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayeredInboundNode {
    pub tag: String,
    pub carrier: InboundCarrierConfig,
    pub protocol: ProtocolConfig,
    #[serde(default)]
    pub security: Option<FlexibleList<InboundSecurityConfig>>,
    #[serde(default)]
    pub framing: Option<FlexibleList<InboundFramingConfig>>,
    /// Optional connection rate limiting (DoS hardening for public listeners).
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Optional stream multiplexing (off by default).
    #[serde(default)]
    pub multiplex: Option<MultiplexConfig>,
}

/// Per-inbound connection rate limiting: per-IP token bucket + global cap.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Sustained new connections per second allowed per client IP (0/absent = unlimited).
    #[serde(default)]
    pub max_conn_per_ip_per_sec: Option<u32>,
    /// Burst allowance per client IP (default: max(rate, 1) * 2).
    #[serde(default)]
    pub burst: Option<u32>,
    /// Global concurrent connection cap for this inbound (0/absent = unlimited).
    #[serde(default)]
    pub max_concurrent: Option<u32>,
}

impl RateLimitConfig {
    pub fn build(&self) -> Arc<flux_common::RateLimiter> {
        let rate = self.max_conn_per_ip_per_sec.unwrap_or(0);
        let burst = self
            .burst
            .unwrap_or_else(|| rate.max(1).saturating_mul(2))
            .max(1);
        flux_common::RateLimiter::new(rate, burst, self.max_concurrent.unwrap_or(0))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum OutboundGroupConfig {
    #[serde(rename = "direct")]
    Direct {
        tag: String,
        #[serde(default)]
        tls_fragment: Option<flux_transport::fragment::FragmentationConfig>,
    },
    #[serde(rename = "block")]
    Block { tag: String },
    #[serde(rename = "selector")]
    Selector {
        tag: String,
        outbounds: Vec<String>,
        #[serde(default)]
        default: Option<String>,
    },
    #[serde(rename = "urltest")]
    UrlTest {
        tag: String,
        outbounds: Vec<String>,
        #[serde(default)]
        url: Option<String>,
        #[serde(default)]
        interval: Option<String>,
        #[serde(default)]
        tolerance: Option<u64>,
    },
    #[serde(rename = "fallback")]
    Fallback {
        tag: String,
        outbounds: Vec<String>,
        #[serde(default)]
        url: Option<String>,
        #[serde(default)]
        interval: Option<String>,
    },
    #[serde(rename = "loadbalance")]
    LoadBalance {
        tag: String,
        outbounds: Vec<String>,
        #[serde(default)]
        strategy: Option<String>,
    },
}

impl OutboundGroupConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Direct { tag, .. }
            | Self::Block { tag }
            | Self::Selector { tag, .. }
            | Self::UrlTest { tag, .. }
            | Self::Fallback { tag, .. }
            | Self::LoadBalance { tag, .. } => tag,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OutboundConfig {
    Node(Box<LayeredOutboundNode>),
    Group(OutboundGroupConfig),
}

impl OutboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Node(node) => &node.tag,
            Self::Group(group) => group.tag(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteConfig {
    #[serde(default)]
    pub geoip_path: Option<String>,
    #[serde(default)]
    pub rule_set: Vec<RuleSetConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(rename = "final")]
    pub final_outbound: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleSetConfig {
    pub tag: String,
    /// "local" (default, file at `path`), "inline" (embedded lists) or
    /// "remote" (http(s) URL at `path`, fetched in the background).
    #[serde(rename = "type")]
    pub set_type: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    /// Optional periodic refresh interval for remote rule sets (e.g. "24h", "30m").
    #[serde(default)]
    pub update_interval: Option<String>,
    /// Optional disk cache file for remote rule sets: the last successfully
    /// fetched content is applied instantly at startup, before any network
    /// fetch completes. Default:
    /// `$XDG_CACHE_HOME/flux-core/rulesets/<tag>-<urlhash>.txt`
    #[serde(default)]
    pub cache_path: Option<String>,
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrManyString {
    One(String),
    Many(Vec<String>),
}

fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<OneOrManyString>::deserialize(deserializer)?;
    Ok(match opt {
        Some(OneOrManyString::One(s)) => vec![s],
        Some(OneOrManyString::Many(v)) => v,
        None => vec![],
    })
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrManyU16 {
    One(u16),
    Many(Vec<u16>),
}

fn deserialize_port_list<'de, D>(deserializer: D) -> Result<Vec<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<OneOrManyU16>::deserialize(deserializer)?;
    Ok(match opt {
        Some(OneOrManyU16::One(p)) => vec![p],
        Some(OneOrManyU16::Many(v)) => v,
        None => vec![],
    })
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub inbound: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub domain: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub domain_suffix: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub domain_keyword: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub ip_cidr: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_port_list")]
    pub port: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub port_range: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub rule_set: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub geosite: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub geoip: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub process_name: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub network: Vec<String>,
    #[serde(default)]
    pub invert: bool,
    pub outbound: String,
}

impl RuleConfig {
    pub fn to_rule(&self) -> FluxResult<Rule> {
        let mut domains = Vec::new();
        for d in &self.domain {
            domains.push(DomainMatch::exact(d));
        }
        for s in &self.domain_suffix {
            domains.push(DomainMatch::suffix(s));
        }
        for k in &self.domain_keyword {
            domains.push(DomainMatch::keyword(k));
        }

        let mut ip_cidrs = Vec::new();
        for cidr_str in &self.ip_cidr {
            let cidr: IpNet = cidr_str
                .parse()
                .map_err(|e| FluxError::Config(format!("invalid ip_cidr {}: {}", cidr_str, e)))?;
            ip_cidrs.push(cidr);
        }

        let mut rule_sets = self.rule_set.clone();
        rule_sets.extend(self.geosite.clone());
        let mut geoip_codes = Vec::new();

        for g in &self.geoip {
            if g == "private" {
                for priv_cidr in &[
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10",
                ] {
                    if let Ok(c) = priv_cidr.parse::<IpNet>() {
                        ip_cidrs.push(c);
                    }
                }
            } else {
                rule_sets.push(g.clone());
                geoip_codes.push(g.clone());
            }
        }

        let mut ports: Vec<PortRange> = self.port.iter().map(|&p| PortRange::single(p)).collect();
        for pr in &self.port_range {
            if let Some((s, e)) = pr.split_once(':').or_else(|| pr.split_once('-')) {
                let start = s.trim().parse::<u16>().map_err(|_| {
                    FluxError::Config(format!("invalid port_range '{}': bad start port", pr))
                })?;
                let end = e.trim().parse::<u16>().map_err(|_| {
                    FluxError::Config(format!("invalid port_range '{}': bad end port", pr))
                })?;
                if start > end {
                    return Err(FluxError::Config(format!(
                        "invalid port_range '{}': start {start} is greater than end {end}",
                        pr
                    )));
                }
                ports.push(PortRange::range(start, end));
            } else {
                let p = pr.trim().parse::<u16>().map_err(|_| {
                    FluxError::Config(format!("invalid port_range '{}': expected N or A-B", pr))
                })?;
                ports.push(PortRange::single(p));
            }
        }

        let mut networks = Vec::new();
        for net_str in &self.network {
            match net_str.to_ascii_lowercase().as_str() {
                "tcp" => networks.push(NetworkType::Tcp),
                "udp" => networks.push(NetworkType::Udp),
                other => {
                    return Err(FluxError::Config(format!(
                        "unsupported network type '{}' in rule",
                        other
                    )));
                }
            }
        }

        let mut rule = Rule {
            inbound_tags: self.inbound.clone(),
            networks,
            domains,
            ip_cidrs,
            ports,
            rule_set: rule_sets,
            geoip: geoip_codes,
            process_name: self.process_name.clone(),
            invert: self.invert,
            outbound: self.outbound.clone(),
            ..Default::default()
        };
        rule.compile_cidrs();
        Ok(rule)
    }
}

/// Like [`try_expand_env_vars`], but leaves comment lines untouched.
///
/// YAML comments begin with `#`; expanding them made a commented-out
/// `# secret: ${DB_PASS}` abort the load when `DB_PASS` was unset.
fn expand_env_vars_skipping_comments(raw: &str) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    for line in raw.split_inclusive('\n') {
        if line.trim_start().starts_with('#') {
            out.push_str(line);
        } else {
            out.push_str(&try_expand_env_vars(line)?);
        }
    }
    Ok(out)
}

/// Expands `${VAR}` and `${VAR:-default}` in the text; `$$` unescapes to `$`.
///
/// An undefined variable **without** a default is a configuration error: silently
/// substituting `""` turns a typo into a working-looking config with an empty
/// secret or password.
pub fn try_expand_env_vars(input: &str) -> Result<String, String> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'$') {
                chars.next();
                result.push('$');
                continue;
            }
            if chars.peek() == Some(&'{') {
                chars.next();
                let mut var_expr = String::new();
                let mut closed = false;
                for vc in chars.by_ref() {
                    if vc == '}' {
                        closed = true;
                        break;
                    }
                    var_expr.push(vc);
                }
                if !closed {
                    return Err(format!("unterminated ${{...}} in config: ${{{var_expr}"));
                }
                if let Some((var_name, default_val)) = var_expr.split_once(":-") {
                    if var_name.is_empty() {
                        return Err(
                            "empty environment variable name in ${:-default} in config".to_string()
                        );
                    }
                    if default_val.contains("${") {
                        return Err(format!(
                            "nested environment variable defaults are not supported: ${{{var_expr}}}"
                        ));
                    }
                    let val = std::env::var(var_name).unwrap_or_default();
                    if val.is_empty() {
                        result.push_str(default_val);
                    } else {
                        result.push_str(&val);
                    }
                } else {
                    match std::env::var(&var_expr) {
                        Ok(v) => result.push_str(&v),
                        Err(_) => {
                            return Err(format!(
                                "undefined environment variable ${{{var_expr}}} in config \
                                 (use ${{{var_expr}:-default}} to provide a fallback)"
                            ));
                        }
                    }
                }
            } else {
                result.push('$');
            }
        } else {
            result.push(c);
        }
    }
    Ok(result)
}

/// Lenient variant used by callers that cannot propagate an error.
pub fn expand_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'$') {
                // Escaped $$
                chars.next();
                result.push('$');
                continue;
            }

            if chars.peek() == Some(&'{') {
                chars.next(); // Consume '{'
                let mut var_expr = String::new();
                let mut closed = false;
                for vc in chars.by_ref() {
                    if vc == '}' {
                        closed = true;
                        break;
                    }
                    var_expr.push(vc);
                }

                if closed {
                    if let Some((var_name, default_val)) = var_expr.split_once(":-") {
                        let val = std::env::var(var_name).unwrap_or_default();
                        if val.is_empty() {
                            result.push_str(default_val);
                        } else {
                            result.push_str(&val);
                        }
                    } else {
                        let val = std::env::var(&var_expr).unwrap_or_default();
                        result.push_str(&val);
                    }
                } else {
                    result.push('$');
                    result.push('{');
                    result.push_str(&var_expr);
                }
                continue;
            }

            result.push('$');
        } else {
            result.push(c);
        }
    }

    result
}

/// Strips `//` single-line and `/* ... */` multi-line comments from JSON string,
/// correctly ignoring comments inside double-quoted string literals.
pub fn strip_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;

    while i < len {
        let c = chars[i];

        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        // Not in string
        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
            continue;
        }

        if c == '/' && i + 1 < len {
            if chars[i + 1] == '/' {
                // Line comment
                i += 2;
                while i < len && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            } else if chars[i + 1] == '*' {
                // Block comment
                i += 2;
                while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2; // skip */
                continue;
            }
        }

        out.push(c);
        i += 1;
    }

    out
}

/// Rejects a key the schema does not know, at any depth.
///
/// `deny_unknown_fields` cannot be applied to serde's internally-tagged enums —
/// which is what every `carrier`/`protocol`/`security`/`framing` block is — so a
/// typo *inside* a node used to be accepted silently: `lissten_port` or `securty`
/// simply vanished and the configuration did something other than it said.
///
/// Rather than hand-maintain a schema that would drift from the structs, the parsed
/// configuration is serialised back and the two key sets are compared. Serde emits
/// exactly the keys it accepts, so the check cannot fall out of date, and it works at
/// any depth for free.
fn reject_unknown_keys(
    raw: &serde_json::Value,
    typed: &serde_json::Value,
    path: &str,
) -> FluxResult<()> {
    match (raw, typed) {
        (serde_json::Value::Object(raw_map), serde_json::Value::Object(typed_map)) => {
            for key in raw_map.keys() {
                // `$include` is accepted as an alias for `include`.
                let canonical: &str = if key == "$include" { "include" } else { key };
                if !typed_map.contains_key(canonical) && !ALWAYS_ACCEPTED_KEYS.contains(&canonical)
                {
                    let mut known: Vec<&str> = typed_map.keys().map(|s| s.as_str()).collect();
                    known.sort_unstable();
                    return Err(FluxError::Config(format!(
                        "unknown field `{key}` in {path}{}; expected one of: {}",
                        "",
                        known.join(", ")
                    )));
                }
            }
            for (key, raw_child) in raw_map {
                let canonical: &str = if key == "$include" { "include" } else { key };
                if let Some(typed_child) = typed_map.get(canonical) {
                    reject_unknown_keys(raw_child, typed_child, &format!("{path}.{key}"))?;
                }
            }
        }
        (serde_json::Value::Array(raw_items), serde_json::Value::Array(typed_items)) => {
            for (i, (raw_child, typed_child)) in
                raw_items.iter().zip(typed_items.iter()).enumerate()
            {
                reject_unknown_keys(raw_child, typed_child, &format!("{path}[{i}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Keys that are valid configuration but deliberately absent from the serialised
/// form (`#[serde(skip)]`), so the comparison above must not flag them.
const ALWAYS_ACCEPTED_KEYS: &[&str] = &[];

impl Config {
    /// Parse configuration from a JSON string (with optional comments and env vars).
    pub fn from_json_str(raw: &str) -> FluxResult<Self> {
        // Strip comments *before* expansion: expanding first made a commented-out
        // line containing `${SOME_UNSET_VAR}` abort the whole configuration.
        let stripped = strip_comments(raw);
        let expanded = try_expand_env_vars(&stripped).map_err(FluxError::Config)?;
        let cfg: Self = serde_json::from_str(&expanded)
            .map_err(|e| FluxError::Config(format!("failed to parse json config: {}", e)))?;
        // Catch keys the schema does not know, at any depth (see `reject_unknown_keys`).
        if let (Ok(raw), Ok(typed)) = (
            serde_json::from_str::<serde_json::Value>(&expanded),
            serde_json::to_value(&cfg),
        ) {
            reject_unknown_keys(&raw, &typed, "config")?;
        }
        Ok(cfg)
    }

    /// Parse configuration from a YAML string (with env vars).
    pub fn from_yaml_str(raw: &str) -> FluxResult<Self> {
        let expanded = expand_env_vars_skipping_comments(raw).map_err(FluxError::Config)?;
        let cfg: Self = serde_yaml_ng::from_str(&expanded)
            .map_err(|e| FluxError::Config(format!("failed to parse yaml config: {}", e)))?;
        // Same deep key check as the JSON path: YAML is converted to JSON so one
        // implementation covers both.
        if let (Ok(raw_v), Ok(typed)) = (
            serde_yaml_ng::from_str::<serde_json::Value>(&expanded),
            serde_json::to_value(&cfg),
        ) {
            reject_unknown_keys(&raw_v, &typed, "config")?;
        }
        Ok(cfg)
    }

    /// Auto-detect format from file extension or content and parse.
    pub fn from_str_auto(raw: &str, ext_hint: Option<&str>) -> FluxResult<Self> {
        let is_yaml = matches!(ext_hint, Some("yaml") | Some("yml"));
        if is_yaml {
            Self::from_yaml_str(raw)
        } else {
            // Try JSON first
            match Self::from_json_str(raw) {
                Ok(c) => Ok(c),
                Err(json_err) => {
                    // Try YAML fallback if JSON fails
                    Self::from_yaml_str(raw).map_err(|_| json_err)
                }
            }
        }
    }

    /// Read and parse a single configuration file, detecting the format from
    /// its extension.
    pub fn from_file(path: impl AsRef<Path>) -> FluxResult<Self> {
        Self::from_file_format(path, ConfigFormat::Auto)
    }

    /// Read and parse a single configuration file with an explicit format.
    ///
    /// `Auto` keeps extension-based detection (JSON/JSONC first, YAML fallback);
    /// `Json`/`Yaml` force the parser regardless of the file name, which is what
    /// the documented `--format` flag promises.
    pub fn from_file_format(path: impl AsRef<Path>, format: ConfigFormat) -> FluxResult<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| {
            FluxError::Config(format!("cannot read config file '{:?}': {}", path, e))
        })?;
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase());
        match format {
            ConfigFormat::Auto => Self::from_str_auto(&content, ext.as_deref()),
            ConfigFormat::Json => Self::from_json_str(&content),
            ConfigFormat::Yaml => Self::from_yaml_str(&content).map_err(|e| {
                FluxError::Config(format!(
                    "failed to parse '{:?}' as YAML (forced by --format): {}",
                    path, e
                ))
            }),
        }
    }

    /// Load configuration file and recursively merge all files specified in `include` / `$include`.
    pub fn load_with_includes(root_path: impl AsRef<Path>) -> FluxResult<Self> {
        Self::load_with_includes_format(root_path, ConfigFormat::Auto)
    }

    /// Like [`Config::load_with_includes`] but forces `format` for the root file.
    pub fn load_with_includes_format(
        root_path: impl AsRef<Path>,
        format: ConfigFormat,
    ) -> FluxResult<Self> {
        let root_path = root_path.as_ref().canonicalize().map_err(|e| {
            FluxError::Config(format!(
                "cannot canonicalize path '{:?}': {}",
                root_path.as_ref(),
                e
            ))
        })?;

        let mut visited = HashSet::new();
        visited.insert(root_path.clone());

        let mut root_config = Self::from_file_format(&root_path, format)?;
        let base_dir = root_path.parent().unwrap_or_else(|| Path::new("."));

        root_config.resolve_includes(base_dir, &mut visited)?;
        root_config.validate()?;

        Ok(root_config)
    }

    fn resolve_includes(
        &mut self,
        base_dir: &Path,
        visited: &mut HashSet<PathBuf>,
    ) -> FluxResult<()> {
        // `visited` stops cycles, but a long *chain* of includes (a1 → a2 → … → a500)
        // would still recurse once per file and can overflow the stack.
        const MAX_INCLUDE_DEPTH: usize = 32;
        if visited.len() > MAX_INCLUDE_DEPTH {
            return Err(FluxError::Config(format!(
                "include chain deeper than {MAX_INCLUDE_DEPTH} files; check for an accidental loop"
            )));
        }
        let includes = std::mem::take(&mut self.include);
        for pattern in includes {
            let full_pattern = if Path::new(&pattern).is_absolute() {
                PathBuf::from(&pattern)
            } else {
                base_dir.join(&pattern)
            };

            let pattern_str = full_pattern.to_string_lossy().into_owned();
            let mut matched_files = Vec::new();

            // A path that exists literally wins: a real file name may contain glob
            // metacharacters (`rules[1].json`), which used to be misparsed.
            if full_pattern.is_file() {
                matched_files.push(full_pattern);
            } else if pattern_str.contains('*')
                || pattern_str.contains('?')
                || pattern_str.contains('[')
            {
                match glob::glob(&pattern_str) {
                    Ok(entries) => {
                        for entry in entries {
                            match entry {
                                Ok(path) => matched_files.push(path),
                                Err(e) => {
                                    return Err(FluxError::Config(format!(
                                        "include pattern '{}': {}",
                                        pattern, e
                                    )));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        return Err(FluxError::Config(format!(
                            "invalid include pattern '{}': {}",
                            pattern, e
                        )));
                    }
                }
                if matched_files.is_empty() {
                    return Err(FluxError::Config(format!(
                        "include pattern '{}' matched no files",
                        pattern
                    )));
                }
            } else {
                // A literal path that does not exist is a typo, not a no-op.
                return Err(FluxError::Config(format!(
                    "included file '{}' does not exist (resolved to '{}')",
                    pattern, pattern_str
                )));
            }

            for file_path in matched_files {
                let canonical = match file_path.canonicalize() {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(FluxError::Config(format!(
                            "cannot canonicalize included file '{:?}': {}",
                            file_path, e
                        )));
                    }
                };

                if visited.contains(&canonical) {
                    continue; // Skip already loaded files to prevent infinite inclusion loops
                }
                visited.insert(canonical.clone());

                let mut child = Self::from_file(&canonical)?;
                let child_base_dir = canonical.parent().unwrap_or(base_dir);
                child.resolve_includes(child_base_dir, visited)?;

                self.merge(child);
            }
        }
        Ok(())
    }

    /// Merges another config into this config.
    pub fn merge(&mut self, other: Config) {
        self.inbounds.extend(other.inbounds);
        self.outbounds.extend(other.outbounds);

        if let Some(other_route) = other.route {
            if let Some(ref mut this_route) = self.route {
                this_route.rules.extend(other_route.rules);
                this_route.rule_set.extend(other_route.rule_set);
                if this_route.final_outbound.is_none() {
                    this_route.final_outbound = other_route.final_outbound;
                }
            } else {
                self.route = Some(other_route);
            }
        }

        if let Some(other_dns) = other.dns {
            if let Some(ref mut this_dns) = self.dns {
                this_dns.servers.extend(other_dns.servers);
                if this_dns.fakeip.is_none() {
                    this_dns.fakeip = other_dns.fakeip;
                }
            } else {
                self.dns = Some(other_dns);
            }
        }

        if self.log.is_none() && other.log.is_some() {
            self.log = other.log;
        }

        if self.api.is_none() && other.api.is_some() {
            self.api = other.api;
        }

        if self.flux.is_none() && other.flux.is_some() {
            self.flux = other.flux;
        }
    }

    /// Rejects configuration that parses but would not be honoured.
    ///
    /// A field that is accepted and ignored is worse than an unknown one: the user
    /// believes a feature is configured, nothing errors, and the behaviour they
    /// asked for silently does not happen. Every check below names the field and
    /// says what the code does instead.
    fn reject_unhonoured_options(&self) -> FluxResult<()> {
        // A format marker with no meaning was accepted and merged but never read.
        if let Some(flux) = &self.flux {
            // The field is a format/version marker (a native config writes
            // `"flux": "1.0"`). It is not otherwise used, so validate its shape
            // rather than accept any string: a typo here would otherwise pass.
            let looks_like_version = flux
                .trim_start_matches(['v', 'V'])
                .split('.')
                .all(|part| part.chars().all(|c| c.is_ascii_digit()) && !part.is_empty());
            if !looks_like_version && flux != "flux" && flux != "flux-core" {
                return Err(FluxError::Config(format!(
                    "config field 'flux' is a version marker such as \"1.0\", not {flux:?}"
                )));
            }
        }

        let check_protocol = |tag: &str, proto: &ProtocolConfig| -> FluxResult<()> {
            match proto {
                ProtocolConfig::Hysteria2 {
                    h3,
                    down_mbps,
                    hop_interval_secs,
                    ..
                } => {
                    // `h3: true` states what the code does (authentication is always
                    // HTTP/3), so it is accepted; `h3: false` asks for something the
                    // implementation cannot do, so it is refused rather than ignored.
                    if *h3 == Some(false) {
                        return Err(FluxError::Config(format!(
                            "outbound '{tag}': 'h3: false' is not supported — Hysteria 2 \
                             authentication is always HTTP/3"
                        )));
                    }
                    let _ = down_mbps;
                    if hop_interval_secs.is_some() {
                        return Err(FluxError::Config(format!(
                            "outbound '{tag}': 'hop_interval_secs' has no effect — a Hysteria 2 \
                             node carries a single port here, so there is nothing to hop between"
                        )));
                    }
                }
                ProtocolConfig::Tuic {
                    congestion_control,
                    zero_rtt,
                    ..
                } => {
                    if let Some(cc) = congestion_control {
                        return Err(FluxError::Config(format!(
                            "outbound '{tag}': 'congestion_control' is not implemented (QUIC \
                             congestion control is fixed); remove the field instead of \
                             believing it is set to {cc:?}"
                        )));
                    }
                    if zero_rtt.is_some() {
                        return Err(FluxError::Config(format!(
                            "outbound '{tag}': 'zero_rtt' is not implemented; remove the field"
                        )));
                    }
                }
                _ => {}
            }
            Ok(())
        };

        for out in &self.outbounds {
            if let OutboundConfig::Node(node) = out {
                check_protocol(&node.tag, &node.protocol)?;
            }
        }
        for inb in &self.inbounds {
            if let InboundConfig::Node(node) = inb {
                check_protocol(&node.tag, &node.protocol)?;
            }
        }

        // An inbound TLS 'server_name' was destructured away: the acceptor never
        // advertises an SNI list, so a config asking for one is misleading.
        for inb in &self.inbounds {
            if let InboundConfig::Node(node) = inb
                && let Some(secs) = &node.security
            {
                for sec in secs.as_slice() {
                    if let InboundSecurityConfig::Tls { server_name, .. } = sec
                        && server_name.is_some()
                    {
                        return Err(FluxError::Config(format!(
                            "inbound '{}': TLS 'server_name' is not supported — the acceptor \
                             serves one certificate and does not filter by SNI; remove the field \
                             (use ShadowTLS or REALITY 'server_names' if you need an SNI list)",
                            node.tag
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Validates the full configuration graph:
    /// - Checks for duplicate outbound and inbound tags.
    /// - Verifies that every outbound referenced in routing rules, groups, and selectors exists.
    /// - Validates UUIDs, Reality public keys, CIDRs.
    /// - Detects cycles in outbound groups (Selector, Fallback, LoadBalance).
    pub fn validate(&self) -> FluxResult<()> {
        self.reject_unhonoured_options()?;
        let mut known_outbounds = HashSet::new();
        known_outbounds.insert("direct".to_string());
        known_outbounds.insert("block".to_string());

        let mut known_inbounds = HashSet::new();

        // 1. Inbound validation
        for in_cfg in &self.inbounds {
            let tag = in_cfg.tag();
            if !known_inbounds.insert(tag.to_string()) {
                return Err(FluxError::Config(format!(
                    "duplicate inbound tag '{}'",
                    tag
                )));
            }

            if let InboundConfig::System(SystemInboundConfig::WireGuard {
                private_key,
                peers,
                ..
            }) = in_cfg
            {
                decode_key_32bytes(private_key).map_err(|e| {
                    FluxError::Config(format!(
                        "inbound '{}': invalid wireguard private_key: {}",
                        tag, e
                    ))
                })?;
                if peers.is_empty() {
                    return Err(FluxError::Config(format!(
                        "inbound '{}': wireguard requires at least one peer",
                        tag
                    )));
                }
                for (i, peer) in peers.iter().enumerate() {
                    decode_key_32bytes(&peer.public_key).map_err(|e| {
                        FluxError::Config(format!(
                            "inbound '{}': invalid wireguard peer[{}] public_key: {}",
                            tag, i, e
                        ))
                    })?;
                    if let Some(psk) = &peer.preshared_key {
                        decode_key_32bytes(psk).map_err(|e| {
                            FluxError::Config(format!(
                                "inbound '{}': invalid wireguard peer[{}] preshared_key: {}",
                                tag, i, e
                            ))
                        })?;
                    }
                    for cidr in &peer.allowed_ips {
                        cidr.parse::<ipnet::IpNet>().map_err(|e| {
                            FluxError::Config(format!(
                                "inbound '{}': invalid wireguard peer[{}] allowed_ip '{}': {}",
                                tag, i, cidr, e
                            ))
                        })?;
                    }
                }
            }
        }

        // 2. Outbound collection & leaf validation
        let mut group_edges: HashMap<String, Vec<String>> = HashMap::new();

        for out_cfg in &self.outbounds {
            let tag = out_cfg.tag();
            if tag == "direct" || tag == "block" {
                // Allowed override of default built-ins
            } else if !known_outbounds.insert(tag.to_string()) {
                return Err(FluxError::Config(format!(
                    "duplicate outbound tag '{}'",
                    tag
                )));
            }

            match out_cfg {
                OutboundConfig::Node(node) => {
                    match &node.protocol {
                        ProtocolConfig::Vless { uuid, .. } | ProtocolConfig::Vmess { uuid, .. } => {
                            Uuid::parse_str(uuid).map_err(|e| {
                                FluxError::Config(format!(
                                    "outbound '{}': invalid uuid: {}",
                                    tag, e
                                ))
                            })?;
                        }
                        _ => {}
                    }
                    if let Some(ref sec_list) = node.security {
                        for sec in sec_list.as_slice() {
                            if let SecurityConfig::Reality { public_key, .. } = sec
                                && decode_key_32bytes(public_key).is_err()
                            {
                                return Err(FluxError::Config(format!(
                                    "outbound '{}': reality public_key must be 32 bytes (64 hex characters or Base64)",
                                    tag
                                )));
                            }
                        }
                    }
                }
                OutboundConfig::Group(group) => match group {
                    OutboundGroupConfig::Selector {
                        outbounds, default, ..
                    } => {
                        if outbounds.is_empty() {
                            return Err(FluxError::Config(format!(
                                "selector '{}' must have at least one outbound candidate",
                                tag
                            )));
                        }
                        if let Some(def) = default
                            && !outbounds.contains(def)
                        {
                            return Err(FluxError::Config(format!(
                                "selector '{}': default outbound '{}' is not in candidate list",
                                tag, def
                            )));
                        }
                        group_edges.insert(tag.to_string(), outbounds.clone());
                    }
                    OutboundGroupConfig::UrlTest { outbounds, .. } => {
                        if outbounds.is_empty() {
                            return Err(FluxError::Config(format!(
                                "urltest '{}' must have at least one outbound candidate",
                                tag
                            )));
                        }
                        group_edges.insert(tag.to_string(), outbounds.clone());
                    }
                    OutboundGroupConfig::Fallback { outbounds, .. } => {
                        if outbounds.is_empty() {
                            return Err(FluxError::Config(format!(
                                "fallback '{}' must have at least one outbound candidate",
                                tag
                            )));
                        }
                        group_edges.insert(tag.to_string(), outbounds.clone());
                    }
                    OutboundGroupConfig::LoadBalance { outbounds, .. } => {
                        if outbounds.is_empty() {
                            return Err(FluxError::Config(format!(
                                "loadbalance '{}' must have at least one outbound candidate",
                                tag
                            )));
                        }
                        group_edges.insert(tag.to_string(), outbounds.clone());
                    }
                    _ => {}
                },
            }
        }

        // 3. Verify outbound references in groups
        for (group_tag, targets) in &group_edges {
            for target in targets {
                if !known_outbounds.contains(target) {
                    return Err(FluxError::Config(format!(
                        "group '{}' references non-existent outbound '{}'",
                        group_tag, target
                    )));
                }
            }
        }

        // 4. Cycle detection in outbound groups
        for start_tag in group_edges.keys() {
            let mut visited = HashSet::new();
            let mut rec_stack = HashSet::new();
            if check_cycle(start_tag, &group_edges, &mut visited, &mut rec_stack) {
                return Err(FluxError::Config(format!(
                    "cyclic dependency detected in outbound groups starting at '{}'",
                    start_tag
                )));
            }
        }

        // 5. Route validation
        if let Some(ref route) = self.route {
            let mut known_rule_sets = HashSet::new();
            for rs in &route.rule_set {
                known_rule_sets.insert(&rs.tag);
            }

            for (idx, rule) in route.rules.iter().enumerate() {
                if !known_outbounds.contains(&rule.outbound) {
                    return Err(FluxError::Config(format!(
                        "route.rules[{}]: references non-existent outbound '{}'",
                        idx, rule.outbound
                    )));
                }

                for rs_tag in &rule.rule_set {
                    if !known_rule_sets.contains(rs_tag) {
                        return Err(FluxError::Config(format!(
                            "route.rules[{}]: references unknown rule_set '{}'",
                            idx, rs_tag
                        )));
                    }
                }

                // Verify IP CIDRs parse correctly
                for cidr in &rule.ip_cidr {
                    if cidr.parse::<IpNet>().is_err() && cidr.parse::<std::net::IpAddr>().is_err() {
                        return Err(FluxError::Config(format!(
                            "route.rules[{}]: invalid IP / CIDR '{}'",
                            idx, cidr
                        )));
                    }
                }
            }

            if let Some(ref fin) = route.final_outbound
                && !known_outbounds.contains(fin)
            {
                return Err(FluxError::Config(format!(
                    "route.final references non-existent outbound '{}'",
                    fin
                )));
            }
        }

        Ok(())
    }
}

/// Decodes 32-byte key from either 64-character hex or standard/URL-safe base64.
pub fn decode_key_32bytes(s: &str) -> FluxResult<[u8; 32]> {
    let clean = s.trim();

    // 1. Try Hex (64 chars)
    if clean.len() == 64
        && let Some(bytes) = flux_types::decode_hex(clean)
        && bytes.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    // 2. Try Base64
    use base64::Engine;
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(clean)
        && bytes.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(clean)
        && bytes.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(clean)
        && bytes.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    Err(FluxError::Config(format!(
        "invalid 32-byte key (expected 64 hex characters or 32-byte base64 string): '{}'",
        clean
    )))
}

fn check_cycle(
    node: &str,
    edges: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    rec_stack: &mut HashSet<String>,
) -> bool {
    visited.insert(node.to_string());
    rec_stack.insert(node.to_string());

    if let Some(neighbors) = edges.get(node) {
        for neighbor in neighbors {
            if !visited.contains(neighbor) {
                if check_cycle(neighbor, edges, visited, rec_stack) {
                    return true;
                }
            } else if rec_stack.contains(neighbor) {
                return true;
            }
        }
    }

    rec_stack.remove(node);
    false
}

#[cfg(test)]
mod format_tests {
    use super::*;

    fn yaml_doc() -> String {
        "inbounds: []\noutbounds: [{ type: direct, tag: direct }]\n".to_string()
    }

    #[test]
    fn explicit_format_overrides_the_extension() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.txt");
        std::fs::write(&path, yaml_doc()).unwrap();

        // Forcing YAML parses a file whose extension says nothing.
        assert!(Config::from_file_format(&path, ConfigFormat::Yaml).is_ok());
        // Auto-detect also falls back to YAML.
        assert!(Config::from_file_format(&path, ConfigFormat::Auto).is_ok());
        // Forcing JSON must fail loudly instead of silently guessing.
        let err = Config::from_file_format(&path, ConfigFormat::Json).unwrap_err();
        assert!(err.to_string().contains("json"), "unexpected error: {err}");
    }

    #[test]
    fn load_config_honours_the_format_argument() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("cfg.txt");
        std::fs::write(&path, yaml_doc()).unwrap();
        assert!(load_config(&path, Some(ConfigFormat::Yaml)).is_ok());
        assert!(load_config(&path, Some(ConfigFormat::Json)).is_err());
    }

    #[test]
    fn format_from_str_round_trips() {
        for (text, expect) in [
            ("auto", ConfigFormat::Auto),
            ("json", ConfigFormat::Json),
            ("jsonc", ConfigFormat::Json),
            ("yaml", ConfigFormat::Yaml),
            ("YML", ConfigFormat::Yaml),
        ] {
            assert_eq!(text.parse::<ConfigFormat>().unwrap(), expect);
        }
        assert!("toml".parse::<ConfigFormat>().is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jsonc_with_comments() {
        let raw = r#"{
            // Log configuration
            "log": { "level": "debug" },
            /* Inbound listeners */
            "inbounds": [
                {
                    "tag": "socks-in",
                    "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": 10808 },
                    "protocol": { "type": "socks" }
                }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": {
                "rules": [
                    { "domain_suffix": [".google.com"], "outbound": "direct" }
                ],
                "final": "direct"
            }
        }"#;

        let cfg = Config::from_json_str(raw).unwrap();
        assert_eq!(cfg.inbounds.len(), 1);
        assert_eq!(cfg.outbounds.len(), 2);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_multiplex_block_parses_and_builds() {
        // YAML surface, exactly as documented for users.
        let yaml = r#"
inbounds:
  - tag: vless-in
    carrier: { type: tcp, listen: 127.0.0.1, listen_port: 8443 }
    protocol: { type: vless, uuid: "a1b2c3d4-e5f6-7890-1234-56789abcdef0" }
    multiplex: { enabled: true, protocol: smux, max_streams: 32, padding: true }
outbounds:
  - tag: node
    carrier: { type: tcp, address: 127.0.0.1:443 }
    protocol: { type: vless, uuid: "a1b2c3d4-e5f6-7890-1234-56789abcdef0" }
    multiplex: { enabled: true }
"#;
        let cfg = Config::from_yaml_str(yaml).expect("yaml config parses");
        assert!(cfg.validate().is_ok());

        let InboundConfig::Node(node) = &cfg.inbounds[0] else {
            panic!("expected a layered inbound");
        };
        let inbound_mux = node
            .multiplex
            .as_ref()
            .expect("inbound multiplex block")
            .build()
            .expect("build")
            .expect("enabled");
        assert_eq!(inbound_mux.protocol.as_str(), "smux");
        assert_eq!(inbound_mux.max_streams, 32);
        assert!(inbound_mux.padding);

        let OutboundConfig::Node(node) = &cfg.outbounds[0] else {
            panic!("expected a layered outbound");
        };
        let outbound_mux = node
            .multiplex
            .as_ref()
            .expect("outbound multiplex block")
            .build()
            .expect("build")
            .expect("enabled");
        // Defaults: 128 streams per session, no padding, keepalive on.
        assert_eq!(outbound_mux.max_streams, 128);
        assert!(!outbound_mux.padding);
        assert!(outbound_mux.keepalive.is_some());

        // Multiplexing is off unless explicitly enabled.
        let disabled = MultiplexConfig::default();
        assert!(disabled.build().expect("build").is_none());

        // Only smux exists; anything else is a config error.
        let unsupported = MultiplexConfig {
            enabled: true,
            protocol: "yamux".into(),
            ..Default::default()
        };
        assert!(unsupported.build().is_err());
    }

    #[test]
    fn test_parse_yaml_config() {
        let yaml = r#"
log:
  level: info
inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    listen_port: 7890
outbounds:
  - type: direct
    tag: direct
  - type: block
    tag: block
route:
  rules:
    - domain_keyword:
        - torrent
      outbound: block
  final: direct
"#;
        let cfg = Config::from_yaml_str(yaml).unwrap();
        assert_eq!(cfg.inbounds.len(), 1);
        assert_eq!(cfg.inbounds[0].tag(), "mixed-in");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_expand_env_vars() {
        unsafe {
            std::env::set_var("TEST_PORT_FLUX", "10809");
            std::env::set_var("TEST_HOST_FLUX", "example.com");
        }

        let input = r#"{"port": ${TEST_PORT_FLUX}, "host": "${TEST_HOST_FLUX}", "def": "${NON_EXISTENT_VAR_FLUX:-default_val}"}"#;
        let expanded = expand_env_vars(input);
        assert_eq!(
            expanded,
            r#"{"port": 10809, "host": "example.com", "def": "default_val"}"#
        );
    }

    #[test]
    fn test_validation_detects_unknown_outbound() {
        let raw = r#"{
            "inbounds": [],
            "outbounds": [
                { "type": "direct", "tag": "direct" }
            ],
            "route": {
                "rules": [
                    { "domain_suffix": [".google.com"], "outbound": "non-existent-node" }
                ]
            }
        }"#;

        let cfg = Config::from_json_str(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("references non-existent outbound 'non-existent-node'")
        );
    }

    #[test]
    fn test_validation_detects_cycle() {
        let raw = r#"{
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "selector", "tag": "groupA", "outbounds": ["groupB"] },
                { "type": "selector", "tag": "groupB", "outbounds": ["groupA"] }
            ]
        }"#;

        let cfg = Config::from_json_str(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("cyclic dependency"));
    }
}

#[cfg(test)]
mod env_expansion_tests {
    use super::*;

    #[test]
    fn undefined_variable_without_default_is_an_error() {
        let err = try_expand_env_vars("secret: ${FLUX_DEFINITELY_UNSET_XYZ}").unwrap_err();
        assert!(err.contains("undefined environment variable"), "{err}");
    }

    #[test]
    fn default_and_empty_default_are_accepted() {
        assert_eq!(
            try_expand_env_vars("${FLUX_DEFINITELY_UNSET_XYZ:-fallback}").unwrap(),
            "fallback"
        );
        assert_eq!(
            try_expand_env_vars("${FLUX_DEFINITELY_UNSET_XYZ:-}").unwrap(),
            ""
        );
    }

    #[test]
    fn dollar_escape_survives() {
        assert_eq!(try_expand_env_vars("cost $$5").unwrap(), "cost $5");
    }

    /// A commented-out line must not be expanded, or a stale
    /// `# secret: ${DB_PASS}` would abort the whole load.
    #[test]
    fn yaml_comments_are_not_expanded() {
        let yaml = "# secret: ${FLUX_DEFINITELY_UNSET_XYZ}\nlog:\n  level: info\n";
        let out = expand_env_vars_skipping_comments(yaml).unwrap();
        assert!(out.contains("${FLUX_DEFINITELY_UNSET_XYZ}"), "{out}");
    }

    #[test]
    fn json_comments_are_stripped_before_expansion() {
        let json = "{\n  // \"secret\": \"${FLUX_DEFINITELY_UNSET_XYZ}\",\n  \"log\": {\"level\": \"info\"}\n}";
        let cfg = Config::from_json_str(json).expect("commented-out variable must not fail");
        let _ = cfg;
    }
}

#[cfg(test)]
mod unknown_key_tests {
    use super::*;

    /// A misspelled key must be reported, not silently ignored — a typo used to
    /// disable the feature the user thought they had configured.
    #[test]
    fn unknown_top_level_key_is_rejected() {
        let json = r#"{"outbounds": [{"type": "direct", "tag": "direct"}], "dns_typo": {}}"#;
        let err = Config::from_json_str(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    #[test]
    fn unknown_dns_key_is_rejected() {
        let json = r#"{"outbounds": [{"type": "direct", "tag": "direct"}],
                       "dns": {"listen": "127.0.0.1:5353", "fake_ip_range": "198.18.0.0/15"}}"#;
        let err = Config::from_json_str(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    #[test]
    fn documented_keys_are_accepted() {
        let json = r#"{
            "log": {"level": "info"},
            "dns": {"listen": "127.0.0.1:5353", "servers": ["1.1.1.1"],
                    "fakeip": {"enabled": true, "inet4_range": "198.18.0.0/15"}},
            "api": {"listen": "127.0.0.1:9090", "secret": "s"},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }"#;
        Config::from_json_str(json).expect("documented keys must parse");
    }
}
