use flux_router::{DomainMatch, PortRange, Rule};
use flux_types::{FluxError, FluxResult, NetworkType};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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
pub fn load_config(path: impl AsRef<Path>, _format: Option<ConfigFormat>) -> FluxResult<Config> {
    Config::load_with_includes(path)
}

/// Alias for load_config.
pub fn load_any_config(path: impl AsRef<Path>, format: Option<ConfigFormat>) -> FluxResult<Config> {
    load_config(path, format)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
pub struct LogConfig {
    pub level: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsConfig {
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
pub struct FakeIpConfig {
    pub enabled: Option<bool>,
    pub inet4_range: Option<String>,
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
}

impl SystemInboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Tun { tag, .. }
            | Self::Mixed { tag, .. }
            | Self::Redirect { tag, .. }
            | Self::Tproxy { tag, .. } => tag,
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
        version: u8,
        password: String,
        fallback: String,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayeredOutboundNode {
    pub tag: String,
    pub carrier: CarrierConfig,
    pub protocol: ProtocolConfig,
    #[serde(default)]
    pub security: Option<FlexibleList<SecurityConfig>>,
    #[serde(default)]
    pub framing: Option<FlexibleList<FramingConfig>>,
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
    #[serde(rename = "type")]
    pub set_type: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
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
                if let (Ok(start), Ok(end)) = (s.trim().parse::<u16>(), e.trim().parse::<u16>()) {
                    ports.push(PortRange::range(start, end));
                }
            } else if let Ok(p) = pr.trim().parse::<u16>() {
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

/// Expands environment variables like `${VAR}` or `${VAR:-default}` in the text.
/// `$$` is unescaped to `$`.
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

impl Config {
    /// Parse configuration from a JSON string (with optional comments and env vars).
    pub fn from_json_str(raw: &str) -> FluxResult<Self> {
        let expanded = expand_env_vars(raw);
        let stripped = strip_comments(&expanded);
        serde_json::from_str(&stripped)
            .map_err(|e| FluxError::Config(format!("failed to parse json config: {}", e)))
    }

    /// Parse configuration from a YAML string (with env vars).
    pub fn from_yaml_str(raw: &str) -> FluxResult<Self> {
        let expanded = expand_env_vars(raw);
        serde_yaml_ng::from_str(&expanded)
            .map_err(|e| FluxError::Config(format!("failed to parse yaml config: {}", e)))
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

    /// Read and parse a single configuration file.
    pub fn from_file(path: impl AsRef<Path>) -> FluxResult<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| {
            FluxError::Config(format!("cannot read config file '{:?}': {}", path, e))
        })?;
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase());
        Self::from_str_auto(&content, ext.as_deref())
    }

    /// Load configuration file and recursively merge all files specified in `include` / `$include`.
    pub fn load_with_includes(root_path: impl AsRef<Path>) -> FluxResult<Self> {
        let root_path = root_path.as_ref().canonicalize().map_err(|e| {
            FluxError::Config(format!(
                "cannot canonicalize path '{:?}': {}",
                root_path.as_ref(),
                e
            ))
        })?;

        let mut visited = HashSet::new();
        visited.insert(root_path.clone());

        let mut root_config = Self::from_file(&root_path)?;
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
        let includes = std::mem::take(&mut self.include);
        for pattern in includes {
            let full_pattern = if Path::new(&pattern).is_absolute() {
                PathBuf::from(&pattern)
            } else {
                base_dir.join(&pattern)
            };

            let pattern_str = full_pattern.to_string_lossy().into_owned();
            let mut matched_files = Vec::new();

            if pattern_str.contains('*') || pattern_str.contains('?') || pattern_str.contains('[') {
                if let Ok(entries) = glob::glob(&pattern_str) {
                    for entry in entries.flatten() {
                        matched_files.push(entry);
                    }
                }
            } else if full_pattern.is_file() {
                matched_files.push(full_pattern);
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

    /// Validates the full configuration graph:
    /// - Checks for duplicate outbound and inbound tags.
    /// - Verifies that every outbound referenced in routing rules, groups, and selectors exists.
    /// - Validates UUIDs, Reality public keys, CIDRs.
    /// - Detects cycles in outbound groups (Selector, Fallback, LoadBalance).
    pub fn validate(&self) -> FluxResult<()> {
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
