use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use flux_types::{FluxError, FluxResult};
use flux_router::{DomainMatch, PortRange, Rule};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub log: Option<LogConfig>,
    pub dns: Option<DnsConfig>,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    pub route: Option<RouteConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogConfig {
    pub level: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsConfig {
    pub fakeip: Option<FakeIpConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FakeIpConfig {
    pub enabled: Option<bool>,
    pub inet4_range: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InboundConfig {
    #[serde(rename = "socks")]
    Socks {
        tag: String,
        listen: String,
        listen_port: u16,
    },
    #[serde(rename = "http")]
    Http {
        tag: String,
        listen: String,
        listen_port: u16,
    },
    #[serde(rename = "mixed")]
    Mixed {
        tag: String,
        listen: String,
        listen_port: u16,
    },
    #[serde(rename = "vless")]
    Vless {
        tag: String,
        listen: String,
        listen_port: u16,
        #[serde(default)]
        users: Vec<VlessUserConfig>,
        tls: Option<InboundTlsConfig>,
        reality: Option<InboundRealityConfig>,
    },
    #[serde(rename = "tun")]
    Tun {
        tag: String,
        interface_name: Option<String>,
        mtu: Option<usize>,
    },
    #[serde(rename = "trojan")]
    Trojan {
        tag: String,
        listen: String,
        listen_port: u16,
        #[serde(default)]
        password: Vec<String>,
        tls: Option<InboundTlsConfig>,
    },
    #[serde(rename = "shadowsocks")]
    Shadowsocks {
        tag: String,
        listen: String,
        listen_port: u16,
        password: String,
        method: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VlessUserConfig {
    pub uuid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboundTlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub certificate_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboundRealityConfig {
    pub enabled: bool,
    pub server_names: Vec<String>,
    pub private_key: String,
    pub short_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum OutboundConfig {
    #[serde(rename = "direct")]
    Direct {
        tag: String,
    },
    #[serde(rename = "block")]
    Block {
        tag: String,
    },
    #[serde(rename = "socks")]
    Socks {
        tag: String,
        server: String,
        server_port: u16,
    },
    #[serde(rename = "http")]
    Http {
        tag: String,
        server: String,
        server_port: u16,
    },
    #[serde(rename = "vless")]
    Vless {
        tag: String,
        server: String,
        server_port: u16,
        uuid: String,
        flow: Option<String>,
        tls: Option<OutboundTlsConfig>,
        reality: Option<OutboundRealityConfig>,
    },
    #[serde(rename = "selector")]
    Selector {
        tag: String,
        outbounds: Vec<String>,
        default: Option<String>,
    },
    #[serde(rename = "urltest")]
    UrlTest {
        tag: String,
        outbounds: Vec<String>,
        url: Option<String>,
        interval: Option<String>,
        tolerance: Option<u64>,
    },
    #[serde(rename = "trojan")]
    Trojan {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        tls: Option<OutboundTlsConfig>,
    },
    #[serde(rename = "shadowsocks")]
    Shadowsocks {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        method: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboundTlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboundRealityConfig {
    pub enabled: bool,
    pub public_key: String,
    pub short_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouteConfig {
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
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default)]
    pub inbound: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub port: Vec<u16>,
    #[serde(default)]
    pub rule_set: Vec<String>,
    pub outbound: String,
}

impl RuleConfig {
    pub fn to_rule(&self) -> FluxResult<Rule> {
        let mut domains = Vec::new();
        for d in &self.domain {
            domains.push(DomainMatch::Exact(d.clone()));
        }
        for s in &self.domain_suffix {
            domains.push(DomainMatch::Suffix(s.clone()));
        }
        for k in &self.domain_keyword {
            domains.push(DomainMatch::Keyword(k.clone()));
        }

        let mut ip_cidrs = Vec::new();
        for cidr_str in &self.ip_cidr {
            let cidr: IpNet = cidr_str.parse().map_err(|e| {
                FluxError::Config(format!("invalid ip_cidr {}: {}", cidr_str, e))
            })?;
            ip_cidrs.push(cidr);
        }

        let ports = self.port.iter().map(|&p| PortRange::single(p)).collect();

        Ok(Rule {
            inbound_tags: self.inbound.clone(),
            networks: vec![],
            domains,
            ip_cidrs,
            ports,
            rule_set: self.rule_set.clone(),
            outbound: self.outbound.clone(),
        })
    }
}

impl Config {
    pub fn from_json_str(json_str: &str) -> FluxResult<Self> {
        serde_json::from_str(json_str).map_err(|e| {
            FluxError::Config(format!("failed to parse json config: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sing_box_config() {
        let raw = r#"{
            "log": { "level": "debug" },
            "inbounds": [
                { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 10808 },
                { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 1080 }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" },
                { "type": "socks", "tag": "socks-out", "server": "127.0.0.1", "server_port": 10808 }
            ],
            "route": {
                "rules": [
                    { "domain_suffix": [".google.com"], "outbound": "direct" },
                    { "port": [443], "outbound": "block" }
                ],
                "final": "direct"
            }
        }"#;

        let cfg = Config::from_json_str(raw).unwrap();
        assert_eq!(cfg.inbounds.len(), 2);
        assert_eq!(cfg.outbounds.len(), 3);
        let rules = &cfg.route.unwrap().rules;
        assert_eq!(rules.len(), 2);
    }
}
