use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use dashmap::DashMap;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use uuid::Uuid;
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, Outbound, OutboundLookup, TargetAddress,
};
use flux_dns::{DnsResolver, FakeIpPool};
use flux_router::Router;
use flux_transport::tls::{TlsClientConfig, TlsTransport};
use flux_transport::reality::RealityClientConfig;
use flux_inbound::{HttpInbound, MixedInbound, SocksInbound, VlessInbound};
use flux_outbound::{
    BlockOutbound, DirectOutbound, SelectorOutbound, SocksOutbound, UrlTestOutbound, VlessOutbound,
};
use crate::api::{ApiServer, TrafficMeter};
use crate::config::{Config, InboundConfig, OutboundConfig};
use crate::dispatcher::DefaultDispatcher;

#[derive(Clone, Default)]
pub struct OutboundRegistry {
    pub map: Arc<DashMap<String, Arc<dyn Outbound>>>,
}

impl OutboundRegistry {
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
    }

    pub fn insert(&self, tag: String, outbound: Arc<dyn Outbound>) {
        self.map.insert(tag, outbound);
    }

    pub fn get_outbound(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.map.get(tag).map(|e| e.value().clone())
    }
}

impl OutboundLookup for OutboundRegistry {
    fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.map.get(tag).map(|e| e.value().clone())
    }
}

pub struct Instance {
    pub inbounds: Vec<Arc<dyn Inbound>>,
    pub registry: Arc<OutboundRegistry>,
    pub dispatcher: Arc<dyn Dispatcher>,
    pub meter: Arc<TrafficMeter>,
    pub api_server: Option<Arc<ApiServer>>,
}

impl Instance {
    pub fn new(config: Config) -> FluxResult<Self> {
        // 1. DNS & Fake-IP
        let (fake_ip_pool, dns_servers) = if let Some(dns_cfg) = &config.dns {
            let pool = if let Some(fip) = &dns_cfg.fakeip {
                if fip.enabled.unwrap_or(false) {
                    let range = fip.inet4_range.as_deref().unwrap_or("198.18.0.0/15");
                    let p = FakeIpPool::new(range, 10000).map_err(|e| {
                        FluxError::Config(format!("invalid fake-ip range {}: {}", range, e))
                    })?;
                    Some(Arc::new(p))
                } else {
                    None
                }
            } else {
                None
            };
            (pool, dns_cfg.servers.clone())
        } else {
            (None, vec![])
        };

        let resolver = Arc::new(DnsResolver::new(fake_ip_pool).with_servers(dns_servers));
        let registry = Arc::new(OutboundRegistry::new());
        let meter = TrafficMeter::new();

        // 2. Outbounds - Pass 1: Leaf outbounds
        let mut group_configs = Vec::new();

        for out_cfg in config.outbounds {
            match out_cfg {
                OutboundConfig::Direct { tag } => {
                    let out = DirectOutbound::new(tag.clone(), resolver.clone());
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Block { tag } => {
                    let out = BlockOutbound::new(tag.clone());
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Socks { tag, server, server_port, username, password } => {
                    let target = TargetAddress::domain(server, server_port);
                    let mut out = SocksOutbound::new(tag.clone(), target, resolver.clone());
                    if let (Some(u), Some(p)) = (username, password) {
                        out = out.with_auth(u, p);
                    }
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Http { tag, server, server_port, username, password } => {
                    let target = TargetAddress::domain(server, server_port);
                    let mut out = flux_outbound::HttpOutbound::new(tag.clone(), target, resolver.clone());
                    if let (Some(u), Some(p)) = (username, password) {
                        out = out.with_auth(u, p);
                    }
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Vless {
                    tag,
                    server,
                    server_port,
                    uuid,
                    flow,
                    tls,
                    reality,
                } => {
                    let parsed_uuid = Uuid::parse_str(&uuid).map_err(|e| {
                        FluxError::Config(format!("invalid vless uuid {}: {}", uuid, e))
                    })?;
                    let target = TargetAddress::domain(server.clone(), server_port);

                    let tls_cfg = if let Some(t) = tls {
                        if t.enabled {
                            let sni = t.server_name.unwrap_or(server);
                            Some(
                                TlsClientConfig::new(sni)
                                    .with_insecure(t.insecure)
                                    .with_alpn(t.alpn),
                            )
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let reality_cfg = if let Some(r) = reality {
                        if r.enabled {
                            let pk_bytes = hex_to_32bytes(&r.public_key)?;
                            let short_id = if let Some(sid) = r.short_id {
                                decode_hex(&sid).unwrap_or_default()
                            } else {
                                vec![]
                            };

                            Some(RealityClientConfig {
                                server_name: tls_cfg.as_ref().map(|c| c.server_name.clone()).unwrap_or_default(),
                                public_key: pk_bytes,
                                short_id,
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let out = VlessOutbound::new(
                        tag.clone(),
                        target,
                        parsed_uuid,
                        flow,
                        resolver.clone(),
                        tls_cfg,
                        reality_cfg,
                    );
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Trojan {
                    tag,
                    server,
                    server_port,
                    password,
                    tls,
                } => {
                    let target = TargetAddress::domain(server.clone(), server_port);
                    let tls_cfg = if let Some(t) = tls {
                        let sni = t.server_name.unwrap_or(server);
                        TlsClientConfig::new(sni)
                            .with_insecure(t.insecure)
                            .with_alpn(t.alpn)
                    } else {
                        TlsClientConfig::new(server)
                    };

                    let out = flux_outbound::TrojanOutbound::new(
                        tag.clone(),
                        target,
                        password,
                        resolver.clone(),
                        tls_cfg,
                    );
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Shadowsocks {
                    tag,
                    server,
                    server_port,
                    password,
                    method,
                } => {
                    let target = TargetAddress::domain(server, server_port);
                    let cipher_kind = method.as_deref().and_then(flux_protocol::shadowsocks::CipherKind::parse_str).unwrap_or_default();
                    let out = flux_outbound::ShadowsocksOutbound::new(
                        tag.clone(),
                        target,
                        &password,
                        resolver.clone(),
                    ).with_cipher_kind(cipher_kind);
                    registry.insert(tag, Arc::new(out));
                }
                group @ OutboundConfig::Selector { .. } | group @ OutboundConfig::UrlTest { .. } => {
                    group_configs.push(group);
                }
            }
        }

        // Ensure default "direct" exists if not explicitly defined
        if registry.get("direct").is_none() {
            registry.insert(
                "direct".into(),
                Arc::new(DirectOutbound::new("direct", resolver.clone())),
            );
        }

        // Pass 2: Group outbounds (selector, urltest)
        for group in group_configs {
            match group {
                OutboundConfig::Selector { tag, outbounds, default } => {
                    let selector = SelectorOutbound::new(tag.clone(), outbounds, default, registry.clone());
                    registry.insert(tag, Arc::new(selector));
                }
                OutboundConfig::UrlTest { tag, outbounds, url, interval, tolerance } => {
                    let parsed_interval = interval.and_then(|s| parse_duration(&s)).unwrap_or(Duration::from_secs(300));
                    let parsed_tolerance = tolerance.map(Duration::from_millis).unwrap_or(Duration::from_millis(50));
                    let urltest = Arc::new(UrlTestOutbound::new(
                        tag.clone(),
                        outbounds,
                        url,
                        Some(parsed_interval),
                        Some(parsed_tolerance),
                        registry.clone(),
                    ));
                    urltest.start_probing();
                    registry.insert(tag, urltest);
                }
                _ => unreachable!(),
            }
        }

        // 3. Router
        let (rules, default_outbound, rule_set_registry) = if let Some(route_cfg) = config.route {
            let mut reg = flux_router::RuleSetRegistry::new();
            for rs_cfg in route_cfg.rule_set {
                let rs = flux_router::RuleSet {
                    tag: rs_cfg.tag,
                    path: rs_cfg.path,
                    ip_cidr: rs_cfg.ip_cidr,
                    domain: rs_cfg.domain,
                    domain_suffix: rs_cfg.domain_suffix,
                    domain_keyword: rs_cfg.domain_keyword,
                    ..Default::default()
                };
                reg.insert(rs);
            }
            let mut r_vec = Vec::new();
            for r in route_cfg.rules {
                r_vec.push(r.to_rule()?);
            }
            let def = route_cfg.final_outbound.unwrap_or_else(|| "direct".into());
            (r_vec, def, reg)
        } else {
            (vec![], "direct".into(), flux_router::RuleSetRegistry::new())
        };

        let router = Arc::new(Router::new(rules, default_outbound).with_rule_sets(rule_set_registry));

        // 4. Dispatcher with live traffic meter
        let dispatcher = Arc::new(DefaultDispatcher::new(router, registry.clone()).with_meter(meter.clone()));

        // 5. Inbounds
        let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();
        for in_cfg in config.inbounds {
            match in_cfg {
                InboundConfig::Socks { tag, listen, listen_port, users } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let user_pairs = users.into_iter().map(|u| (u.username, u.password)).collect();
                    inbounds.push(Arc::new(SocksInbound::new(tag, addr).with_users(user_pairs)));
                }
                InboundConfig::Http { tag, listen, listen_port, users } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let user_pairs = users.into_iter().map(|u| (u.username, u.password)).collect();
                    inbounds.push(Arc::new(HttpInbound::new(tag, addr).with_users(user_pairs)));
                }
                InboundConfig::Mixed { tag, listen, listen_port, users } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let user_pairs = users.into_iter().map(|u| (u.username, u.password)).collect();
                    inbounds.push(Arc::new(MixedInbound::new(tag, addr).with_users(user_pairs)));
                }
                InboundConfig::Vless { tag, listen, listen_port, users, tls, reality } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;

                    let mut uuids = Vec::new();
                    for u in users {
                        let parsed = Uuid::parse_str(&u.uuid).map_err(|e| {
                            FluxError::Config(format!("invalid vless uuid {}: {}", u.uuid, e))
                        })?;
                        uuids.push(parsed);
                    }

                    let tls_acceptor = if let Some(t) = tls {
                        if t.enabled {
                            let (certs, key) = if let (Some(cp), Some(kp)) = (&t.certificate_path, &t.key_path) {
                                TlsTransport::load_certs_and_key(cp, kp)?
                            } else {
                                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                                    .map_err(|e| FluxError::Crypto(format!("failed to generate cert: {}", e)))?;
                                (vec![CertificateDer::from(cert.cert)], PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()))
                            };
                            Some(TlsTransport::create_server_acceptor(certs, key, vec![])?)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let reality_config = if let Some(r) = reality {
                        if r.enabled {
                            let pk_bytes = hex_to_32bytes(&r.private_key)?;
                            let short_ids = r.short_ids.into_iter().filter_map(|s| decode_hex(&s)).collect();
                            Some(flux_transport::reality::RealityServerConfig {
                                server_names: r.server_names,
                                private_key: pk_bytes,
                                short_ids,
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    inbounds.push(Arc::new(VlessInbound::new(tag, addr, uuids, tls_acceptor, reality_config)));
                }
                InboundConfig::Tun { tag, interface_name, mtu } => {
                    let ifname = interface_name.unwrap_or_else(|| "tun0".into());
                    inbounds.push(Arc::new(flux_inbound::TunInbound::new(tag, ifname, mtu)));
                }
                InboundConfig::Trojan { tag, listen, listen_port, password, tls } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let (certs, key) = if let Some(t) = &tls
                        && let (Some(cp), Some(kp)) = (&t.certificate_path, &t.key_path)
                    {
                        TlsTransport::load_certs_and_key(cp, kp)?
                    } else {
                        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                            .map_err(|e| FluxError::Crypto(format!("failed to generate cert: {}", e)))?;
                        (vec![CertificateDer::from(cert.cert)], PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()))
                    };
                    let tls_acceptor = TlsTransport::create_server_acceptor(certs, key, vec![])?;
                    inbounds.push(Arc::new(flux_inbound::TrojanInbound::new(tag, addr, password, tls_acceptor)));
                }
                InboundConfig::Shadowsocks { tag, listen, listen_port, password, method } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let cipher_kind = method.as_deref().and_then(flux_protocol::shadowsocks::CipherKind::parse_str).unwrap_or_default();
                    inbounds.push(Arc::new(flux_inbound::ShadowsocksInbound::new(tag, addr, &password).with_cipher_kind(cipher_kind)));
                }
            }
        }

        // 6. Optional Clash REST API server
        let api_server = if let Some(exp) = config.experimental
            && let Some(clash_api) = exp.clash_api
            && let Some(ctrl) = clash_api.external_controller
        {
            let api_addr: SocketAddr = ctrl.parse().map_err(|e| {
                FluxError::Config(format!("invalid external_controller address {}: {}", ctrl, e))
            })?;
            Some(Arc::new(ApiServer::new(api_addr, registry.clone(), meter.clone())))
        } else {
            None
        };

        Ok(Self {
            inbounds,
            registry,
            dispatcher,
            meter,
            api_server,
        })
    }

    pub async fn start(&self) -> FluxResult<()> {
        if let Some(api) = &self.api_server {
            api.start().await?;
        }
        for inbound in &self.inbounds {
            inbound.start(self.dispatcher.clone()).await?;
        }
        Ok(())
    }

    pub async fn stop(&self) -> FluxResult<()> {
        if let Some(api) = &self.api_server {
            api.stop().await?;
        }
        for inbound in &self.inbounds {
            inbound.stop().await?;
        }
        Ok(())
    }
}

fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(rest) = s.strip_suffix('s') {
        rest.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60))
    } else if let Some(rest) = s.strip_suffix('h') {
        rest.parse::<u64>().ok().map(|h| Duration::from_secs(h * 3600))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let clean = s.trim();
    if !clean.len().is_multiple_of(2) {
        return None;
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
        .collect()
}

fn hex_to_32bytes(s: &str) -> FluxResult<[u8; 32]> {
    let clean = s.trim();
    let bytes = if let Some(h) = decode_hex(clean) {
        h
    } else {
        return Err(FluxError::Config(format!("invalid hex string: {}", clean)));
    };

    if bytes.len() != 32 {
        return Err(FluxError::Config(format!(
            "public key must be 32 bytes (64 hex characters), got {} bytes",
            bytes.len()
        )));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
