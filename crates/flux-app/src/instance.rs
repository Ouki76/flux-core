use crate::api::{ApiServer, TrafficMeter};
use crate::config::{
    Config, InboundConfig, OutboundConfig, OutboundRealityConfig, OutboundTlsConfig,
    TransportConfig,
};
use crate::dispatcher::DefaultDispatcher;
use dashmap::DashMap;
use flux_dns::{DnsResolver, FakeIpPool};
use flux_inbound::{HttpInbound, MixedInbound, SocksInbound, VlessInbound};
use flux_outbound::{
    BlockOutbound, DirectOutbound, SelectorOutbound, SocksOutbound, UrlTestOutbound, VlessOutbound,
};
use flux_router::Router;
use flux_transport::reality::RealityClientConfig;
use flux_transport::tls::{TlsClientConfig, TlsTransport};
use flux_types::{
    Dispatcher, FluxError, FluxResult, Inbound, Outbound, OutboundLookup, SessionMeta,
    TargetAddress,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use uuid::Uuid;

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
    pub router: Arc<Router>,
    pub meter: Arc<TrafficMeter>,
    pub api_server: Option<Arc<ApiServer>>,
    pub resolver: Arc<DnsResolver>,
}

impl Instance {
    pub fn new(config: Config) -> FluxResult<Self> {
        config.validate()?;

        // 1. DNS & Fake-IP & Split-DNS
        let (fake_ip_pool, dns_servers, dns_rules, global_ecs) = if let Some(dns_cfg) = &config.dns
        {
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

            let rules = dns_cfg
                .rules
                .iter()
                .map(|r| {
                    let ecs = r
                        .client_subnet
                        .as_deref()
                        .and_then(|s| s.parse::<ipnet::IpNet>().ok());
                    flux_dns::DnsRule {
                        domains: r.domains.clone(),
                        servers: r.servers.clone(),
                        client_subnet: ecs,
                    }
                })
                .collect();

            let ecs = dns_cfg
                .client_subnet
                .as_deref()
                .and_then(|s| s.parse::<ipnet::IpNet>().ok());

            (pool, dns_cfg.servers.clone(), rules, ecs)
        } else {
            (None, vec![], vec![], None)
        };

        let resolver = Arc::new(
            DnsResolver::new(fake_ip_pool)
                .with_servers(dns_servers)
                .with_rules(dns_rules)
                .with_client_subnet(global_ecs),
        );
        let registry = Arc::new(OutboundRegistry::new());
        let meter = TrafficMeter::new();

        // 2. Outbounds - Pass 1: Leaf outbounds
        let mut group_configs = Vec::new();

        for out_cfg in config.outbounds {
            match out_cfg {
                OutboundConfig::Direct { tag, tls_fragment } => {
                    let mut out = DirectOutbound::new(tag.clone(), resolver.clone());
                    if let Some(frag) = tls_fragment {
                        out = out.with_fragmentation(frag);
                    }
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Block { tag } => {
                    let out = BlockOutbound::new(tag.clone());
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Socks {
                    tag,
                    server,
                    server_port,
                    username,
                    password,
                } => {
                    let target = TargetAddress::domain(server, server_port);
                    let mut out = SocksOutbound::new(tag.clone(), target, resolver.clone());
                    if let (Some(u), Some(p)) = (username, password) {
                        out = out.with_auth(u, p);
                    }
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Http {
                    tag,
                    server,
                    server_port,
                    username,
                    password,
                } => {
                    let target = TargetAddress::domain(server, server_port);
                    let mut out =
                        flux_outbound::HttpOutbound::new(tag.clone(), target, resolver.clone());
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
                    transport,
                } => {
                    let parsed_uuid = Uuid::parse_str(&uuid).map_err(|e| {
                        FluxError::Config(format!("invalid vless uuid {}: {}", uuid, e))
                    })?;
                    let target = TargetAddress::domain(server, server_port);
                    let dialer =
                        build_layered_dialer(target, resolver.clone(), tls, reality, transport)?;
                    let out =
                        VlessOutbound::new_with_dialer(tag.clone(), parsed_uuid, flow, dialer);
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Vmess {
                    tag,
                    server,
                    server_port,
                    uuid,
                    security,
                    tls,
                    transport,
                } => {
                    let parsed_uuid = Uuid::parse_str(&uuid).map_err(|e| {
                        FluxError::Config(format!("invalid vmess uuid {}: {}", uuid, e))
                    })?;
                    let target = TargetAddress::domain(server, server_port);
                    let dialer =
                        build_layered_dialer(target, resolver.clone(), tls, None, transport)?;
                    let out = flux_outbound::VmessOutbound::new(
                        tag.clone(),
                        parsed_uuid,
                        security.as_deref(),
                        dialer,
                    );
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Trojan {
                    tag,
                    server,
                    server_port,
                    password,
                    tls,
                    transport,
                } => {
                    let target = TargetAddress::domain(server, server_port);
                    let dialer =
                        build_layered_dialer(target, resolver.clone(), tls, None, transport)?;
                    let out = flux_outbound::TrojanOutbound::new_with_dialer(
                        tag.clone(),
                        password,
                        dialer,
                    );
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Shadowsocks {
                    tag,
                    server,
                    server_port,
                    password,
                    method,
                    tls,
                    transport,
                } => {
                    let target = TargetAddress::domain(server, server_port);
                    let dialer = build_layered_dialer(
                        target.clone(),
                        resolver.clone(),
                        tls,
                        None,
                        transport,
                    )?;
                    let cipher_kind = method
                        .as_deref()
                        .and_then(flux_protocol::shadowsocks::CipherKind::parse_str)
                        .unwrap_or_default();
                    let out = flux_outbound::ShadowsocksOutbound::new_with_dialer(
                        tag.clone(),
                        target,
                        &password,
                        resolver.clone(),
                        dialer,
                    )
                    .with_cipher_kind(cipher_kind);
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::WireGuard {
                    tag,
                    server,
                    server_port,
                    private_key,
                    peer_public_key,
                    preshared_key,
                    awg,
                } => {
                    let priv_k = crate::config::decode_key_32bytes(&private_key)?;
                    let pub_k = crate::config::decode_key_32bytes(&peer_public_key)?;
                    let psk =
                        preshared_key.and_then(|k| crate::config::decode_key_32bytes(&k).ok());
                    let target = TargetAddress::domain(server, server_port);

                    let wg_cfg = flux_protocol::wireguard::WireGuardConfig {
                        private_key: priv_k,
                        peer_public_key: pub_k,
                        preshared_key: psk,
                        server_address: target,
                        awg,
                    };
                    tracing::info!(
                        "[{}] WireGuard / AmneziaWG outbound initialized (Noise IK handshake, junk packet obfuscation)",
                        tag
                    );
                    let out = flux_outbound::WireGuardOutbound::new(
                        tag.clone(),
                        wg_cfg,
                        resolver.clone(),
                    );
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Hysteria2 {
                    tag,
                    server,
                    ports,
                    server_port,
                    password,
                    up_mbps,
                    down_mbps,
                    hop_interval_secs,
                } => {
                    let mut port_list = ports;
                    if port_list.is_empty() {
                        port_list.push(server_port.unwrap_or(443));
                    }
                    let hy2_cfg = flux_protocol::hysteria2::Hysteria2Config {
                        server,
                        ports: port_list,
                        password,
                        up_mbps,
                        down_mbps,
                        hop_interval_secs: hop_interval_secs.unwrap_or(30),
                    };
                    tracing::info!(
                        "[{}] Hysteria 2 outbound initialized (QUIC/quinn carrier, Brutal pacer, port-hopping)",
                        tag
                    );
                    let out = flux_outbound::Hysteria2Outbound::new(
                        tag.clone(),
                        hy2_cfg,
                        resolver.clone(),
                    );
                    registry.insert(tag, Arc::new(out));
                }
                OutboundConfig::Tuic {
                    tag,
                    server,
                    server_port,
                    uuid,
                    password,
                    congestion_control,
                    zero_rtt,
                } => {
                    let parsed_uuid = Uuid::parse_str(&uuid).map_err(|e| {
                        FluxError::Config(format!("invalid tuic uuid {}: {}", uuid, e))
                    })?;
                    let tuic_cfg = flux_protocol::tuic::TuicV5Config {
                        server,
                        server_port,
                        uuid: parsed_uuid,
                        password,
                        congestion_control: congestion_control.unwrap_or_else(|| "bbr".into()),
                        zero_rtt: zero_rtt.unwrap_or(true),
                    };
                    tracing::info!(
                        "[{}] TUIC v5 outbound initialized (QUIC/quinn carrier, BBR congestion control)",
                        tag
                    );
                    let out =
                        flux_outbound::TuicOutbound::new(tag.clone(), tuic_cfg, resolver.clone());
                    registry.insert(tag, Arc::new(out));
                }
                group @ OutboundConfig::Selector { .. }
                | group @ OutboundConfig::UrlTest { .. }
                | group @ OutboundConfig::Fallback { .. }
                | group @ OutboundConfig::LoadBalance { .. } => {
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
                OutboundConfig::Selector {
                    tag,
                    outbounds,
                    default,
                } => {
                    let selector =
                        SelectorOutbound::new(tag.clone(), outbounds, default, registry.clone());
                    registry.insert(tag, Arc::new(selector));
                }
                OutboundConfig::UrlTest {
                    tag,
                    outbounds,
                    url,
                    interval,
                    tolerance,
                } => {
                    let parsed_interval = interval
                        .and_then(|s| parse_duration(&s))
                        .unwrap_or(Duration::from_secs(300));
                    let parsed_tolerance = tolerance
                        .map(Duration::from_millis)
                        .unwrap_or(Duration::from_millis(50));
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
                OutboundConfig::Fallback {
                    tag,
                    outbounds,
                    url,
                    interval,
                } => {
                    let parsed_interval = interval.and_then(|s| parse_duration(&s));
                    let fallback = Arc::new(flux_outbound::FallbackOutbound::new(
                        tag.clone(),
                        outbounds,
                        url,
                        parsed_interval,
                        registry.clone(),
                    ));
                    fallback.start_probing();
                    registry.insert(tag, fallback);
                }
                OutboundConfig::LoadBalance {
                    tag,
                    outbounds,
                    strategy,
                } => {
                    let strat = strategy
                        .as_deref()
                        .map(flux_outbound::BalanceStrategy::parse_str);
                    let lb = flux_outbound::LoadBalanceOutbound::new(
                        tag.clone(),
                        outbounds,
                        strat,
                        registry.clone(),
                    );
                    registry.insert(tag, Arc::new(lb));
                }
                _ => unreachable!(),
            }
        }

        // 3. Router
        let (rules, default_outbound, rule_set_registry, geoip_reg) =
            if let Some(route_cfg) = config.route {
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
                let geo = Arc::new(flux_router::GeoIpRegistry::new());
                if let Some(ref path) = route_cfg.geoip_path {
                    let _ = geo.load(path);
                }
                (r_vec, def, reg, geo)
            } else {
                (
                    vec![],
                    "direct".into(),
                    flux_router::RuleSetRegistry::new(),
                    Arc::new(flux_router::GeoIpRegistry::new()),
                )
            };

        let router = Arc::new(
            Router::new(rules, default_outbound)
                .with_rule_sets(rule_set_registry)
                .with_geoip(geoip_reg),
        );

        // 4. Dispatcher with live traffic meter and DNS resolver for Fake-IP domain recovery
        let dispatcher = Arc::new(
            DefaultDispatcher::new(router.clone(), registry.clone())
                .with_meter(meter.clone())
                .with_resolver(resolver.clone()),
        );

        // 5. Inbounds
        let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();
        for in_cfg in config.inbounds {
            match in_cfg {
                InboundConfig::Socks {
                    tag,
                    listen,
                    listen_port,
                    users,
                } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let user_pairs = users
                        .into_iter()
                        .map(|u| (u.username, u.password))
                        .collect();
                    inbounds.push(Arc::new(
                        SocksInbound::new(tag, addr).with_users(user_pairs),
                    ));
                }
                InboundConfig::Http {
                    tag,
                    listen,
                    listen_port,
                    users,
                } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let user_pairs = users
                        .into_iter()
                        .map(|u| (u.username, u.password))
                        .collect();
                    inbounds.push(Arc::new(HttpInbound::new(tag, addr).with_users(user_pairs)));
                }
                InboundConfig::Mixed {
                    tag,
                    listen,
                    listen_port,
                    users,
                } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let user_pairs = users
                        .into_iter()
                        .map(|u| (u.username, u.password))
                        .collect();
                    inbounds.push(Arc::new(
                        MixedInbound::new(tag, addr).with_users(user_pairs),
                    ));
                }
                InboundConfig::Vless {
                    tag,
                    listen,
                    listen_port,
                    users,
                    tls,
                    reality,
                    transport,
                } => {
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
                            let (certs, key) =
                                if let (Some(cp), Some(kp)) = (&t.certificate_path, &t.key_path) {
                                    TlsTransport::load_certs_and_key(cp, kp)?
                                } else {
                                    let cert = rcgen::generate_simple_self_signed(vec![
                                        "localhost".to_string(),
                                    ])
                                    .map_err(|e| {
                                        FluxError::Crypto(format!("failed to generate cert: {}", e))
                                    })?;
                                    (
                                        vec![CertificateDer::from(cert.cert)],
                                        PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
                                    )
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
                            let pk_bytes = crate::config::decode_key_32bytes(&r.private_key)?;
                            let short_ids = r
                                .short_ids
                                .into_iter()
                                .filter_map(|s| flux_types::decode_hex(&s))
                                .collect();
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

                    let ws_path = transport.and_then(|t| {
                        if t.transport_type.eq_ignore_ascii_case("ws")
                            || t.transport_type.eq_ignore_ascii_case("websocket")
                        {
                            Some(t.path.unwrap_or_else(|| "/".into()))
                        } else {
                            None
                        }
                    });

                    inbounds.push(Arc::new(
                        VlessInbound::new(tag, addr, uuids, tls_acceptor, reality_config)
                            .with_ws_path(ws_path),
                    ));
                }
                InboundConfig::Tun {
                    tag,
                    interface_name,
                    mtu,
                } => {
                    let ifname = interface_name.unwrap_or_else(|| "tun0".into());
                    inbounds.push(Arc::new(flux_inbound::TunInbound::new(tag, ifname, mtu)));
                }
                InboundConfig::Trojan {
                    tag,
                    listen,
                    listen_port,
                    password,
                    tls,
                } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let (certs, key) = if let Some(t) = &tls
                        && let (Some(cp), Some(kp)) = (&t.certificate_path, &t.key_path)
                    {
                        TlsTransport::load_certs_and_key(cp, kp)?
                    } else {
                        let cert =
                            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                                .map_err(|e| {
                                    FluxError::Crypto(format!("failed to generate cert: {}", e))
                                })?;
                        (
                            vec![CertificateDer::from(cert.cert)],
                            PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
                        )
                    };
                    let tls_acceptor = TlsTransport::create_server_acceptor(certs, key, vec![])?;
                    inbounds.push(Arc::new(flux_inbound::TrojanInbound::new(
                        tag,
                        addr,
                        password,
                        tls_acceptor,
                    )));
                }
                InboundConfig::Shadowsocks {
                    tag,
                    listen,
                    listen_port,
                    password,
                    method,
                } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    let cipher_kind = method
                        .as_deref()
                        .and_then(flux_protocol::shadowsocks::CipherKind::parse_str)
                        .unwrap_or_default();
                    inbounds.push(Arc::new(
                        flux_inbound::ShadowsocksInbound::new(tag, addr, &password)
                            .with_cipher_kind(cipher_kind),
                    ));
                }
                InboundConfig::Redirect {
                    tag,
                    listen,
                    listen_port,
                } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    inbounds.push(Arc::new(flux_inbound::RedirectInbound::new(tag, addr)));
                }
                InboundConfig::Tproxy {
                    tag,
                    listen,
                    listen_port,
                } => {
                    let addr_str = format!("{}:{}", listen, listen_port);
                    let addr: SocketAddr = addr_str.parse().map_err(|e| {
                        FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                    })?;
                    inbounds.push(Arc::new(flux_inbound::TproxyInbound::new(tag, addr)));
                }
            }
        }

        // 6. Optional Flux Core Native API server
        let (listen_endpoint, secret_token, allow_insecure) = if let Some(ref api) = config.api
            && let Some(ref l) = api.listen
        {
            (Some(l.clone()), api.secret.clone(), api.allow_insecure_api)
        } else {
            (None, None, false)
        };

        let api_server = listen_endpoint.map(|listen_str| {
            Arc::new(
                ApiServer::new(listen_str, registry.clone(), meter.clone())
                    .with_router(router.clone())
                    .with_inbounds(inbounds.clone())
                    .with_resolver(resolver.clone())
                    .with_secret(secret_token)
                    .with_allow_insecure(allow_insecure),
            )
        });

        Ok(Self {
            inbounds,
            registry,
            dispatcher,
            router,
            meter,
            api_server,
            resolver,
        })
    }

    /// Simulates route lookup for a given session, returning `(matched_rule_outbound, final_active_node)`.
    pub fn trace_route(&self, meta: &SessionMeta) -> (String, String) {
        let effective_meta = if let flux_types::TargetAddress::Ip(sock) = &meta.destination {
            if let Some(fakeip) = self.resolver.fake_ip()
                && let Some(domain) = fakeip.lookup_domain(&sock.ip())
            {
                let mut m = meta.clone();
                m.destination = flux_types::TargetAddress::Domain(domain, sock.port());
                m
            } else {
                meta.clone()
            }
        } else {
            meta.clone()
        };

        let matched = self.router.route(&effective_meta).to_string();
        let active = if let Some(out) = self.registry.get(&matched) {
            if out.is_group() {
                out.current_selected().unwrap_or(matched.clone())
            } else {
                matched.clone()
            }
        } else {
            matched.clone()
        };
        (matched, active)
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
        for entry in self.registry.map.iter() {
            entry.value().stop();
        }
        Ok(())
    }
}

fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(rest) = s.strip_suffix('s') {
        rest.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>()
            .ok()
            .map(|m| Duration::from_secs(m * 60))
    } else if let Some(rest) = s.strip_suffix('h') {
        rest.parse::<u64>()
            .ok()
            .map(|h| Duration::from_secs(h * 3600))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

fn build_layered_dialer(
    server: TargetAddress,
    resolver: Arc<DnsResolver>,
    tls: Option<OutboundTlsConfig>,
    reality: Option<OutboundRealityConfig>,
    transport: Option<TransportConfig>,
) -> FluxResult<Arc<dyn flux_types::StreamDialer>> {
    let server_name_default = server.host();
    let tls_cfg = if let Some(t) = tls {
        if t.enabled {
            let sni = t.server_name.unwrap_or_else(|| server_name_default.clone());
            let mut cfg = TlsClientConfig::new(sni)
                .with_insecure(t.insecure)
                .with_alpn(t.alpn);
            if let Some(ref u) = t.utls
                && let Some(fp) = flux_transport::TlsFingerprint::parse_str(u)
            {
                cfg = cfg.with_fingerprint(fp);
            }
            Some(cfg)
        } else {
            None
        }
    } else {
        None
    };

    let reality_cfg = if let Some(r) = reality {
        if r.enabled {
            let pk_bytes = crate::config::decode_key_32bytes(&r.public_key)?;
            let short_id = if let Some(sid) = r.short_id {
                flux_types::decode_hex(&sid).unwrap_or_default()
            } else {
                vec![]
            };

            Some(RealityClientConfig {
                server_name: tls_cfg
                    .as_ref()
                    .map(|c| c.server_name.clone())
                    .unwrap_or(server_name_default),
                public_key: pk_bytes,
                short_id,
            })
        } else {
            None
        }
    } else {
        None
    };

    let sec = if let Some(r) = reality_cfg {
        flux_transport::pipeline::SecurityLayer::Reality(r)
    } else if let Some(t) = tls_cfg {
        flux_transport::pipeline::SecurityLayer::Tls(t)
    } else {
        flux_transport::pipeline::SecurityLayer::None
    };

    let framing = if let Some(tr) = transport {
        match tr.transport_type.to_ascii_lowercase().as_str() {
            "ws" | "websocket" => flux_transport::pipeline::FramingLayer::WebSocket {
                path: tr.path.unwrap_or_else(|| "/".into()),
                headers: tr.headers,
            },
            "httpupgrade" | "upgrade" => flux_transport::pipeline::FramingLayer::HttpUpgrade {
                path: tr.path.unwrap_or_else(|| "/".into()),
                headers: tr.headers,
            },
            "h2" | "http2" => flux_transport::pipeline::FramingLayer::Http2 {
                path: tr.path.unwrap_or_else(|| "/".into()),
                headers: tr.headers,
            },
            "grpc" | "gun" => flux_transport::pipeline::FramingLayer::Grpc {
                service_name: tr
                    .service_name
                    .or(tr.path)
                    .unwrap_or_else(|| "GunService".into()),
                headers: tr.headers,
            },
            _ => flux_transport::pipeline::FramingLayer::Raw,
        }
    } else {
        flux_transport::pipeline::FramingLayer::Raw
    };

    Ok(Arc::new(flux_outbound::LazyPipelineDialer::new(
        server, resolver, sec, framing,
    )))
}
