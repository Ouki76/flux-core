use crate::api::{ApiServer, TrafficMeter};
use crate::config::{
    CarrierConfig, Config, FlexibleList, FramingConfig, InboundCarrierConfig, InboundConfig,
    InboundFramingConfig, InboundSecurityConfig, LayeredInboundNode, LayeredOutboundNode,
    OutboundConfig, OutboundGroupConfig, ProtocolConfig, SecurityConfig, SystemInboundConfig,
};
use crate::dispatcher::DefaultDispatcher;
use dashmap::DashMap;
use flux_dns::{DnsResolver, FakeIpPool};
use flux_inbound::MixedInbound;
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
                OutboundConfig::Node(node) => {
                    build_layered_outbound(*node, &registry, &resolver)?;
                }
                OutboundConfig::Group(group) => match group {
                    OutboundGroupConfig::Direct { tag, tls_fragment } => {
                        let mut out = DirectOutbound::new(tag.clone(), resolver.clone());
                        if let Some(frag) = tls_fragment {
                            out = out.with_fragmentation(frag);
                        }
                        registry.insert(tag, Arc::new(out));
                    }
                    OutboundGroupConfig::Block { tag } => {
                        let out = BlockOutbound::new(tag.clone());
                        registry.insert(tag, Arc::new(out));
                    }
                    g @ OutboundGroupConfig::Selector { .. }
                    | g @ OutboundGroupConfig::UrlTest { .. }
                    | g @ OutboundGroupConfig::Fallback { .. }
                    | g @ OutboundGroupConfig::LoadBalance { .. } => {
                        group_configs.push(g);
                    }
                },
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
                OutboundGroupConfig::Selector {
                    tag,
                    outbounds,
                    default,
                } => {
                    let selector =
                        SelectorOutbound::new(tag.clone(), outbounds, default, registry.clone());
                    registry.insert(tag, Arc::new(selector));
                }
                OutboundGroupConfig::UrlTest {
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
                OutboundGroupConfig::Fallback {
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
                OutboundGroupConfig::LoadBalance {
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
                InboundConfig::Node(node) => {
                    build_layered_inbound(*node, &mut inbounds)?;
                }
                InboundConfig::System(sys) => match sys {
                    SystemInboundConfig::Tun {
                        tag,
                        interface_name,
                        mtu,
                    } => {
                        let ifname = interface_name.unwrap_or_else(|| "tun0".into());
                        inbounds.push(Arc::new(flux_inbound::TunInbound::new(tag, ifname, mtu)));
                    }
                    SystemInboundConfig::Mixed {
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
                    SystemInboundConfig::Redirect {
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
                    SystemInboundConfig::Tproxy {
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
                },
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

fn parse_outbound_carrier(carrier: &CarrierConfig) -> FluxResult<(TargetAddress, bool)> {
    match carrier {
        CarrierConfig::Tcp {
            address,
            server,
            port,
        } => {
            if let Some(addr_str) = address {
                let target = addr_str.parse::<TargetAddress>()?;
                Ok((target, false))
            } else if let (Some(s), Some(p)) = (server, port) {
                Ok((TargetAddress::domain(s, *p), false))
            } else {
                Err(FluxError::Config(
                    "tcp carrier must specify address or server+port".into(),
                ))
            }
        }
        CarrierConfig::Udp {
            address,
            server,
            port,
        } => {
            if let Some(addr_str) = address {
                let target = addr_str.parse::<TargetAddress>()?;
                Ok((target, true))
            } else if let (Some(s), Some(p)) = (server, port) {
                Ok((TargetAddress::domain(s, *p), true))
            } else {
                Err(FluxError::Config(
                    "udp carrier must specify address or server+port".into(),
                ))
            }
        }
    }
}

fn compile_client_securities(
    sec_opt: Option<FlexibleList<SecurityConfig>>,
    default_sni: &str,
) -> FluxResult<Vec<flux_transport::pipeline::SecurityLayer>> {
    let mut list = Vec::new();
    let Some(secs) = sec_opt else {
        return Ok(list);
    };

    for sec in secs.into_vec() {
        match sec {
            SecurityConfig::Tls {
                sni,
                alpn,
                insecure,
                utls,
            } => {
                let sni_str = sni.unwrap_or_else(|| default_sni.to_string());
                let mut cfg = TlsClientConfig::new(sni_str)
                    .with_insecure(insecure)
                    .with_alpn(alpn);
                if let Some(u) = utls
                    && let Some(fp) = flux_transport::TlsFingerprint::parse_str(&u)
                {
                    cfg = cfg.with_fingerprint(fp);
                }
                list.push(flux_transport::pipeline::SecurityLayer::Tls(cfg));
            }
            SecurityConfig::Reality {
                sni,
                public_key,
                short_id,
            } => {
                let sni_str = sni.unwrap_or_else(|| default_sni.to_string());
                let pk_bytes = crate::config::decode_key_32bytes(&public_key)?;
                let sid = short_id
                    .and_then(|s| flux_types::decode_hex(&s))
                    .unwrap_or_default();
                list.push(flux_transport::pipeline::SecurityLayer::Reality(
                    RealityClientConfig {
                        server_name: sni_str,
                        public_key: pk_bytes,
                        short_id: sid,
                    },
                ));
            }
            SecurityConfig::ShadowTls { password, sni, .. } => {
                list.push(flux_transport::pipeline::SecurityLayer::ShadowTls(
                    flux_transport::shadowtls::ShadowTlsClientConfig {
                        server_name: sni,
                        password,
                        insecure: false,
                    },
                ));
            }
            SecurityConfig::Fragment {
                length_min,
                length_max,
                interval_ms,
            } => {
                list.push(flux_transport::pipeline::SecurityLayer::Fragment(
                    flux_transport::fragment::FragmentationConfig {
                        enabled: true,
                        length_min,
                        length_max,
                        interval_ms,
                    },
                ));
            }
        }
    }
    Ok(list)
}

fn compile_client_framings(
    frame_opt: Option<FlexibleList<FramingConfig>>,
) -> FluxResult<Vec<flux_transport::pipeline::FramingLayer>> {
    let mut list = Vec::new();
    let Some(frames) = frame_opt else {
        return Ok(list);
    };

    for frame in frames.into_vec() {
        match frame {
            FramingConfig::WebSocket { path, headers } => {
                list.push(flux_transport::pipeline::FramingLayer::WebSocket { path, headers });
            }
            FramingConfig::HttpUpgrade { path, headers } => {
                list.push(flux_transport::pipeline::FramingLayer::HttpUpgrade { path, headers });
            }
            FramingConfig::Http2 { path, headers } => {
                list.push(flux_transport::pipeline::FramingLayer::Http2 { path, headers });
            }
            FramingConfig::Grpc {
                service_name,
                headers,
            } => {
                list.push(flux_transport::pipeline::FramingLayer::Grpc {
                    service_name,
                    headers,
                });
            }
        }
    }
    Ok(list)
}

fn build_layered_outbound(
    node: LayeredOutboundNode,
    registry: &Arc<OutboundRegistry>,
    resolver: &Arc<DnsResolver>,
) -> FluxResult<()> {
    let tag = node.tag;
    let (target, is_udp) = parse_outbound_carrier(&node.carrier)?;

    if is_udp {
        match node.protocol {
            ProtocolConfig::Shadowsocks { password, method } => {
                let cipher_kind = method
                    .as_deref()
                    .and_then(flux_protocol::shadowsocks::CipherKind::parse_str)
                    .unwrap_or_default();
                let out = flux_outbound::ShadowsocksOutbound::new_datagram(
                    tag.clone(),
                    target,
                    &password,
                    resolver.clone(),
                )
                .with_cipher_kind(cipher_kind);
                registry.insert(tag, Arc::new(out));
                return Ok(());
            }
            ProtocolConfig::WireGuard {
                private_key,
                peer_public_key,
                preshared_key,
                awg,
            } => {
                let priv_k = crate::config::decode_key_32bytes(&private_key)?;
                let pub_k = crate::config::decode_key_32bytes(&peer_public_key)?;
                let psk = preshared_key.and_then(|k| crate::config::decode_key_32bytes(&k).ok());
                let wg_cfg = flux_protocol::wireguard::WireGuardConfig {
                    private_key: priv_k,
                    peer_public_key: pub_k,
                    preshared_key: psk,
                    server_address: target,
                    awg,
                };
                let out =
                    flux_outbound::WireGuardOutbound::new(tag.clone(), wg_cfg, resolver.clone());
                registry.insert(tag, Arc::new(out));
                return Ok(());
            }
            ProtocolConfig::Hysteria2 {
                password,
                up_mbps,
                down_mbps,
                hop_interval_secs,
                h3,
            } => {
                let hy2_cfg = flux_protocol::hysteria2::Hysteria2Config {
                    server: target.host(),
                    ports: vec![target.port()],
                    password,
                    up_mbps,
                    down_mbps,
                    hop_interval_secs: hop_interval_secs.unwrap_or(30),
                    insecure: true,
                    server_name: None,
                    obfs: None,
                    h3,
                };
                let out =
                    flux_outbound::Hysteria2Outbound::new(tag.clone(), hy2_cfg, resolver.clone());
                registry.insert(tag, Arc::new(out));
                return Ok(());
            }
            ProtocolConfig::Tuic {
                uuid,
                password,
                congestion_control,
                zero_rtt,
            } => {
                let parsed_uuid = Uuid::parse_str(&uuid)
                    .map_err(|e| FluxError::Config(format!("invalid tuic uuid {}: {}", uuid, e)))?;
                let tuic_cfg = flux_protocol::tuic::TuicV5Config {
                    server: target.host(),
                    server_port: target.port(),
                    uuid: parsed_uuid,
                    password,
                    congestion_control: congestion_control.unwrap_or_else(|| "bbr".into()),
                    zero_rtt: zero_rtt.unwrap_or(true),
                    insecure: true,
                    server_name: None,
                };
                let out = flux_outbound::TuicOutbound::new(tag.clone(), tuic_cfg, resolver.clone());
                registry.insert(tag, Arc::new(out));
                return Ok(());
            }
            _ => {
                return Err(FluxError::Config(format!(
                    "outbound '{}': carrier UDP currently supports shadowsocks, wireguard, hysteria2, tuic",
                    tag
                )));
            }
        }
    }

    let securities = compile_client_securities(node.security.clone(), &target.host())?;
    let framings = compile_client_framings(node.framing)?;
    let dialer: Arc<dyn flux_types::StreamDialer> =
        Arc::new(flux_outbound::LazyPipelineDialer::new_multi(
            target.clone(),
            resolver.clone(),
            securities,
            framings,
        ));

    match node.protocol {
        ProtocolConfig::Vless { uuid, flow } => {
            let parsed_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| FluxError::Config(format!("invalid vless uuid {}: {}", uuid, e)))?;
            let out = VlessOutbound::new(tag.clone(), parsed_uuid, flow, dialer);
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Shadowsocks { password, method } => {
            let cipher_kind = method
                .as_deref()
                .and_then(flux_protocol::shadowsocks::CipherKind::parse_str)
                .unwrap_or_default();
            let out = flux_outbound::ShadowsocksOutbound::new(
                tag.clone(),
                target,
                &password,
                resolver.clone(),
                dialer,
            )
            .with_cipher_kind(cipher_kind);
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Trojan { password } => {
            let out = flux_outbound::TrojanOutbound::new(tag.clone(), password, dialer);
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Vmess { uuid, security } => {
            let parsed_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| FluxError::Config(format!("invalid vmess uuid {}: {}", uuid, e)))?;
            let out = flux_outbound::VmessOutbound::new(
                tag.clone(),
                parsed_uuid,
                security.as_deref(),
                dialer,
            );
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Socks { username, password } => {
            let mut out = SocksOutbound::new(tag.clone(), target, resolver.clone(), dialer);
            if let (Some(u), Some(p)) = (username, password) {
                out = out.with_auth(u, p);
            }
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Http { username, password } => {
            let mut out = flux_outbound::HttpOutbound::new(tag.clone(), dialer);
            if let (Some(u), Some(p)) = (username, password) {
                out = out.with_auth(u, p);
            }
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::WireGuard {
            private_key,
            peer_public_key,
            preshared_key,
            awg,
        } => {
            let priv_k = crate::config::decode_key_32bytes(&private_key)?;
            let pub_k = crate::config::decode_key_32bytes(&peer_public_key)?;
            let psk = preshared_key.and_then(|k| crate::config::decode_key_32bytes(&k).ok());
            let wg_cfg = flux_protocol::wireguard::WireGuardConfig {
                private_key: priv_k,
                peer_public_key: pub_k,
                preshared_key: psk,
                server_address: target,
                awg,
            };
            let out = flux_outbound::WireGuardOutbound::new(tag.clone(), wg_cfg, resolver.clone());
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Hysteria2 {
            password,
            up_mbps,
            down_mbps,
            hop_interval_secs,
            h3,
        } => {
            let mut insecure = false;
            let mut server_name = None;
            if let Some(ref sec_list) = node.security {
                for sec in sec_list.as_slice() {
                    if let SecurityConfig::Tls {
                        sni, insecure: ins, ..
                    } = sec
                    {
                        if let Some(s) = sni {
                            server_name = Some(s.clone());
                        }
                        insecure = *ins;
                    }
                }
            }
            let hy2_cfg = flux_protocol::hysteria2::Hysteria2Config {
                server: target.host(),
                ports: vec![target.port()],
                password,
                up_mbps,
                down_mbps,
                hop_interval_secs: hop_interval_secs.unwrap_or(30),
                insecure,
                server_name,
                obfs: None,
                h3,
            };
            let out = if let CarrierConfig::Udp { .. } = node.carrier {
                flux_outbound::Hysteria2Outbound::new(tag.clone(), hy2_cfg, resolver.clone())
            } else {
                flux_outbound::Hysteria2Outbound::new_with_dialer(tag.clone(), hy2_cfg, dialer)
            };
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Tuic {
            uuid,
            password,
            congestion_control,
            zero_rtt,
        } => {
            let parsed_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| FluxError::Config(format!("invalid tuic uuid {}: {}", uuid, e)))?;
            let tuic_cfg = flux_protocol::tuic::TuicV5Config {
                server: target.host(),
                server_port: target.port(),
                uuid: parsed_uuid,
                password,
                congestion_control: congestion_control.unwrap_or_else(|| "bbr".into()),
                zero_rtt: zero_rtt.unwrap_or(true),
                insecure: false,
                server_name: None,
            };
            let out = flux_outbound::TuicOutbound::new_with_dialer(tag.clone(), tuic_cfg, dialer);
            registry.insert(tag, Arc::new(out));
        }
    }
    Ok(())
}

fn parse_inbound_carrier(carrier: &InboundCarrierConfig) -> FluxResult<(SocketAddr, bool)> {
    match carrier {
        InboundCarrierConfig::Tcp {
            listen,
            listen_port,
            address,
        } => {
            if let Some(addr_str) = address {
                let a = addr_str.parse::<SocketAddr>().map_err(|e| {
                    FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                })?;
                Ok((a, false))
            } else {
                let l_str = listen.as_deref().unwrap_or("0.0.0.0");
                let s = format!("{}:{}", l_str, listen_port.unwrap_or(0));
                let a = s
                    .parse::<SocketAddr>()
                    .map_err(|e| FluxError::Config(format!("invalid listen addr {}: {}", s, e)))?;
                Ok((a, false))
            }
        }
        InboundCarrierConfig::Udp {
            listen,
            listen_port,
            address,
        } => {
            if let Some(addr_str) = address {
                let a = addr_str.parse::<SocketAddr>().map_err(|e| {
                    FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                })?;
                Ok((a, true))
            } else {
                let l_str = listen.as_deref().unwrap_or("0.0.0.0");
                let s = format!("{}:{}", l_str, listen_port.unwrap_or(0));
                let a = s
                    .parse::<SocketAddr>()
                    .map_err(|e| FluxError::Config(format!("invalid listen addr {}: {}", s, e)))?;
                Ok((a, true))
            }
        }
    }
}

fn compile_server_securities(
    sec_opt: Option<FlexibleList<InboundSecurityConfig>>,
) -> FluxResult<Vec<flux_transport::pipeline::ServerSecurityLayer>> {
    let mut list = Vec::new();
    let Some(secs) = sec_opt else {
        return Ok(list);
    };

    for sec in secs.into_vec() {
        match sec {
            InboundSecurityConfig::Tls {
                certificate_path,
                key_path,
                ..
            } => {
                let (certs, key) = if let (Some(cp), Some(kp)) = (certificate_path, key_path) {
                    TlsTransport::load_certs_and_key(&cp, &kp)?
                } else {
                    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                        .map_err(|e| {
                            FluxError::Crypto(format!("failed to generate cert: {}", e))
                        })?;
                    (
                        vec![CertificateDer::from(cert.cert)],
                        PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
                    )
                };
                let acceptor = TlsTransport::create_server_acceptor(certs, key, vec![])?;
                list.push(flux_transport::pipeline::ServerSecurityLayer::Tls(acceptor));
            }
            InboundSecurityConfig::Reality {
                server_names,
                private_key,
                short_ids,
                fallback,
            } => {
                let pk_bytes = crate::config::decode_key_32bytes(&private_key)?;
                let sids = short_ids
                    .into_iter()
                    .filter_map(|s| flux_types::decode_hex(&s))
                    .collect();
                list.push(flux_transport::pipeline::ServerSecurityLayer::Reality(
                    flux_transport::reality::RealityServerConfig {
                        server_names,
                        private_key: pk_bytes,
                        short_ids: sids,
                        fallback,
                    },
                ));
            }
            InboundSecurityConfig::ShadowTls {
                password, fallback, ..
            } => {
                let fb_target = if let Ok(sa) = fallback.parse::<SocketAddr>() {
                    flux_transport::shadowtls::TargetFallback::Address(sa)
                } else if let Some((host, port_str)) = fallback.rsplit_once(':')
                    && let Ok(port) = port_str.parse::<u16>()
                {
                    flux_transport::shadowtls::TargetFallback::Domain(host.to_string(), port)
                } else {
                    return Err(FluxError::Config(format!(
                        "invalid shadowtls fallback addr {}: expected host:port or ip:port",
                        fallback
                    )));
                };
                list.push(flux_transport::pipeline::ServerSecurityLayer::ShadowTls(
                    flux_transport::shadowtls::ShadowTlsServerConfig {
                        server_names: vec![],
                        password,
                        fallback_address: fb_target,
                    },
                ));
            }
        }
    }
    Ok(list)
}

fn compile_server_framings(
    frame_opt: Option<FlexibleList<InboundFramingConfig>>,
) -> FluxResult<Vec<flux_transport::pipeline::ServerFramingLayer>> {
    let mut list = Vec::new();
    let Some(frames) = frame_opt else {
        return Ok(list);
    };

    for frame in frames.into_vec() {
        match frame {
            InboundFramingConfig::WebSocket { path } => {
                list.push(flux_transport::pipeline::ServerFramingLayer::WebSocket { path });
            }
            InboundFramingConfig::HttpUpgrade { path } => {
                list.push(flux_transport::pipeline::ServerFramingLayer::HttpUpgrade { path });
            }
            InboundFramingConfig::Http2 => {
                list.push(flux_transport::pipeline::ServerFramingLayer::Http2);
            }
            InboundFramingConfig::Grpc => {
                list.push(flux_transport::pipeline::ServerFramingLayer::Grpc);
            }
        }
    }
    Ok(list)
}

fn build_layered_inbound(
    node: LayeredInboundNode,
    inbounds: &mut Vec<Arc<dyn Inbound>>,
) -> FluxResult<()> {
    let tag = node.tag;
    let (addr, is_udp) = parse_inbound_carrier(&node.carrier)?;

    if is_udp {
        match node.protocol {
            ProtocolConfig::Shadowsocks { password, method } => {
                let cipher_kind = method
                    .as_deref()
                    .and_then(flux_protocol::shadowsocks::CipherKind::parse_str)
                    .unwrap_or_default();
                inbounds.push(Arc::new(
                    flux_inbound::ShadowsocksInbound::new(tag, addr, &password)
                        .with_cipher_kind(cipher_kind),
                ));
                return Ok(());
            }
            ProtocolConfig::Hysteria2 { password, .. } => {
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| FluxError::Crypto(format!("failed to generate cert: {}", e)))?;
                let certs = vec![CertificateDer::from(cert.cert)];
                let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
                inbounds.push(Arc::new(flux_inbound::Hysteria2Inbound::new(
                    tag, addr, password, certs, key,
                )));
                return Ok(());
            }
            ProtocolConfig::Tuic { uuid, password, .. } => {
                let parsed_uuid = Uuid::parse_str(&uuid)
                    .map_err(|e| FluxError::Config(format!("invalid tuic uuid {}: {}", uuid, e)))?;
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| FluxError::Crypto(format!("failed to generate cert: {}", e)))?;
                let certs = vec![CertificateDer::from(cert.cert)];
                let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
                inbounds.push(Arc::new(flux_inbound::TuicInbound::new(
                    tag,
                    addr,
                    vec![parsed_uuid],
                    password,
                    certs,
                    key,
                )));
                return Ok(());
            }
            _ => {
                return Err(FluxError::Config(format!(
                    "inbound '{}': carrier UDP currently supports shadowsocks, hysteria2, tuic",
                    tag
                )));
            }
        }
    }

    let securities = compile_server_securities(node.security)?;
    let framings = compile_server_framings(node.framing)?;
    let pipeline = flux_transport::pipeline::ServerTransportPipeline::new(securities, framings);

    match node.protocol {
        ProtocolConfig::Vless { uuid, .. } => {
            let parsed_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| FluxError::Config(format!("invalid vless uuid {}: {}", uuid, e)))?;
            inbounds.push(Arc::new(flux_inbound::VlessInbound::new(
                tag,
                addr,
                vec![parsed_uuid],
                pipeline,
            )));
        }
        ProtocolConfig::Shadowsocks { password, method } => {
            let cipher_kind = method
                .as_deref()
                .and_then(flux_protocol::shadowsocks::CipherKind::parse_str)
                .unwrap_or_default();
            inbounds.push(Arc::new(
                flux_inbound::ShadowsocksInbound::new(tag, addr, &password)
                    .with_cipher_kind(cipher_kind)
                    .with_pipeline(pipeline),
            ));
        }
        ProtocolConfig::Trojan { password } => {
            inbounds.push(Arc::new(flux_inbound::TrojanInbound::new(
                tag,
                addr,
                vec![password],
                pipeline,
            )));
        }
        ProtocolConfig::Vmess { uuid, .. } => {
            let parsed_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| FluxError::Config(format!("invalid vmess uuid {}: {}", uuid, e)))?;
            inbounds.push(Arc::new(flux_inbound::VmessInbound::new(
                tag,
                addr,
                vec![parsed_uuid],
                pipeline,
            )));
        }
        ProtocolConfig::Socks { username, password } => {
            let users = match (username, password) {
                (Some(u), Some(p)) => vec![(u, p)],
                _ => vec![],
            };
            inbounds.push(Arc::new(
                flux_inbound::SocksInbound::new(tag, addr)
                    .with_users(users)
                    .with_pipeline(pipeline),
            ));
        }
        ProtocolConfig::Http { username, password } => {
            let users = match (username, password) {
                (Some(u), Some(p)) => vec![(u, p)],
                _ => vec![],
            };
            inbounds.push(Arc::new(
                flux_inbound::HttpInbound::new(tag, addr)
                    .with_users(users)
                    .with_pipeline(pipeline),
            ));
        }
        ProtocolConfig::WireGuard { .. } => {
            return Err(FluxError::Config(
                "wireguard server inbound not supported".to_string(),
            ));
        }
        ProtocolConfig::Hysteria2 { password, .. } => {
            if pipeline.securities.is_empty() && pipeline.framings.is_empty() {
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| FluxError::Crypto(format!("failed to generate cert: {}", e)))?;
                let certs = vec![CertificateDer::from(cert.cert)];
                let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
                inbounds.push(Arc::new(flux_inbound::Hysteria2Inbound::new(
                    tag, addr, password, certs, key,
                )));
            } else {
                inbounds.push(Arc::new(flux_inbound::Hysteria2Inbound::new_with_pipeline(
                    tag, addr, password, pipeline,
                )));
            }
        }
        ProtocolConfig::Tuic { uuid, password, .. } => {
            let parsed_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| FluxError::Config(format!("invalid tuic uuid {}: {}", uuid, e)))?;
            if pipeline.securities.is_empty() && pipeline.framings.is_empty() {
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| FluxError::Crypto(format!("failed to generate cert: {}", e)))?;
                let certs = vec![CertificateDer::from(cert.cert)];
                let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
                inbounds.push(Arc::new(flux_inbound::TuicInbound::new(
                    tag,
                    addr,
                    vec![parsed_uuid],
                    password,
                    certs,
                    key,
                )));
            } else {
                inbounds.push(Arc::new(flux_inbound::TuicInbound::new_with_pipeline(
                    tag,
                    addr,
                    vec![parsed_uuid],
                    password,
                    pipeline,
                )));
            }
        }
    }
    Ok(())
}
