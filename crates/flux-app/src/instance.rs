/// Joins a listen host and a port into something `SocketAddr` can parse.
///
/// A bare `format!("{host}:{port}")` produces `::1:8080` for an IPv6 host, which does not parse:
/// v6 literals need brackets. Doing this in one place means a v6 listener works everywhere one
/// is accepted by the configuration, rather than in whichever code path remembered the brackets.
fn join_host_port(host: impl AsRef<str>, port: u16) -> String {
    let host = host.as_ref();
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

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
/// /// Outbounds by tag.
pub struct OutboundRegistry {
    /// The outbounds themselves.
    pub map: Arc<DashMap<String, Arc<dyn Outbound>>>,
}

impl OutboundRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
    }

    /// Adds or replaces an outbound.
    pub fn insert(&self, tag: String, outbound: Arc<dyn Outbound>) {
        self.map.insert(tag, outbound);
    }

    /// Looks an outbound up by tag.
    pub fn get_outbound(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.map.get(tag).map(|e| e.value().clone())
    }
}

impl OutboundLookup for OutboundRegistry {
    fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.map.get(tag).map(|e| e.value().clone())
    }
}

/// A remote (URL-fetched) rule set registered for background fetching.
struct RemoteRuleSetSpec {
    ruleset: Arc<flux_router::RuleSet>,
    url: String,
    interval: Option<Duration>,
    cache_path: Option<std::path::PathBuf>,
}

/// /// A running proxy built from a configuration.
pub struct Instance {
    /// The listeners this instance started.
    pub inbounds: Vec<Arc<dyn Inbound>>,
    /// Outbounds by tag.
    pub registry: Arc<OutboundRegistry>,
    /// The component that joins inbounds to outbounds.
    pub dispatcher: Arc<dyn Dispatcher>,
    /// The routing rules.
    pub router: Arc<Router>,
    /// Traffic counters and the connection table.
    pub meter: Arc<TrafficMeter>,
    /// The management API, when one is configured.
    pub api_server: Option<Arc<ApiServer>>,
    /// The resolver the dispatcher uses.
    pub resolver: Arc<DnsResolver>,
    /// Remote rule sets to fetch in the background.
    remote_rulesets: Vec<RemoteRuleSetSpec>,
    /// Cancel handle for background fetch loops (SIGHUP reload / shutdown safe).
    ///
    /// Mutable behind a lock because a [`tokio_util::sync::CancellationToken`]
    /// is one-shot: `stop()` cancels it, so `start()` hands out a *fresh* token.
    /// Reusing the cancelled one left the fetch loops of a restarted instance
    /// exiting on their first poll, silently losing the refresh.
    fetch_cancel: std::sync::Mutex<tokio_util::sync::CancellationToken>,
    /// Serializes `start`/`stop` and remembers whether the instance is up.
    ///
    /// `start()` is idempotent (a second call would otherwise bind every port a
    /// second time — SO_REUSEPORT makes that succeed instead of failing — and
    /// spawn a second accept loop per inbound); `stop()` may be called twice.
    started: tokio::sync::Mutex<bool>,
}

impl Instance {
    /// Builds everything the configuration describes, without starting it.
    pub fn new(config: Config) -> FluxResult<Self> {
        config.validate()?;

        // 1. DNS & Fake-IP & Split-DNS
        let (fake_ip_pool, dns_servers, dns_rules, global_ecs) = if let Some(dns_cfg) = &config.dns
        {
            let pool = if let Some(fip) = &dns_cfg.fakeip {
                if fip.enabled.unwrap_or(false) {
                    let v4 = fip
                        .inet4_range
                        .as_deref()
                        .unwrap_or(flux_dns::fakeip::DEFAULT_INET4_RANGE);
                    // The IPv6 pool is on by default so AAAA queries can be
                    // answered; `off`/`none`/`disabled`/"" restores NODATA.
                    let v6 = fip
                        .inet6_range
                        .as_deref()
                        .unwrap_or(flux_dns::fakeip::DEFAULT_INET6_RANGE);
                    let p = FakeIpPool::from_ranges(v4, Some(v6), 10000).map_err(|e| {
                        FluxError::Config(format!(
                            "invalid fake-ip range v4={} v6={}: {}",
                            v4, v6, e
                        ))
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
        let (rules, default_outbound, rule_set_registry, geoip_reg, remote_rulesets) = if let Some(
            route_cfg,
        ) =
            config.route
        {
            let mut reg = flux_router::RuleSetRegistry::new();
            let mut remote_specs: Vec<RemoteRuleSetSpec> = Vec::new();
            for rs_cfg in route_cfg.rule_set {
                // Auto-detect remote rule sets: explicit type=remote or an http(s) URL path.
                let is_remote = rs_cfg.set_type.as_deref() == Some("remote")
                    || rs_cfg
                        .path
                        .as_deref()
                        .map(|p| p.starts_with("http://") || p.starts_with("https://"))
                        .unwrap_or(false);
                match rs_cfg.set_type.as_deref() {
                    None | Some("local") | Some("inline") | Some("remote") => {}
                    Some(other) => {
                        return Err(FluxError::Config(format!(
                            "rule_set '{}': unsupported type '{}' (supported: 'local', 'inline', 'remote')",
                            rs_cfg.tag, other
                        )));
                    }
                }
                if is_remote {
                    let url = rs_cfg.path.clone().ok_or_else(|| {
                        FluxError::Config(format!(
                            "rule_set '{}': remote type requires a 'path' with an http(s) URL",
                            rs_cfg.tag
                        ))
                    })?;
                    if !url.starts_with("http://") && !url.starts_with("https://") {
                        return Err(FluxError::Config(format!(
                            "rule_set '{}': remote path must be an http(s) URL, got '{}'",
                            rs_cfg.tag, url
                        )));
                    }
                    let interval = rs_cfg
                        .update_interval
                        .as_deref()
                        .map(|s| {
                            parse_duration(s).ok_or_else(|| {
                                FluxError::Config(format!(
                                    "rule_set '{}': invalid update_interval '{}'",
                                    rs_cfg.tag, s
                                ))
                            })
                        })
                        .transpose()?;
                    let rs_tag = rs_cfg.tag.clone();
                    let mut rs = flux_router::RuleSet {
                        tag: rs_cfg.tag,
                        ip_cidr: rs_cfg.ip_cidr,
                        domain: rs_cfg.domain,
                        domain_suffix: rs_cfg.domain_suffix,
                        domain_keyword: rs_cfg.domain_keyword,
                        ..Default::default()
                    };
                    rs.remote_url = Some(url.clone());
                    rs.update_interval = interval;
                    // Remote rule sets start empty (never-matching) and are populated
                    // asynchronously; a failed fetch must not break instance startup.
                    reg.insert(rs).map_err(flux_types::FluxError::Config)?;
                    // Disk cache: apply the last successfully fetched content
                    // immediately, before any network round-trip.
                    let cache_path = rs_cfg
                        .cache_path
                        .clone()
                        .map(std::path::PathBuf::from)
                        .or_else(|| Some(default_ruleset_cache_path(&rs_tag, &url)));
                    if let Some(cp) = &cache_path
                        && let Ok(cached) = std::fs::read_to_string(cp)
                        && let Some(arc_rs) = reg.get(&rs_tag)
                    {
                        arc_rs.apply_content(&cached);
                        tracing::info!(
                            "remote rule set '{}' restored from cache {} ({} bytes)",
                            rs_tag,
                            cp.display(),
                            cached.len()
                        );
                    }
                    if let Some(arc_rs) = reg.get(&rs_tag) {
                        remote_specs.push(RemoteRuleSetSpec {
                            ruleset: arc_rs,
                            url,
                            interval,
                            cache_path,
                        });
                    }
                    continue;
                }
                let rs = flux_router::RuleSet {
                    tag: rs_cfg.tag,
                    path: rs_cfg.path,
                    ip_cidr: rs_cfg.ip_cidr,
                    domain: rs_cfg.domain,
                    domain_suffix: rs_cfg.domain_suffix,
                    domain_keyword: rs_cfg.domain_keyword,
                    ..Default::default()
                };
                reg.insert(rs).map_err(flux_types::FluxError::Config)?;
            }
            let mut r_vec = Vec::new();
            for r in route_cfg.rules {
                r_vec.push(r.to_rule()?);
            }
            let def = route_cfg.final_outbound.unwrap_or_else(|| "direct".into());
            let geo = Arc::new(flux_router::GeoIpRegistry::new());
            if let Some(ref path) = route_cfg.geoip_path {
                geo.load(path).map_err(flux_types::FluxError::Config)?;
            }
            (r_vec, def, reg, geo, remote_specs)
        } else {
            (
                vec![],
                "direct".into(),
                flux_router::RuleSetRegistry::new(),
                Arc::new(flux_router::GeoIpRegistry::new()),
                Vec::new(),
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

        // DNS inbound (fake-IP responder / forwarding resolver), when configured.
        if let Some(listen) = config.dns.as_ref().and_then(|d| d.listen.as_deref()) {
            let addr: std::net::SocketAddr = listen.parse().map_err(|e| {
                FluxError::Config(format!("invalid dns.listen '{}': {}", listen, e))
            })?;
            let pool = resolver.fake_ip().cloned();
            if pool.is_none() {
                tracing::info!(
                    "dns.listen is set but fake-ip is disabled: serving as a plain resolver"
                );
            }
            inbounds.push(Arc::new(flux_inbound::DnsInbound::new(
                "dns-in",
                addr,
                resolver.clone(),
                pool,
            )));
        }
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
                        rate_limit,
                    } => {
                        let addr_str = join_host_port(&listen, listen_port);
                        let addr: SocketAddr = addr_str.parse().map_err(|e| {
                            FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                        })?;
                        let user_pairs = users
                            .into_iter()
                            .map(|u| (u.username, u.password))
                            .collect();
                        let mut ib = MixedInbound::new(tag, addr).with_users(user_pairs);
                        if let Some(rl) = rate_limit.as_ref().map(|c| c.build()) {
                            ib = ib.with_rate_limiter(rl);
                        }
                        inbounds.push(Arc::new(ib));
                    }
                    SystemInboundConfig::Redirect {
                        tag,
                        listen,
                        listen_port,
                    } => {
                        let addr_str = join_host_port(&listen, listen_port);
                        let addr: SocketAddr = addr_str.parse().map_err(|e| {
                            FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                        })?;
                        inbounds.push(Arc::new(flux_inbound::RedirectInbound::new(tag, addr)));
                    }
                    SystemInboundConfig::WireGuard {
                        tag,
                        listen,
                        listen_port,
                        private_key,
                        peers,
                        mtu,
                        awg,
                    } => {
                        let addr_str = join_host_port(&listen, listen_port);
                        let addr: SocketAddr = addr_str.parse().map_err(|e| {
                            FluxError::Config(format!("invalid listen address {}: {}", addr_str, e))
                        })?;
                        let priv_key =
                            crate::config::decode_key_32bytes(&private_key).map_err(|e| {
                                FluxError::Config(format!("wireguard inbound '{}': {}", tag, e))
                            })?;
                        let mut wg_peers = Vec::with_capacity(peers.len());
                        for peer in &peers {
                            let public_key = crate::config::decode_key_32bytes(&peer.public_key)
                                .map_err(|e| {
                                    FluxError::Config(format!(
                                        "wireguard inbound '{}' peer: {}",
                                        tag, e
                                    ))
                                })?;
                            let preshared_key = peer
                                .preshared_key
                                .as_deref()
                                .map(crate::config::decode_key_32bytes)
                                .transpose()
                                .map_err(|e| {
                                    FluxError::Config(format!(
                                        "wireguard inbound '{}' peer psk: {}",
                                        tag, e
                                    ))
                                })?;
                            let allowed_ips = peer
                                .allowed_ips
                                .iter()
                                .map(|c| c.parse::<ipnet::IpNet>())
                                .collect::<Result<Vec<_>, _>>()
                                .map_err(|e| {
                                    FluxError::Config(format!(
                                        "wireguard inbound '{}' peer allowed_ips: {}",
                                        tag, e
                                    ))
                                })?;
                            wg_peers.push(flux_inbound::WireGuardInboundPeer {
                                public_key,
                                preshared_key,
                                allowed_ips,
                            });
                        }
                        inbounds.push(Arc::new(flux_inbound::WireGuardInbound::new(
                            tag, addr, priv_key, wg_peers, awg, mtu,
                        )));
                    }
                    SystemInboundConfig::Tproxy {
                        tag,
                        listen,
                        listen_port,
                    } => {
                        let addr_str = join_host_port(&listen, listen_port);
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
            remote_rulesets,
            fetch_cancel: std::sync::Mutex::new(tokio_util::sync::CancellationToken::new()),
            started: tokio::sync::Mutex::new(false),
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

    /// Binds every listener and starts serving.
    pub async fn start(&self) -> FluxResult<()> {
        let mut started = self.started.lock().await;
        if *started {
            // Idempotent: bind-once / serve-once. See the field docs.
            tracing::debug!("instance is already started; ignoring repeated start()");
            return Ok(());
        }
        self.reset_fetch_cancel();
        // The meter's sampler is stopped by `stop()`; re-arm it for every
        // start cycle (idempotent while it is already running).
        self.meter.start();

        if let Some(api) = &self.api_server
            && let Err(e) = api.start().await
        {
            // The API is the first thing we bind, so nothing is left behind.
            return Err(e);
        }

        for (idx, inbound) in self.inbounds.iter().enumerate() {
            if let Err(e) = inbound.start(self.dispatcher.clone()).await {
                // A start that fails half-way is worse than one that fails
                // cleanly: the listeners opened by the inbounds before this one
                // would stay bound (and accepting, under SO_REUSEPORT) for the
                // lifetime of the process, which is exactly the half-applied
                // state a SIGHUP reload must never produce. Release them, in
                // reverse order, before reporting the error.
                for already in self.inbounds[..=idx].iter().rev() {
                    if let Err(stop_err) = already.stop().await {
                        tracing::warn!(
                            inbound = already.tag(),
                            error = %stop_err,
                            "failed to release inbound after a failed start"
                        );
                    }
                }
                if let Some(api) = &self.api_server
                    && let Err(stop_err) = api.stop().await
                {
                    tracing::warn!(
                        error = %stop_err,
                        "failed to release API server after a failed start"
                    );
                }
                return Err(e);
            }
        }
        self.spawn_remote_ruleset_fetchers();
        *started = true;
        Ok(())
    }

    /// Replaces the fetch cancellation token with a fresh, uncancelled one.
    fn reset_fetch_cancel(&self) {
        *self
            .fetch_cancel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            tokio_util::sync::CancellationToken::new();
    }

    fn fetch_cancel_token(&self) -> tokio_util::sync::CancellationToken {
        self.fetch_cancel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Spawns background fetch loops for remote (URL-based) rule sets.
    /// A fetch failure is logged and retried on the next interval (or once,
    /// when no `update_interval` is configured); it never breaks routing.
    fn spawn_remote_ruleset_fetchers(&self) {
        let cancel = self.fetch_cancel_token();
        for spec in &self.remote_rulesets {
            let rs = spec.ruleset.clone();
            let url = spec.url.clone();
            let interval = spec.interval;
            let cache_path = spec.cache_path.clone();
            let resolver = self.resolver.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    let fetch = crate::ruleset_fetch::fetch_remote_ruleset(&url, &resolver);
                    let result = tokio::select! {
                        _ = cancel.cancelled() => break,
                        r = fetch => r,
                    };
                    match result {
                        Ok(content) => {
                            // A refresh must never replace a working rule set with
                            // one that parses to nothing (a broken feed, a captive
                            // portal): the old rules stay in force instead.
                            if !rs.try_apply_content(&content) {
                                tracing::warn!(
                                    "remote rule set '{}': fetched {} bytes but parsed no usable \
                                     rules — KEEPING the previous contents",
                                    rs.tag,
                                    content.len()
                                );
                                continue;
                            }
                            // A rule set that loads but parses to zero usable
                            // entries makes every `rule_set` rule match nothing,
                            // so traffic silently falls through to the final
                            // outbound. Say so instead of only logging a size.
                            if rs.parsed_entry_count() == 0 {
                                tracing::warn!(
                                    "remote rule set '{}': no usable rules parsed from {} bytes — \
                                     `rule_set` rules referencing it match NOTHING",
                                    rs.tag,
                                    content.len()
                                );
                            } else if rs.unparsed_entry_count() > 0 {
                                tracing::warn!(
                                    "remote rule set '{}': {} rule(s) parsed, {} line(s) ignored \
                                     (unsupported type or malformed)",
                                    rs.tag,
                                    rs.parsed_entry_count(),
                                    rs.unparsed_entry_count()
                                );
                            }
                            if let Some(cp) = &cache_path {
                                if let Some(parent) = cp.parent() {
                                    let _ = std::fs::create_dir_all(parent);
                                }
                                if let Err(e) = std::fs::write(cp, &content) {
                                    tracing::warn!(
                                        "remote rule set '{}': failed to write cache {}: {}",
                                        rs.tag,
                                        cp.display(),
                                        e
                                    );
                                }
                            }
                            tracing::info!(
                                "remote rule set '{}' loaded from {} ({} bytes)",
                                rs.tag,
                                url,
                                content.len()
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "remote rule set '{}' fetch from {} failed: {}",
                                rs.tag,
                                url,
                                e
                            );
                        }
                    }
                    match interval {
                        Some(d) => {
                            tokio::select! {
                                _ = cancel.cancelled() => break,
                                _ = tokio::time::sleep(d) => {}
                            }
                        }
                        None => break,
                    }
                }
            });
        }
    }

    /// Stops every listener, releasing the sockets before it returns.
    pub async fn stop(&self) -> FluxResult<()> {
        let mut started = self.started.lock().await;
        let mut first_error = None;

        if *started {
            *started = false;
            if let Some(api) = &self.api_server
                && let Err(e) = api.stop().await
            {
                first_error = Some(e);
            }
            // Keep going even if one inbound fails to stop: skipping the rest
            // would leak their listeners and tasks.
            for inbound in &self.inbounds {
                if let Err(e) = inbound.stop().await
                    && first_error.is_none()
                {
                    first_error = Some(e);
                }
            }
            self.fetch_cancel_token().cancel();
        }

        // Outbound groups (urltest/fallback) spawn their probing loop in
        // `new()`, i.e. *before* `start()`, so they are quiesced even when the
        // instance never ran. Every group `stop()` is an idempotent cancel.
        for entry in self.registry.map.iter() {
            entry.value().stop();
        }

        // The speed sampler is spawned by `new()`, not by `start()`, and its
        // task used to be reachable only through a `Weak<TrafficMeter>`: the
        // only thing that could stop it was dropping the last `Arc`, so a
        // stopped-but-alive instance always owned one task and every SIGHUP
        // reload kept the previous instance's sampler running until then. It is
        // stopped here unconditionally — like the groups above — so that after
        // `stop()` the instance owns no tasks at all; `start()` re-arms it.
        self.meter.stop().await;

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Default disk cache path for a remote rule set:
/// `$XDG_CACHE_HOME/flux-core/rulesets/<tag>-<url-hash>.txt` (or `~/.cache/...`).
fn default_ruleset_cache_path(tag: &str, url: &str) -> std::path::PathBuf {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    url.hash(&mut h);
    let base = std::env::var("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".cache"))
                .unwrap_or_else(|_| std::env::temp_dir())
        });
    // The tag comes from the configuration and may contain path separators
    // (`../../x`), so restrict it to a safe character set before it becomes a
    // file name.
    let safe_tag: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe_tag = safe_tag.trim_matches('.').replace("..", "_");
    base.join("flux-core")
        .join("rulesets")
        .join(format!("{}-{:016x}.txt", safe_tag, h.finish()))
}

fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    // Saturating arithmetic: a hostile `9e18h` must clamp, not overflow-panic in
    // debug builds.
    if let Some(rest) = s.strip_suffix('s') {
        rest.parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>()
            .ok()
            .map(|m| Duration::from_secs(m.saturating_mul(60)))
    } else if let Some(rest) = s.strip_suffix('h') {
        rest.parse::<u64>()
            .ok()
            .map(|h| Duration::from_secs(h.saturating_mul(3600)))
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

fn parse_outbound_carrier(carrier: &CarrierConfig) -> FluxResult<(TargetAddress, bool)> {
    match carrier {
        // mKCP runs over UDP but is a *stream* carrier: the protocol above it
        // (VLESS, Trojan, …) is the same code, so it takes the layered path and the
        // dialer opens a KCP stream instead of a TCP one.
        CarrierConfig::Kcp {
            address,
            server,
            port,
            ..
        } => {
            if let Some(addr_str) = address {
                Ok((addr_str.parse::<TargetAddress>()?, false))
            } else if let (Some(s), Some(p)) = (server, port) {
                Ok((TargetAddress::domain(s, *p), false))
            } else {
                Err(FluxError::Config(
                    "kcp carrier must specify address or server+port".into(),
                ))
            }
        }
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

/// Extracts (sni, insecure, alpn) from the first `tls` security entry of a layered
/// outbound — used for QUIC-native protocols (hysteria2, tuic) whose TLS lives in
/// the QUIC handshake rather than the stream pipeline.
/// Resolves Hysteria 2 obfuscation config into the Salamander password.
/// `obfs` must be "salamander" (the only supported mode) and requires a password.
fn resolve_hy2_obfs(obfs: Option<&str>, password: Option<String>) -> FluxResult<Option<String>> {
    match obfs {
        None => Ok(None),
        Some("salamander") => password.map(Some).ok_or_else(|| {
            FluxError::Config("hysteria2: obfs 'salamander' requires 'obfs_password'".into())
        }),
        Some(other) => Err(FluxError::Config(format!(
            "hysteria2: unsupported obfs mode '{}' (supported: 'salamander')",
            other
        ))),
    }
}

/// SNI to use when a QUIC outbound has no explicit `tls.server_name`:
/// the carrier host name, unless it is a bare IP literal (SNI must be a name).
fn default_quic_sni(host: &str) -> Option<String> {
    host.parse::<std::net::IpAddr>()
        .is_err()
        .then(|| host.to_string())
}

fn extract_quic_tls_params(
    sec_opt: &Option<FlexibleList<SecurityConfig>>,
) -> (
    Option<String>,
    bool,
    Option<Vec<String>>,
    Vec<std::path::PathBuf>,
) {
    if let Some(secs) = sec_opt {
        for sec in secs.clone().into_vec() {
            if let SecurityConfig::Tls {
                sni,
                alpn,
                insecure,
                ca_cert_path,
                ..
            } = sec
            {
                return (
                    sni,
                    insecure,
                    (!alpn.is_empty()).then_some(alpn),
                    ca_cert_path.into_iter().map(Into::into).collect(),
                );
            }
        }
    }
    // No TLS security block configured for a QUIC-native outbound (hy2/tuic).
    //
    // This used to default to `insecure: true`, which silently disabled
    // certificate verification for every QUIC outbound that did not spell out a
    // `security: {type: tls}` block — a one-config-line path to MITM. Verification
    // is now on by default; servers with self-signed certificates must opt in
    // explicitly with `insecure: true`.
    (None, false, None, vec![])
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
                ca_cert_path,
                native_tls,
            } => {
                let sni_str = sni.unwrap_or_else(|| default_sni.to_string());
                let mut cfg = TlsClientConfig::new(sni_str)
                    .with_insecure(insecure)
                    .with_alpn(alpn);
                cfg.ca_certs = ca_cert_path.into_iter().map(Into::into).collect();
                cfg.native = native_tls;
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
            SecurityConfig::ShadowTls {
                version,
                password,
                sni,
            } => {
                if version != 3 {
                    return Err(FluxError::Config(format!(
                        "shadowtls outbound: version {version} is not supported (only 3); \
                         serving it as v3 would silently mis-negotiate"
                    )));
                }
                list.push(flux_transport::pipeline::SecurityLayer::ShadowTls(
                    flux_transport::shadowtls::ShadowTlsClientConfig {
                        server_name: sni,
                        password,
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
            FramingConfig::Xhttp {
                path,
                headers,
                settings,
            } => {
                settings
                    .validate("outbound xhttp")
                    .map_err(flux_types::FluxError::Config)?;
                list.push(flux_transport::pipeline::FramingLayer::Xhttp {
                    path,
                    headers,
                    xpadding: settings.xpadding_bytes.clone(),
                    // `auto` resolves to `stream-up`: it is a client-side choice between the split
                    // modes and both are served by the same Xray endpoints.
                    packet_up: matches!(
                        settings.mode.as_deref(),
                        Some("packet-up") | Some("packetup")
                    ),
                    stream_up: matches!(
                        settings.mode.as_deref(),
                        Some("stream-up") | Some("streamup") | Some("auto")
                    ),
                });
            }
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
                let cipher_kind = match method.as_deref() {
                    // An omitted method means the documented default.
                    None => flux_protocol::shadowsocks::CipherKind::default(),
                    Some(name) => flux_protocol::shadowsocks::CipherKind::parse_str(name)
                        .ok_or_else(|| {
                            FluxError::Config(format!(
                                "unsupported shadowsocks method {name:?} (expected \
                                 chacha20-ietf-poly1305, aes-128-gcm or aes-256-gcm); silently \
                                 substituting a different cipher would make the config a lie"
                            ))
                        })?,
                };
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
                local_address,
                keepalive_secs,
                awg,
            } => {
                let priv_k = crate::config::decode_key_32bytes(&private_key)?;
                let pub_k = crate::config::decode_key_32bytes(&peer_public_key)?;
                // A malformed key or address must be a hard error: silently dropping them
                // turns a typo into "no PSK" / "no source address", i.e. a tunnel that
                // quietly differs from what the operator wrote.
                let psk = match preshared_key {
                    Some(k) => Some(crate::config::decode_key_32bytes(&k).map_err(|e| {
                        FluxError::Config(format!(
                            "outbound '{}': invalid preshared_key: {}",
                            tag, e
                        ))
                    })?),
                    None => None,
                };
                let local_ip = match local_address.as_deref() {
                    Some(a) => Some(a.parse().map_err(|e| {
                        FluxError::Config(format!(
                            "outbound '{}': invalid local_address '{}': {}",
                            tag, a, e
                        ))
                    })?),
                    None => None,
                };
                let wg_cfg = flux_protocol::wireguard::WireGuardConfig {
                    private_key: priv_k,
                    peer_public_key: pub_k,
                    preshared_key: psk,
                    server_address: target,
                    local_address: local_ip,
                    keepalive_secs,
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
                obfs,
                obfs_password,
            } => {
                let (q_sni, q_insecure, q_alpn, q_ca) = extract_quic_tls_params(&node.security);
                let q_sni = q_sni.or_else(|| default_quic_sni(&target.host()));
                let hy2_cfg = flux_protocol::hysteria2::Hysteria2Config {
                    server: target.host(),
                    ports: vec![target.port()],
                    password,
                    up_mbps,
                    down_mbps,
                    hop_interval_secs: hop_interval_secs.unwrap_or(30),
                    insecure: q_insecure,
                    server_name: q_sni,
                    obfs: resolve_hy2_obfs(obfs.as_deref(), obfs_password)?,
                    alpn: q_alpn,
                    ca_certs: q_ca,
                    h3: h3.unwrap_or(true),
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
                let (q_sni, q_insecure, q_alpn, q_ca) = extract_quic_tls_params(&node.security);
                let q_sni = q_sni.or_else(|| default_quic_sni(&target.host()));
                let tuic_cfg = flux_protocol::tuic::TuicV5Config {
                    server: target.host(),
                    server_port: target.port(),
                    uuid: parsed_uuid,
                    password,
                    congestion_control: congestion_control.unwrap_or_else(|| "bbr".into()),
                    zero_rtt: zero_rtt.unwrap_or(true),
                    insecure: q_insecure,
                    server_name: q_sni,
                    alpn: q_alpn,
                    ca_certs: q_ca,
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
    let mut lazy = flux_outbound::LazyPipelineDialer::new_multi(
        target.clone(),
        resolver.clone(),
        securities,
        framings,
    );
    if let Some(kcp) = node.carrier.as_kcp()? {
        lazy.kcp = Some(kcp);
    }
    let dialer: Arc<dyn flux_types::StreamDialer> = Arc::new(lazy);

    // Multiplexing is opt-in per node and only exists for the stream protocols.
    let mux = node
        .multiplex
        .as_ref()
        .map(|config| config.build())
        .transpose()?
        .flatten();
    if mux.is_some()
        && !matches!(
            node.protocol,
            ProtocolConfig::Vless { .. }
                | ProtocolConfig::Vmess { .. }
                | ProtocolConfig::Trojan { .. }
                | ProtocolConfig::Shadowsocks { .. }
        )
    {
        return Err(FluxError::Config(format!(
            "outbound '{}': multiplex is only supported for vless, vmess, trojan and shadowsocks",
            tag
        )));
    }

    match node.protocol {
        ProtocolConfig::Vless { uuid, flow } => {
            let parsed_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| FluxError::Config(format!("invalid vless uuid {}: {}", uuid, e)))?;
            let mut out = VlessOutbound::new(tag.clone(), parsed_uuid, flow, dialer);
            if let Some(mux) = mux.clone() {
                out = out.with_mux(mux)?;
            }
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Shadowsocks { password, method } => {
            let cipher_kind = match method.as_deref() {
                // An omitted method means the documented default.
                None => flux_protocol::shadowsocks::CipherKind::default(),
                Some(name) => {
                    flux_protocol::shadowsocks::CipherKind::parse_str(name).ok_or_else(|| {
                        FluxError::Config(format!(
                            "unsupported shadowsocks method {name:?} (expected \
                                 chacha20-ietf-poly1305, aes-128-gcm or aes-256-gcm); silently \
                                 substituting a different cipher would make the config a lie"
                        ))
                    })?
                }
            };
            let mut out = flux_outbound::ShadowsocksOutbound::new(
                tag.clone(),
                target,
                &password,
                resolver.clone(),
                dialer,
            )
            .with_cipher_kind(cipher_kind);
            if let Some(mux) = mux.clone() {
                out = out.with_mux(mux)?;
            }
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Trojan { password } => {
            let mut out = flux_outbound::TrojanOutbound::new(tag.clone(), password, dialer);
            if let Some(mux) = mux.clone() {
                out = out.with_mux(mux);
            }
            registry.insert(tag, Arc::new(out));
        }
        ProtocolConfig::Vmess { uuid, security } => {
            let parsed_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| FluxError::Config(format!("invalid vmess uuid {}: {}", uuid, e)))?;
            let mut out = flux_outbound::VmessOutbound::new(
                tag.clone(),
                parsed_uuid,
                security.as_deref(),
                dialer,
            );
            if let Some(mux) = mux.clone() {
                out = out.with_mux(mux);
            }
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
            local_address,
            keepalive_secs,
            awg,
        } => {
            let priv_k = crate::config::decode_key_32bytes(&private_key)?;
            let pub_k = crate::config::decode_key_32bytes(&peer_public_key)?;
            // A malformed key or address must be a hard error: silently dropping them
            // turns a typo into "no PSK" / "no source address", i.e. a tunnel that
            // quietly differs from what the operator wrote.
            let psk = match preshared_key {
                Some(k) => Some(crate::config::decode_key_32bytes(&k).map_err(|e| {
                    FluxError::Config(format!("outbound '{}': invalid preshared_key: {}", tag, e))
                })?),
                None => None,
            };
            let local_ip = match local_address.as_deref() {
                Some(a) => Some(a.parse().map_err(|e| {
                    FluxError::Config(format!(
                        "outbound '{}': invalid local_address '{}': {}",
                        tag, a, e
                    ))
                })?),
                None => None,
            };
            let wg_cfg = flux_protocol::wireguard::WireGuardConfig {
                private_key: priv_k,
                peer_public_key: pub_k,
                preshared_key: psk,
                server_address: target,
                local_address: local_ip,
                keepalive_secs,
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
            obfs,
            obfs_password,
        } => {
            let (q_sni, q_insecure, q_alpn, q_ca) = extract_quic_tls_params(&node.security);
            let hy2_cfg = flux_protocol::hysteria2::Hysteria2Config {
                server: target.host(),
                ports: vec![target.port()],
                password,
                up_mbps,
                down_mbps,
                hop_interval_secs: hop_interval_secs.unwrap_or(30),
                insecure: q_insecure,
                server_name: q_sni,
                obfs: resolve_hy2_obfs(obfs.as_deref(), obfs_password)?,
                alpn: q_alpn,
                ca_certs: q_ca,
                h3: h3.unwrap_or(true),
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
            let (q_sni, q_insecure, q_alpn, q_ca) = extract_quic_tls_params(&node.security);
            let tuic_cfg = flux_protocol::tuic::TuicV5Config {
                server: target.host(),
                server_port: target.port(),
                uuid: parsed_uuid,
                password,
                congestion_control: congestion_control.unwrap_or_else(|| "bbr".into()),
                zero_rtt: zero_rtt.unwrap_or(true),
                insecure: q_insecure,
                server_name: q_sni,
                alpn: q_alpn,
                ca_certs: q_ca,
            };
            let out = flux_outbound::TuicOutbound::new_with_dialer(tag.clone(), tuic_cfg, dialer);
            registry.insert(tag, Arc::new(out));
        }
    }
    Ok(())
}

fn parse_inbound_carrier(carrier: &InboundCarrierConfig) -> FluxResult<(SocketAddr, bool)> {
    match carrier {
        InboundCarrierConfig::Kcp {
            listen,
            listen_port,
            address,
            ..
        } => {
            // The port is ordinary; only the carrier differs. VLESS is the protocol
            // wired to it so far.
            let l_str = address
                .clone()
                .or_else(|| listen.clone())
                .unwrap_or_else(|| "0.0.0.0".to_string());
            let s = join_host_port(&l_str, listen_port.unwrap_or(0));
            let a = s
                .parse::<SocketAddr>()
                .map_err(|e| FluxError::Config(format!("invalid listen addr {}: {}", s, e)))?;
            Ok((a, true))
        }
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
                let s = join_host_port(l_str, listen_port.unwrap_or(0));
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
                let s = join_host_port(l_str, listen_port.unwrap_or(0));
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
                alpn,
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
                let alpn: Vec<Vec<u8>> = alpn.into_iter().map(|s| s.into_bytes()).collect();
                let acceptor = TlsTransport::create_server_acceptor(certs, key, alpn)?;
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
                    flux_transport::reality::RealityServerConfig::new(
                        server_names,
                        pk_bytes,
                        sids,
                        fallback,
                    ),
                ));
            }
            InboundSecurityConfig::ShadowTls {
                version,
                password,
                fallback,
                server_names,
            } => {
                if version != 3 {
                    return Err(FluxError::Config(format!(
                        "shadowtls inbound: version {version} is not supported (only 3); \
                         serving it as v3 would silently mis-negotiate"
                    )));
                }
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
                        server_names: server_names.clone(),
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
            InboundFramingConfig::Xhttp { path, settings } => {
                settings
                    .validate("inbound xhttp")
                    .map_err(flux_types::FluxError::Config)?;
                list.push(flux_transport::pipeline::ServerFramingLayer::Xhttp {
                    path,
                    no_sse_header: settings.no_sse_header.unwrap_or(false),
                });
            }
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
    // mKCP is a stream carrier that happens to travel over UDP: the protocol above it
    // is unchanged, so it must not take the datagram paths.
    let is_kcp = matches!(node.carrier, InboundCarrierConfig::Kcp { .. });
    let rate_limiter = node.rate_limit.as_ref().map(|c| c.build());
    // Multiplexing needs a stream carrier and a stream protocol.
    let mux = node
        .multiplex
        .as_ref()
        .map(|config| config.build())
        .transpose()?
        .flatten();
    if mux.is_some() && is_udp {
        return Err(FluxError::Config(format!(
            "inbound '{}': multiplex requires a tcp carrier",
            tag
        )));
    }
    if mux.is_some()
        && !matches!(
            node.protocol,
            ProtocolConfig::Vless { .. }
                | ProtocolConfig::Vmess { .. }
                | ProtocolConfig::Trojan { .. }
                | ProtocolConfig::Shadowsocks { .. }
        )
    {
        return Err(FluxError::Config(format!(
            "inbound '{}': multiplex is only supported for vless, vmess, trojan and shadowsocks",
            tag
        )));
    }
    let mux = mux.filter(|_| !is_udp);

    // mKCP is a stream carrier that travels over UDP: its protocol is handled below,
    // like TCP, and must not fall into the datagram branches.
    if is_udp && !is_kcp {
        match node.protocol {
            ProtocolConfig::Shadowsocks { password, method } => {
                let cipher_kind = match method.as_deref() {
                    // An omitted method means the documented default.
                    None => flux_protocol::shadowsocks::CipherKind::default(),
                    Some(name) => flux_protocol::shadowsocks::CipherKind::parse_str(name)
                        .ok_or_else(|| {
                            FluxError::Config(format!(
                                "unsupported shadowsocks method {name:?} (expected \
                                 chacha20-ietf-poly1305, aes-128-gcm or aes-256-gcm); silently \
                                 substituting a different cipher would make the config a lie"
                            ))
                        })?,
                };
                inbounds.push(Arc::new(
                    flux_inbound::ShadowsocksInbound::new(tag, addr, &password)
                        .with_cipher_kind(cipher_kind),
                ));
                return Ok(());
            }
            ProtocolConfig::Hysteria2 {
                password,
                obfs,
                obfs_password,
                ..
            } => {
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| FluxError::Crypto(format!("failed to generate cert: {}", e)))?;
                let certs = vec![CertificateDer::from(cert.cert)];
                let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
                let mut ib = flux_inbound::Hysteria2Inbound::new(tag, addr, password, certs, key)
                    .with_obfs_password(resolve_hy2_obfs(obfs.as_deref(), obfs_password)?);
                if let Some(rl) = rate_limiter.clone() {
                    ib = ib.with_rate_limiter(rl);
                }
                inbounds.push(Arc::new(ib));
                return Ok(());
            }
            ProtocolConfig::Tuic { uuid, password, .. } => {
                let parsed_uuid = Uuid::parse_str(&uuid)
                    .map_err(|e| FluxError::Config(format!("invalid tuic uuid {}: {}", uuid, e)))?;
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| FluxError::Crypto(format!("failed to generate cert: {}", e)))?;
                let certs = vec![CertificateDer::from(cert.cert)];
                let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
                let mut ib = flux_inbound::TuicInbound::new(
                    tag,
                    addr,
                    vec![parsed_uuid],
                    password,
                    certs,
                    key,
                );
                if let Some(rl) = rate_limiter.clone() {
                    ib = ib.with_rate_limiter(rl);
                }
                inbounds.push(Arc::new(ib));
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
            let mut ib = flux_inbound::VlessInbound::new(tag, addr, vec![parsed_uuid], pipeline);
            if is_kcp {
                // Honour the carrier's fields: this used to pass `KcpConfig::default()`,
                // so a server silently ignored `header` and `seed`.
                let cfg = node.carrier.kcp_config()?.unwrap_or_default();
                ib = ib.with_kcp(cfg);
            }
            if let Some(rl) = rate_limiter.clone() {
                ib = ib.with_rate_limiter(rl);
            }
            if let Some(mux) = mux.clone() {
                ib = ib.with_mux(mux);
            }
            inbounds.push(Arc::new(ib));
        }
        ProtocolConfig::Shadowsocks { password, method } => {
            let cipher_kind = match method.as_deref() {
                // An omitted method means the documented default.
                None => flux_protocol::shadowsocks::CipherKind::default(),
                Some(name) => {
                    flux_protocol::shadowsocks::CipherKind::parse_str(name).ok_or_else(|| {
                        FluxError::Config(format!(
                            "unsupported shadowsocks method {name:?} (expected \
                                 chacha20-ietf-poly1305, aes-128-gcm or aes-256-gcm); silently \
                                 substituting a different cipher would make the config a lie"
                        ))
                    })?
                }
            };
            let mut ib = flux_inbound::ShadowsocksInbound::new(tag, addr, &password)
                .with_cipher_kind(cipher_kind)
                .with_pipeline(pipeline);
            if let Some(rl) = rate_limiter.clone() {
                ib = ib.with_rate_limiter(rl);
            }
            if let Some(mux) = mux.clone() {
                ib = ib.with_mux(mux);
            }
            inbounds.push(Arc::new(ib));
        }
        ProtocolConfig::Trojan { password } => {
            let mut ib = flux_inbound::TrojanInbound::new(tag, addr, vec![password], pipeline);
            if let Some(rl) = rate_limiter.clone() {
                ib = ib.with_rate_limiter(rl);
            }
            if let Some(mux) = mux.clone() {
                ib = ib.with_mux(mux);
            }
            inbounds.push(Arc::new(ib));
        }
        ProtocolConfig::Vmess { uuid, .. } => {
            let parsed_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| FluxError::Config(format!("invalid vmess uuid {}: {}", uuid, e)))?;
            let mut ib = flux_inbound::VmessInbound::new(tag, addr, vec![parsed_uuid], pipeline);
            if let Some(rl) = rate_limiter.clone() {
                ib = ib.with_rate_limiter(rl);
            }
            if let Some(mux) = mux.clone() {
                ib = ib.with_mux(mux);
            }
            inbounds.push(Arc::new(ib));
        }
        ProtocolConfig::Socks { username, password } => {
            let users = match (username, password) {
                (Some(u), Some(p)) => vec![(u, p)],
                _ => vec![],
            };
            let mut ib = flux_inbound::SocksInbound::new(tag, addr)
                .with_users(users)
                .with_pipeline(pipeline);
            if let Some(rl) = rate_limiter.clone() {
                ib = ib.with_rate_limiter(rl);
            }
            inbounds.push(Arc::new(ib));
        }
        ProtocolConfig::Http { username, password } => {
            let users = match (username, password) {
                (Some(u), Some(p)) => vec![(u, p)],
                _ => vec![],
            };
            let mut ib = flux_inbound::HttpInbound::new(tag, addr)
                .with_users(users)
                .with_pipeline(pipeline);
            if let Some(rl) = rate_limiter.clone() {
                ib = ib.with_rate_limiter(rl);
            }
            inbounds.push(Arc::new(ib));
        }
        ProtocolConfig::WireGuard { .. } => {
            return Err(FluxError::Config(
                "wireguard is an L3 UDP tunnel and cannot be a layered inbound; use a system inbound instead: { \"type\": \"wireguard\", \"listen\": ..., \"private_key\": ..., \"peers\": [...] }".to_string(),
            ));
        }
        ProtocolConfig::Hysteria2 {
            password,
            obfs,
            obfs_password,
            ..
        } => {
            let obfs_pwd = resolve_hy2_obfs(obfs.as_deref(), obfs_password)?;
            if pipeline.securities.is_empty() && pipeline.framings.is_empty() {
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| FluxError::Crypto(format!("failed to generate cert: {}", e)))?;
                let certs = vec![CertificateDer::from(cert.cert)];
                let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
                let mut ib = flux_inbound::Hysteria2Inbound::new(tag, addr, password, certs, key)
                    .with_obfs_password(obfs_pwd);
                if let Some(rl) = rate_limiter.clone() {
                    ib = ib.with_rate_limiter(rl);
                }
                inbounds.push(Arc::new(ib));
            } else {
                let mut ib = flux_inbound::Hysteria2Inbound::new_with_pipeline(
                    tag, addr, password, pipeline,
                )
                .with_obfs_password(obfs_pwd);
                if let Some(rl) = rate_limiter.clone() {
                    ib = ib.with_rate_limiter(rl);
                }
                inbounds.push(Arc::new(ib));
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
                let mut ib = flux_inbound::TuicInbound::new(
                    tag,
                    addr,
                    vec![parsed_uuid],
                    password,
                    certs,
                    key,
                );
                if let Some(rl) = rate_limiter.clone() {
                    ib = ib.with_rate_limiter(rl);
                }
                inbounds.push(Arc::new(ib));
            } else {
                let mut ib = flux_inbound::TuicInbound::new_with_pipeline(
                    tag,
                    addr,
                    vec![parsed_uuid],
                    password,
                    pipeline,
                );
                if let Some(rl) = rate_limiter.clone() {
                    ib = ib.with_rate_limiter(rl);
                }
                inbounds.push(Arc::new(ib));
            }
        }
    }
    Ok(())
}

/// Lifecycle tests: they own the properties that only show up across a
/// start/stop boundary (leaked listeners, half-started instances, leaked
/// background tasks) rather than the behaviour of any single protocol.
///
/// No `sleep` is used for synchronisation: everything the tests wait for is
/// caused by another task on the same runtime (a listener dropping its socket, a
/// fetch loop running), so the tests yield to the scheduler and only use a
/// deadline to bound the *failure*.
#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::task::yield_now;

    /// Upper bound for every "wait until the OS/task catches up" loop. Generous
    /// enough for a loaded CI box, tight enough that a leaked listener fails the
    /// test instead of hanging the suite.
    const DEADLINE: Duration = Duration::from_secs(10);

    /// Hands out ports no other test in this process has received. The probe
    /// socket is closed immediately, so two tests running in parallel could
    /// otherwise be handed the same port by `bind(:0)`.
    fn unique_port(bind: impl Fn() -> u16) -> u16 {
        static HANDED_OUT: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
        let mut handed_out = HANDED_OUT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            let port = bind();
            if !handed_out.contains(&port) {
                handed_out.push(port);
                return port;
            }
        }
    }

    fn free_port() -> u16 {
        unique_port(|| {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("bind ephemeral port")
                .local_addr()
                .expect("local_addr")
                .port()
        })
    }

    fn free_udp_port() -> u16 {
        unique_port(|| {
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("bind ephemeral udp port")
                .local_addr()
                .expect("local_addr")
                .port()
        })
    }

    fn local(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    /// Holds a TCP port with a *plain* socket (no `SO_REUSEPORT`). Every proxy
    /// listener sets `SO_REUSEPORT`, and Linux refuses to add a non-REUSEPORT
    /// socket to a port that already has one — so this both simulates "the port
    /// is taken" for a start, and proves a proxy listener really went away.
    fn occupying_listener() -> (TcpListener, u16) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("occupy a port");
        let port = listener.local_addr().expect("local_addr").port();
        (listener, port)
    }

    fn tcp_port_is_free(port: u16) -> bool {
        TcpListener::bind(local(port)).is_ok()
    }

    fn udp_port_is_free(port: u16) -> bool {
        UdpSocket::bind(local(port)).is_ok()
    }

    /// Runs the scheduler until `cond` holds. Yielding — not sleeping — is the
    /// synchronisation, because the state we wait for can only change when
    /// another task on this runtime gets to run.
    async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let start = Instant::now();
        while !cond() {
            assert!(start.elapsed() < DEADLINE, "timed out waiting for {what}");
            yield_now().await;
        }
    }

    /// Number of live tasks on this test's runtime. A leaked accept loop or
    /// fetch loop shows up here as a count that never returns to the baseline.
    fn alive_tasks() -> usize {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    }

    fn tcp_inbound(tag: &str, port: u16, protocol: &str) -> String {
        format!(
            r#"{{"tag":"{tag}","carrier":{{"type":"tcp","listen":"127.0.0.1","listen_port":{port}}},"protocol":{{"type":"{protocol}"}}}}"#
        )
    }

    /// Builds a config with the given inbounds plus an optional API / DNS
    /// listener. Every listener is on loopback, so the tests need no privileges.
    fn config(inbounds: &[String], api_port: Option<u16>, dns_port: Option<u16>) -> Config {
        let mut sections: Vec<String> = Vec::new();
        if let Some(p) = api_port {
            sections.push(format!(
                r#""api": {{"listen":"127.0.0.1:{p}","secret":"lifecycle-test-token"}}"#
            ));
        }
        if let Some(p) = dns_port {
            sections.push(format!(r#""dns": {{"listen":"127.0.0.1:{p}"}}"#));
        }
        sections.push(format!(r#""inbounds": [{}]"#, inbounds.join(",")));
        sections.push(r#""outbounds": [{"type":"direct","tag":"direct"}]"#.to_string());
        Config::from_json_str(&format!("{{{}}}", sections.join(","))).expect("config must parse")
    }

    /// SOCKS5 greeting. Any answer proves a live accept loop serving the old
    /// protocol, not merely a socket that is still bound.
    async fn socks_greeting(port: u16) -> Option<u8> {
        let mut stream = TcpStream::connect(local(port)).await.ok()?;
        stream.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
        let mut reply = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply))
            .await
            .ok()?
            .ok()?;
        (reply[0] == 0x05).then_some(reply[1])
    }

    /// Property: `start()` then `stop()` frees every port the instance listened
    /// on, and the same instance can run a second cycle. A listener leaked by
    /// the first cycle is invisible everywhere except in the second `start()`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_stop_releases_every_listener_and_cycles() {
        let socks_port = free_port();
        let http_port = free_port();
        let api_port = free_port();
        let instance = Instance::new(config(
            &[
                tcp_inbound("in-socks", socks_port, "socks"),
                tcp_inbound("in-http", http_port, "http"),
            ],
            Some(api_port),
            None,
        ))
        .expect("instance");

        for cycle in 0..2 {
            instance.start().await.expect("start");

            // `start()` returning Ok is not the assertion: the sockets must
            // actually be bound now.
            for port in [socks_port, http_port, api_port] {
                assert!(
                    !tcp_port_is_free(port),
                    "cycle {cycle}: start() returned Ok but nothing is bound on {port}"
                );
            }
            assert_eq!(
                socks_greeting(socks_port).await,
                Some(0x00),
                "cycle {cycle}: the socks listener must serve, not just be bound"
            );

            instance.stop().await.expect("stop");

            for port in [socks_port, http_port, api_port] {
                wait_until(
                    &format!("port {port} to be released after stop (cycle {cycle})"),
                    || tcp_port_is_free(port),
                )
                .await;
            }
        }
    }

    /// Property: the DNS listener (UDP) is covered by the same guarantee; a
    /// leaked datagram socket would otherwise keep answering on a port the new
    /// instance also bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dns_listen_port_is_released_on_stop() {
        let dns_port = free_udp_port();
        let instance = Instance::new(config(&[], None, Some(dns_port))).expect("instance");

        instance.start().await.expect("start");
        assert!(
            !udp_port_is_free(dns_port),
            "the DNS inbound did not bind {dns_port}"
        );

        instance.stop().await.expect("stop");
        wait_until("the DNS socket to be released", || {
            udp_port_is_free(dns_port)
        })
        .await;
    }

    /// Property: `stop()` is idempotent and safe on a never-started instance;
    /// `start()` is idempotent, so a repeated call does not bind a second time
    /// (SO_REUSEPORT would happily allow that, and two accept loops would then
    /// race for the same connections).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_start_and_stop_are_idempotent() {
        let port = free_port();
        // Measured before the instance exists: `stop()` releases the
        // `TrafficMeter` sampler too, so a baseline taken after `Instance::new`
        // would be one task stale.
        let baseline = alive_tasks();
        let instance = Instance::new(config(
            &[tcp_inbound("in-socks", port, "socks")],
            None,
            None,
        ))
        .expect("instance");

        // stop() before start(): no panic, no hang, and nothing invented.
        tokio::time::timeout(Duration::from_secs(10), instance.stop())
            .await
            .expect("stop() must not hang when the instance never started")
            .expect("stop() before start() must succeed");
        assert!(tcp_port_is_free(port));

        instance.start().await.expect("first start");
        let after_start = alive_tasks();
        assert_eq!(
            after_start,
            baseline + 2,
            "one inbound must spawn exactly one accept loop, on top of the \
             instance's TrafficMeter sampler"
        );

        instance
            .start()
            .await
            .expect("a repeated start must be a no-op, not an error");
        assert_eq!(
            alive_tasks(),
            after_start,
            "a repeated start must not spawn a second accept loop"
        );

        tokio::time::timeout(Duration::from_secs(10), instance.stop())
            .await
            .expect("first stop must not hang")
            .expect("first stop must succeed");
        tokio::time::timeout(Duration::from_secs(10), instance.stop())
            .await
            .expect("second stop must not hang")
            .expect("second stop must succeed");

        wait_until("every task to exit", || alive_tasks() == baseline).await;
        assert!(
            tcp_port_is_free(port),
            "the listener must stay released after repeated stop() calls"
        );
    }

    /// Property: a start that fails half-way returns an error *and* releases the
    /// inbound it already bound. This is the state that leaks a listener nobody
    /// will ever stop — the port stays taken for the life of the process.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_start_releases_the_inbound_it_already_bound() {
        let first_port = free_port();
        let (blocker, blocked_port) = occupying_listener();
        let instance = Instance::new(config(
            &[
                tcp_inbound("in-first", first_port, "socks"),
                tcp_inbound("in-blocked", blocked_port, "http"),
            ],
            None,
            None,
        ))
        .expect("instance");
        let baseline = alive_tasks();

        instance
            .start()
            .await
            .expect_err("the second inbound cannot bind its port");

        wait_until("the already-bound inbound to be released", || {
            tcp_port_is_free(first_port)
        })
        .await;
        wait_until("every task of the failed start to exit", || {
            alive_tasks() == baseline
        })
        .await;

        // A failed start must leave the instance usable, not wedged.
        assert!(
            instance.start().await.is_err(),
            "the port is still taken; the retry must fail the same way"
        );
        wait_until("the retry to release the first listener too", || {
            tcp_port_is_free(first_port)
        })
        .await;

        // Once the obstacle is gone the very same instance must start.
        drop(blocker);
        instance
            .start()
            .await
            .expect("with the port free the same instance must start");
        assert_eq!(socks_greeting(first_port).await, Some(0x00));
        instance.stop().await.expect("stop");
        wait_until("the listener to be released", || {
            tcp_port_is_free(first_port)
        })
        .await;
    }

    /// Property: the API listener binds first, so when it cannot, no inbound may
    /// be left bound behind it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_api_bind_starts_no_inbound() {
        let (blocker, api_port) = occupying_listener();
        let inbound_port = free_port();
        let instance = Instance::new(config(
            &[tcp_inbound("in-socks", inbound_port, "socks")],
            Some(api_port),
            None,
        ))
        .expect("instance");

        instance.start().await.expect_err("the API port is taken");
        assert!(
            tcp_port_is_free(inbound_port),
            "no inbound may stay bound when the API bind fails"
        );

        drop(blocker);
        instance.start().await.expect("start once the port is free");
        instance.stop().await.expect("stop");
    }

    /// Property: a candidate config that fails to start must not disturb the
    /// running instance — the reload path builds a new instance, starts it and
    /// only then stops the old one, so a failing candidate must release what it
    /// bound and leave the old listener serving its own configuration.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_replacement_start_does_not_disturb_the_running_instance() {
        let live_port = free_port();
        let live = Instance::new(config(
            &[tcp_inbound("old-socks", live_port, "socks")],
            None,
            None,
        ))
        .expect("instance");
        live.start().await.expect("start");

        // The candidate reuses the live port (SO_REUSEPORT lets it bind, which is
        // the whole point of a zero-downtime reload) and adds an inbound on an
        // occupied port: it fails *after* it already bound something.
        let (blocker, blocked_port) = occupying_listener();
        let candidate = Instance::new(config(
            &[
                tcp_inbound("new-socks", live_port, "socks"),
                tcp_inbound("new-blocked", blocked_port, "http"),
            ],
            None,
            None,
        ))
        .expect("instance");
        // `Instance::new` already owns one task of its own (`TrafficMeter`'s
        // sampler, in api.rs), so "no leftovers" is measured against the
        // candidate's own construction baseline, not against the old instance.
        let tasks_with_candidate = alive_tasks();

        candidate
            .start()
            .await
            .expect_err("the candidate cannot bind its second inbound");

        wait_until("the failed candidate to release its accept loop", || {
            alive_tasks() == tasks_with_candidate
        })
        .await;

        assert_eq!(
            socks_greeting(live_port).await,
            Some(0x00),
            "the running instance must still serve after a failed reload"
        );

        live.stop().await.expect("stop");
        wait_until("the live listener to be released", || {
            tcp_port_is_free(live_port)
        })
        .await;
        drop(blocker);
    }

    /// Serves a rule-set body to every request and counts the requests.
    async fn spawn_ruleset_server() -> (u16, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind rule set server");
        let port = listener.local_addr().expect("local_addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = socket.read(&mut buf).await;
                    counter.fetch_add(1, Ordering::SeqCst);
                    let body = "DOMAIN-SUFFIX,example.com\n";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        (port, hits)
    }

    /// Property: `start()`/`stop()` symmetry includes background work. The fetch
    /// loops are cancelled by `stop()`, so `start()` must hand them a *fresh*
    /// cancellation token — a `CancellationToken` is one-shot, and reusing the
    /// cancelled one made every restarted instance silently stop refreshing its
    /// remote rule sets.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_after_stop_refetches_remote_rulesets() {
        let (rules_port, hits) = spawn_ruleset_server().await;
        let inbound_port = free_port();
        let cache_dir = tempfile::tempdir().expect("tempdir");
        let cache_path = cache_dir.path().join("rs.txt");
        let cfg = Config::from_json_str(&format!(
            r#"{{
                "inbounds": [{}],
                "outbounds": [{{"type":"direct","tag":"direct"}}],
                "route": {{"rule_set": [{{
                    "tag": "rs",
                    "type": "remote",
                    "path": "http://127.0.0.1:{rules_port}/rules.txt",
                    "cache_path": "{}"
                }}]}}
            }}"#,
            tcp_inbound("in-socks", inbound_port, "socks"),
            cache_path.display()
        ))
        .expect("config must parse");
        let instance = Instance::new(cfg).expect("instance");

        instance.start().await.expect("start");
        wait_until("the rule set to be fetched by the first start", || {
            hits.load(Ordering::SeqCst) == 1
        })
        .await;

        instance.stop().await.expect("stop");
        wait_until("the listener to be released", || {
            tcp_port_is_free(inbound_port)
        })
        .await;

        instance.start().await.expect("restart");
        wait_until("the rule set to be fetched again after a restart", || {
            hits.load(Ordering::SeqCst) == 2
        })
        .await;
        instance.stop().await.expect("stop");
    }

    /// Property: `stop()` is synchronous with respect to the listening sockets.
    ///
    /// A supervisor, a reload script, or `Instance::stop()` followed by
    /// `start()` binds the same ports in the very next statement, so there must
    /// be no window in which an old listener is still open. That is why this
    /// test contains no `wait_until` and no `yield_now`: the binds happen
    /// immediately after `stop().await` returns.
    ///
    /// The runtime is single-threaded on purpose. With more than one worker the
    /// polled-elsewhere accept loop could close its socket at any moment, and a
    /// test that "passes" because the other thread happened to win the race
    /// would prove nothing; here no task can run between `stop()` returning and
    /// the bind, so the assertions describe the code, not the scheduler.
    #[tokio::test(flavor = "current_thread")]
    async fn stop_releases_every_port_before_it_returns() {
        let socks_port = free_port();
        let api_port = free_port();
        let dns_port = free_udp_port();
        let instance = Instance::new(config(
            &[tcp_inbound("in-socks", socks_port, "socks")],
            Some(api_port),
            Some(dns_port),
        ))
        .expect("instance");

        instance.start().await.expect("start");
        for port in [socks_port, api_port] {
            assert!(
                !tcp_port_is_free(port),
                "start() returned Ok but nothing is bound on {port}"
            );
        }
        assert!(!udp_port_is_free(dns_port), "the DNS socket is not bound");

        instance.stop().await.expect("stop");

        // No polling loop: `stop()` has to have closed these already. All three
        // are checked before asserting so one run reports every socket that
        // outlived `stop()`, not just the first.
        let still_open: Vec<&str> = [
            (
                "the TCP listener of 'in-socks'",
                tcp_port_is_free(socks_port),
            ),
            ("the API listener", tcp_port_is_free(api_port)),
            (
                "the UDP socket of the DNS inbound",
                udp_port_is_free(dns_port),
            ),
        ]
        .into_iter()
        .filter(|(_, free)| !*free)
        .map(|(what, _)| what)
        .collect();
        assert!(
            still_open.is_empty(),
            "stop() returned with these ports still held: {still_open:?}"
        );
    }

    /// Property: `start()`/`stop()` symmetry is absolute — the runtime's task
    /// count returns to the level it had *before the instance was built*.
    ///
    /// The previous baseline was taken after `Instance::new`, which hid the
    /// `TrafficMeter` speed sampler: it was reachable only through a `Weak`, so
    /// it could not be stopped and outlived every `stop()`. Measuring from
    /// before construction is what makes the sampler a test subject rather than
    /// a constant, and a SIGHUP reload leaks exactly this way — the old
    /// instance stays alive until its last `Arc` drops.
    #[tokio::test(flavor = "current_thread")]
    async fn stop_returns_the_task_count_to_baseline() {
        let port = free_port();
        let baseline = alive_tasks();
        let instance = Instance::new(config(
            &[tcp_inbound("in-socks", port, "socks")],
            None,
            None,
        ))
        .expect("instance");
        assert!(
            alive_tasks() > baseline,
            "constructing an instance must own its sampler task"
        );

        // A stopped-but-alive instance must own nothing: this is the state a
        // SIGHUP reload leaves the old instance in, and the unstoppable
        // sampler is exactly what used to survive it. `start()` re-arms it.
        instance
            .stop()
            .await
            .expect("stop() before start() must succeed");
        assert_eq!(
            alive_tasks(),
            baseline,
            "stop() on a never-started instance must release the sampler too"
        );

        instance.start().await.expect("start");
        assert!(
            alive_tasks() > baseline + 1,
            "start() must add the accept loop on top of the sampler"
        );

        instance.stop().await.expect("stop");
        assert_eq!(
            alive_tasks(),
            baseline,
            "stop() must join the accept loop *and* the TrafficMeter sampler"
        );

        // A second cycle must neither leak nor accumulate.
        instance.start().await.expect("restart");
        instance.stop().await.expect("stop");
        assert_eq!(alive_tasks(), baseline, "a restart must be leak-free too");
    }
}

#[cfg(test)]
mod host_port_tests {
    use super::join_host_port;

    /// A v6 literal needs brackets, and a bare `format!("{host}:{port}")` produces `::1:8080`,
    /// which does not parse. This was a real defect: an IPv6 listener failed at startup with
    /// "invalid socket address syntax" in four separate places that all built the address by hand.
    #[test]
    fn a_v6_listen_host_gets_brackets() {
        assert_eq!(join_host_port("::1", 8080), "[::1]:8080");
        assert_eq!(join_host_port("::", 443), "[::]:443");
        assert_eq!(join_host_port("fe80::1", 80), "[fe80::1]:80");
    }

    /// An IPv4 host and a bracketed v6 host are passed through unchanged, so the helper cannot
    /// double-bracket a value that already has them.
    #[test]
    fn v4_and_already_bracketed_hosts_are_unchanged() {
        assert_eq!(join_host_port("127.0.0.1", 8080), "127.0.0.1:8080");
        assert_eq!(join_host_port("0.0.0.0", 1), "0.0.0.0:1");
        assert_eq!(join_host_port("[::1]", 8080), "[::1]:8080");
    }

    /// And the result parses, which is the property that actually matters.
    #[test]
    fn every_result_parses_as_a_socket_address() {
        for (host, port) in [
            ("::1", 8080u16),
            ("::", 0),
            ("127.0.0.1", 53),
            ("fe80::abcd", 9),
        ] {
            let joined = join_host_port(host, port);
            joined
                .parse::<std::net::SocketAddr>()
                .unwrap_or_else(|e| panic!("{joined} must parse: {e}"));
        }
    }
}
