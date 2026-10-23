use flux_app::{Config, Instance};
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn test_modular_config_includes() {
    let dir = tempdir().unwrap();
    let root_dir = dir.path();

    // 1. Write an included outbound file: outbounds/nodes.json
    let outbounds_dir = root_dir.join("outbounds");
    fs::create_dir_all(&outbounds_dir).unwrap();
    let nodes_file = outbounds_dir.join("nodes.json");
    fs::write(
        &nodes_file,
        r#"{
            "outbounds": [
                { "type": "direct", "tag": "node-us" },
                { "type": "direct", "tag": "node-eu" }
            ]
        }"#,
    )
    .unwrap();

    // 2. Write an included rules file: rules/routing.yaml
    let rules_dir = root_dir.join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    let rules_file = rules_dir.join("routing.yaml");
    fs::write(
        &rules_file,
        r#"
route:
  rules:
    - domain_suffix:
        - ".us.example.com"
      outbound: node-us
    - domain_suffix:
        - ".eu.example.com"
      outbound: node-eu
  final: direct
"#,
    )
    .unwrap();

    // 3. Write root config with $include
    let root_file = root_dir.join("config.json");
    fs::write(
        &root_file,
        r#"{
            "$include": [
                "outbounds/*.json",
                "rules/routing.yaml"
            ],
            "inbounds": [
                {
                    "tag": "socks-in",
                    "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": 10888 },
                    "protocol": { "type": "socks" }
                }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                {
                    "type": "fallback",
                    "tag": "auto-fallback",
                    "outbounds": ["node-us", "node-eu"]
                },
                {
                    "type": "loadbalance",
                    "tag": "auto-lb",
                    "outbounds": ["node-us", "node-eu"],
                    "strategy": "round-robin"
                }
            ]
        }"#,
    )
    .unwrap();

    // Load with includes
    let cfg = Config::load_with_includes(&root_file).unwrap();

    assert_eq!(cfg.inbounds.len(), 1);
    // direct + auto-fallback + auto-lb + node-us + node-eu = 5 outbounds
    assert_eq!(cfg.outbounds.len(), 5);

    let route = cfg.route.as_ref().unwrap();
    assert_eq!(route.rules.len(), 2);
    assert_eq!(route.final_outbound.as_deref(), Some("direct"));

    // Verify it instantiates without error
    let instance = Instance::new(cfg);
    assert!(instance.is_ok());
}

#[test]
fn test_config_env_var_substitution() {
    unsafe {
        std::env::set_var("FLUX_TEST_INBOUND_PORT", "19999");
        std::env::set_var("FLUX_TEST_SECRET", "supersecret123");
    }

    let raw = r#"{
        "inbounds": [
            {
                "tag": "socks-in",
                "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": ${FLUX_TEST_INBOUND_PORT} },
                "protocol": { "type": "socks" }
            }
        ],
        "outbounds": [
            { "type": "direct", "tag": "direct" }
        ],
        "api": {
            "listen": "127.0.0.1:9099",
            "secret": "${FLUX_TEST_SECRET}"
        }
    }"#;

    let cfg = Config::from_json_str(raw).unwrap();
    let inb = &cfg.inbounds[0];
    match inb {
        flux_app::InboundConfig::Node(node) => {
            assert_eq!(node.tag, "socks-in");
            match &node.carrier {
                flux_app::InboundCarrierConfig::Tcp { listen_port, .. } => {
                    assert_eq!(*listen_port, Some(19999));
                }
                _ => panic!("expected tcp carrier"),
            }
        }
        _ => panic!("expected node inbound"),
    }

    let api_cfg = cfg.api.unwrap();
    assert_eq!(api_cfg.secret.as_deref(), Some("supersecret123"));
    assert_eq!(api_cfg.listen.as_deref(), Some("127.0.0.1:9099"));
}

// ---------------------------------------------------------------------------
// ShadowTLS config wiring
// ---------------------------------------------------------------------------

fn shadowtls_outbound(version_line: &str) -> String {
    format!(
        r#"{{
            "outbounds": [{{
                "tag": "out",
                "carrier": {{ "type": "tcp", "address": "127.0.0.1:24801" }},
                "protocol": {{ "type": "vless", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811" }},
                "security": {{ "type": "shadowtls"{version_line}, "password": "hunter2", "sni": "cover.example.com" }}
            }}]
        }}"#
    )
}

/// Only ShadowTLS v3 is implemented. A config asking for v1/v2 must be refused
/// instead of silently being served as v3 — the previous code dropped the field
/// in destructuring, so the client negotiated v3 while the operator believed
/// otherwise.
#[tokio::test]
async fn shadowtls_rejects_an_unimplemented_version() {
    let cfg = flux_app::Config::from_json_str(&shadowtls_outbound(r#", "version": 2"#))
        .expect("config must parse");
    let err = flux_app::Instance::new(cfg)
        .err()
        .expect("a v2 shadowtls layer must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("version 2") && msg.contains("only 3"),
        "the error must name the version and the supported one, got: {msg}"
    );
}

/// Omitting `version` must default to 3 rather than fail.
#[tokio::test]
async fn shadowtls_version_defaults_to_three() {
    let cfg = flux_app::Config::from_json_str(&shadowtls_outbound("")).expect("config must parse");
    if let Err(e) = flux_app::Instance::new(cfg) {
        let msg = format!("{e}");
        assert!(
            !msg.contains("version"),
            "an omitted version must default to 3, got: {msg}"
        );
    }
}

/// The inbound's cover-host allow-list was hardcoded to an empty vector, so a
/// configured list could never take effect.
#[tokio::test]
async fn shadowtls_inbound_accepts_a_server_names_list() {
    let json = r#"{
        "inbounds": [{
            "tag": "st-in",
            "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": 24801 },
            "security": {
                "type": "shadowtls",
                "version": 3,
                "password": "hunter2",
                "fallback": "127.0.0.1:24802",
                "server_names": ["cover.example.com", "www.example.com"]
            },
            "protocol": { "type": "vless", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811" }
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    }"#;
    let cfg = flux_app::Config::from_json_str(json).expect("config with server_names must parse");
    if let Err(e) = flux_app::Instance::new(cfg) {
        let msg = format!("{e}");
        assert!(
            !msg.contains("server_names") && !msg.contains("unknown field"),
            "server_names must be a recognized field, got: {msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// Inert and silently-substituted configuration must be refused
// ---------------------------------------------------------------------------

/// An unknown Shadowsocks method used to fall back to ChaCha20 silently, so a
/// config asking for a cipher we do not implement negotiated something else
/// entirely — the config was a lie and the failure surfaced as "wrong cipher" on
/// the wire.
#[tokio::test]
async fn an_unknown_shadowsocks_method_is_refused() {
    let json = r#"{
        "outbounds": [{
            "tag": "ss",
            "carrier": { "type": "tcp", "address": "127.0.0.1:8388" },
            "protocol": { "type": "shadowsocks", "password": "pw", "method": "aes-192-ctr" }
        }]
    }"#;
    let cfg = flux_app::Config::from_json_str(json).expect("config must parse");
    let err = flux_app::Instance::new(cfg)
        .err()
        .expect("an unsupported cipher must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("aes-192-ctr") && msg.contains("unsupported shadowsocks method"),
        "the error must name the method, got: {msg}"
    );
}

/// The methods we do implement must still be accepted.
#[tokio::test]
async fn a_supported_shadowsocks_method_is_accepted() {
    for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
        let json = format!(
            r#"{{
                "outbounds": [{{
                    "tag": "ss",
                    "carrier": {{ "type": "tcp", "address": "127.0.0.1:8388" }},
                    "protocol": {{ "type": "shadowsocks", "password": "pw", "method": "{method}" }}
                }}]
            }}"#
        );
        let cfg = flux_app::Config::from_json_str(&json).expect("config must parse");
        if let Err(e) = flux_app::Instance::new(cfg) {
            let msg = format!("{e}");
            assert!(
                !msg.contains("unsupported shadowsocks method"),
                "{method} must be accepted, got: {msg}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// A field that is accepted but not honoured is a lie: it must be refused
// ---------------------------------------------------------------------------

async fn build(json: &str) -> Result<(), String> {
    let cfg = flux_app::Config::from_json_str(json).map_err(|e| format!("{e}"))?;
    flux_app::Instance::new(cfg)
        .map(|_| ())
        .map_err(|e| format!("{e}"))
}

const VLESS_PROTO: &str =
    r#""protocol": { "type": "vless", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811" }"#;

/// `flux` is a version marker; a typo in it used to be accepted silently.
#[tokio::test]
async fn a_malformed_version_marker_is_refused() {
    let err = build(r#"{"flux": "surely-not-a-version", "outbounds": []}"#)
        .await
        .expect_err("a malformed marker must be refused");
    assert!(err.contains("version marker"), "got: {err}");

    // The shapes a native config actually uses are accepted.
    for marker in ["1.0", "1", "v2", "flux", "flux-core"] {
        let json =
            format!(r#"{{"flux": "{marker}", "outbounds": [{{"type": "direct", "tag": "d"}}]}}"#);
        assert!(
            build(&json).await.is_ok(),
            "marker {marker:?} must be accepted"
        );
    }
}

/// TUIC congestion control and 0-RTT are not implemented; setting them used to be
/// silently ignored, so the user believed a QUIC behaviour was configured.
#[tokio::test]
async fn unimplemented_tuic_options_are_refused() {
    for field in [r#""congestion_control": "bbr""#, r#""zero_rtt": true"#] {
        let json = format!(
            r#"{{
                "outbounds": [{{
                    "tag": "t",
                    "carrier": {{ "type": "udp", "address": "127.0.0.1:8443" }},
                    "protocol": {{ "type": "tuic", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "pw", {field} }}
                }}]
            }}"#
        );
        let err = build(&json)
            .await
            .expect_err("an unimplemented TUIC option must be refused");
        assert!(
            err.contains("not implemented") || err.contains("no effect"),
            "the error must say it is unimplemented, got: {err}"
        );
    }
}

/// `h3: true` states what the code does (Hysteria 2 authenticates over HTTP/3), so it
/// is accepted; `h3: false` asks for something the implementation cannot do, and
/// port hopping has nothing to hop between because a node carries one port.
#[tokio::test]
async fn unimplemented_hysteria2_options_are_refused() {
    // Accepted: it describes reality.
    let ok = r#"{
        "outbounds": [{
            "tag": "h2",
            "carrier": { "type": "udp", "address": "127.0.0.1:8443" },
            "protocol": { "type": "hysteria2", "password": "pw", "h3": true }
        }]
    }"#;
    assert!(
        build(ok).await.is_ok(),
        "h3: true states what the code does and must be accepted"
    );

    for field in [r#""h3": false"#, r#""hop_interval_secs": 30"#] {
        let json = format!(
            r#"{{
                "outbounds": [{{
                    "tag": "h2",
                    "carrier": {{ "type": "udp", "address": "127.0.0.1:8443" }},
                    "protocol": {{ "type": "hysteria2", "password": "pw", {field} }}
                }}]
            }}"#
        );
        let err = build(&json)
            .await
            .expect_err("an unimplemented Hysteria 2 option must be refused");
        assert!(
            err.contains("h3") || err.contains("hop_interval_secs") || err.contains("hop"),
            "the error must name the field, got: {err}"
        );
    }
}

/// An inbound TLS `server_name` was destructured away — the acceptor never
/// filtered by SNI, so a config asking for it was misleading.
#[tokio::test]
async fn an_inbound_tls_server_name_is_refused() {
    let json = format!(
        r#"{{
            "inbounds": [{{
                "tag": "in",
                "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": 25811 }},
                "security": {{ "type": "tls", "server_name": "example.com" }},
                {VLESS_PROTO}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "d" }}]
        }}"#
    );
    let err = build(&json)
        .await
        .expect_err("an ignored server_name must be refused");
    assert!(err.contains("server_name"), "got: {err}");
}

// ---------------------------------------------------------------------------
// A key the schema does not know must be refused at any depth
// ---------------------------------------------------------------------------

/// `deny_unknown_fields` cannot be applied to serde's internally-tagged enums, so a
/// typo *inside* a node used to be accepted and simply ignored — the configuration
/// then did something other than what it said.
#[test]
fn an_unknown_key_inside_a_node_is_refused() {
    let json = r#"{
        "inbounds": [{
            "tag": "in",
            "carrier": { "type": "tcp", "listen": "127.0.0.1", "listen_port": 18099, "lissten": "x" },
            "protocol": { "type": "vless", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811" }
        }],
        "outbounds": [{ "type": "direct", "tag": "d" }]
    }"#;
    let err = flux_app::Config::from_json_str(json).expect_err("a typo must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("lissten"),
        "the error must name the key: {msg}"
    );
    assert!(
        msg.contains("config.inbounds[0].carrier"),
        "the error must give the path: {msg}"
    );
    assert!(
        msg.contains("listen_port"),
        "the error must list what is accepted: {msg}"
    );
}

#[test]
fn an_unknown_key_deep_inside_a_protocol_block_is_refused() {
    let json = r#"{
        "outbounds": [{
            "tag": "o",
            "carrier": { "type": "tcp", "address": "127.0.0.1:443" },
            "protocol": { "type": "trojan", "password": "pw", "pasword": "typo" }
        }]
    }"#;
    let err = flux_app::Config::from_json_str(json).expect_err("a typo must be refused");
    let msg = format!("{err}");
    assert!(msg.contains("pasword"), "{msg}");
    assert!(msg.contains("password"), "must list the real field: {msg}");
}

/// The YAML path runs the same check, because both are converted to the same value.
#[test]
fn an_unknown_key_is_refused_in_yaml_too() {
    let yaml = r#"
inbounds:
  - tag: in
    carrier: { type: tcp, listen: 127.0.0.1, listen_port: 18098, framin: ws }
    protocol: { type: vless, uuid: "b831381d-6324-4d53-ad4f-8cda48b30811" }
outbounds:
  - { type: direct, tag: d }
"#;
    let err = flux_app::Config::from_yaml_str(yaml).expect_err("a typo must be refused");
    assert!(format!("{err}").contains("framin"), "{err}");
}

/// And the alias a real config uses must not be mistaken for a typo.
#[test]
fn the_include_alias_is_not_a_typo() {
    let json = r#"{ "$include": [], "outbounds": [{ "type": "direct", "tag": "d" }] }"#;
    assert!(
        flux_app::Config::from_json_str(json).is_ok(),
        "$include is an accepted alias, not an unknown key"
    );
}
