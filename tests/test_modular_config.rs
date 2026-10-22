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
