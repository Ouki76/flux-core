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
                { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 10888 }
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
            { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": ${FLUX_TEST_INBOUND_PORT} }
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
        flux_app::InboundConfig::Socks { listen_port, .. } => {
            assert_eq!(*listen_port, 19999);
        }
        _ => panic!("expected socks inbound"),
    }

    let api_cfg = cfg.api.unwrap();
    assert_eq!(api_cfg.secret.as_deref(), Some("supersecret123"));
    assert_eq!(api_cfg.listen.as_deref(), Some("127.0.0.1:9099"));
}
