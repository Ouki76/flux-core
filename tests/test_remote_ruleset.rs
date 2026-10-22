mod common;

use common::get_free_tcp_port;
use flux_app::{Config, Instance};
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serves a fixed rule set body over HTTP/1.1 with Connection: close.
async fn start_ruleset_http_server(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await; // consume request
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

/// A remote rule set must be fetched in the background and start matching
/// once loaded — without blocking instance startup.
#[tokio::test]
async fn test_remote_ruleset_fetch_and_route() {
    let rs_port = start_ruleset_http_server(
        "# test ruleset\nDOMAIN-SUFFIX,blocked-cdn.com\nDOMAIN,exact-blocked.org\nIP-CIDR,203.0.113.0/24\n",
    )
    .await;
    let _api_port = get_free_tcp_port().await;
    // A private cache file: the default path hashes the URL, and the port
    // allocator restarts at the same base in every process, so a cache written by
    // an earlier run would be restored at construction and the rule would already
    // match before start() — which is exactly what this test asserts it does not.
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path = cache_dir.path().join("rules.cache");

    let raw_config = format!(
        r#"{{
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "block" }}
            ],
            "route": {{
                "rule_set": [
                    {{
                        "tag": "remote-rs",
                        "type": "remote",
                        "path": "http://127.0.0.1:{}/rules.txt",
                        "cache_path": "{}"
                    }}
                ],
                "rules": [
                    {{ "rule_set": ["remote-rs"], "outbound": "block" }}
                ],
                "final": "direct"
            }}
        }}"#,
        rs_port,
        cache_path.display()
    );

    let cfg = Config::from_json_str(&raw_config).unwrap();
    let instance = Instance::new(cfg).unwrap();

    // Before the fetch completes, the ruleset matches nothing → direct.
    let meta = SessionMeta::new(
        "127.0.0.1:1000".parse().unwrap(),
        TargetAddress::domain("cdn.blocked-cdn.com", 443),
        "test",
        NetworkType::Tcp,
    );
    assert_eq!(instance.router.route(&meta), "direct");

    instance.start().await.unwrap();

    // Poll until the background fetch lands (bounded wait).
    let mut matched = false;
    for _ in 0..100 {
        if instance.router.route(&meta) == "block" {
            matched = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(matched, "remote rule set never started matching");

    // Exact domain entry from the remote file.
    let meta_exact = SessionMeta::new(
        "127.0.0.1:1000".parse().unwrap(),
        TargetAddress::domain("exact-blocked.org", 443),
        "test",
        NetworkType::Tcp,
    );
    assert_eq!(instance.router.route(&meta_exact), "block");

    // IP-CIDR entry from the remote file.
    let meta_ip = SessionMeta::new(
        "127.0.0.1:1000".parse().unwrap(),
        "203.0.113.10:443".parse().unwrap(),
        "test",
        NetworkType::Tcp,
    );
    assert_eq!(instance.router.route(&meta_ip), "block");

    // Non-listed destination still goes direct.
    let meta_other = SessionMeta::new(
        "127.0.0.1:1000".parse().unwrap(),
        TargetAddress::domain("example.com", 443),
        "test",
        NetworkType::Tcp,
    );
    assert_eq!(instance.router.route(&meta_other), "direct");

    instance.stop().await.unwrap();
}

/// An unreachable remote rule set must not break instance startup; routing
/// falls back to the remaining rules.
#[tokio::test]
async fn test_remote_ruleset_fetch_failure_is_non_fatal() {
    let raw_config = r#"{
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" }
        ],
        "route": {
            "rule_set": [
                { "tag": "dead-rs", "type": "remote", "path": "http://127.0.0.1:1/never.txt" }
            ],
            "rules": [
                { "rule_set": ["dead-rs"], "outbound": "block" }
            ],
            "final": "direct"
        }
    }"#;

    let cfg = Config::from_json_str(raw_config).unwrap();
    let instance = Instance::new(cfg).unwrap();
    instance.start().await.unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:1000".parse().unwrap(),
        TargetAddress::domain("anything.com", 443),
        "test",
        NetworkType::Tcp,
    );
    assert_eq!(instance.router.route(&meta), "direct");

    instance.stop().await.unwrap();
}

#[tokio::test]
async fn test_remote_ruleset_disk_cache_survives_restart() {
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path = cache_dir.path().join("rs-cache.txt");
    let rs_port = start_ruleset_http_server("DOMAIN-SUFFIX,cached-domain.com\n").await;

    let make_config = |port: u16| {
        format!(
            r#"{{
                "outbounds": [
                    {{ "type": "direct", "tag": "direct" }},
                    {{ "type": "block", "tag": "block" }}
                ],
                "route": {{
                    "rule_set": [
                        {{
                            "tag": "cached-rs",
                            "type": "remote",
                            "path": "http://127.0.0.1:{}/rules.txt",
                            "cache_path": "{}"
                        }}
                    ],
                    "rules": [
                        {{ "rule_set": ["cached-rs"], "outbound": "block" }}
                    ],
                    "final": "direct"
                }}
            }}"#,
            port,
            cache_path.display()
        )
    };

    // Phase 1: live server — fetch populates the cache file.
    {
        let cfg = Config::from_json_str(&make_config(rs_port)).unwrap();
        let instance = Instance::new(cfg).unwrap();
        instance.start().await.unwrap();

        let meta = SessionMeta::new(
            "127.0.0.1:1000".parse().unwrap(),
            TargetAddress::domain("www.cached-domain.com", 443),
            "test",
            NetworkType::Tcp,
        );
        let mut ok = false;
        for _ in 0..100 {
            if instance.router.route(&meta) == "block" {
                ok = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(ok, "remote ruleset must load from the live server");
        instance.stop().await.unwrap();
    }

    assert!(
        std::fs::metadata(&cache_path).is_ok(),
        "cache file must be written after a successful fetch"
    );

    // Phase 2: server down (bind a port and immediately drop it) — the
    // ruleset must match instantly from the disk cache at startup.
    let dead_port = get_free_tcp_port().await;
    {
        let cfg = Config::from_json_str(&make_config(dead_port)).unwrap();
        let instance = Instance::new(cfg).unwrap();
        // NO start() fetch needed: cache is applied in Instance::new.
        let meta = SessionMeta::new(
            "127.0.0.1:1000".parse().unwrap(),
            TargetAddress::domain("www.cached-domain.com", 443),
            "test",
            NetworkType::Tcp,
        );
        assert_eq!(
            instance.router.route(&meta),
            "block",
            "ruleset must match from disk cache without network"
        );
        instance.start().await.unwrap();
        instance.stop().await.unwrap();
    }
}
