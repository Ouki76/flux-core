//! Negative-path tests for the local API's authentication.
//!
//! The existing API suite only exercises the happy path (correct token). An auth
//! bypass would therefore go unnoticed, so this file asserts the refusals:
//! missing token, wrong token, wrong scheme, cross-origin query-string token, and
//! that a rejected request never executes its side effect.

mod common;

use common::get_free_tcp_port;
use flux_app::{Config, Instance};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SECRET: &str = "audit-secret-token-42";

async fn start_api() -> (Instance, u16) {
    let api_port = get_free_tcp_port().await;
    let cfg = Config::from_json_str(&format!(
        r#"{{
            "api": {{ "listen": "127.0.0.1:{api_port}", "secret": "{SECRET}" }},
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "blocked" }}
            ]
        }}"#
    ))
    .expect("config");
    let instance = Instance::new(cfg).expect("instance");
    instance.start().await.expect("start");
    // Wait for the listener instead of sleeping blind.
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", api_port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (instance, api_port)
}

/// Sends a raw request and returns (status line, body).
async fn request(port: u16, raw: &str) -> (String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to api");
    s.write_all(raw.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.lines().next().unwrap_or_default().to_string();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

#[tokio::test]
async fn request_without_token_is_rejected() {
    let (instance, port) = start_api().await;
    let (status, _) = request(
        port,
        "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        status.contains("401"),
        "a request with no credentials must be 401, got: {status}"
    );
    let _ = instance.stop().await;
}

#[tokio::test]
async fn wrong_token_is_rejected() {
    let (instance, port) = start_api().await;
    let (status, _) = request(
        port,
        "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        status.contains("401"),
        "wrong token must be 401, got: {status}"
    );
    let _ = instance.stop().await;
}

/// A token with the wrong scheme must not be accepted — otherwise any header
/// carrying the secret (`X-Whatever: <secret>`) would authenticate.
#[tokio::test]
async fn wrong_authorization_scheme_is_rejected() {
    let (instance, port) = start_api().await;
    let (status, _) = request(
        port,
        &format!(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {SECRET}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(
        status.contains("401"),
        "Basic with the raw secret must not authenticate, got: {status}"
    );
    let _ = instance.stop().await;
}

/// A missing prefix (`Authorization: <secret>`) must also fail.
#[tokio::test]
async fn bare_authorization_value_is_rejected() {
    let (instance, port) = start_api().await;
    let (status, _) = request(
        port,
        &format!(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: {SECRET}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(
        status.contains("401"),
        "an unprefixed Authorization value must not authenticate, got: {status}"
    );
    let _ = instance.stop().await;
}

/// Query-string tokens are accepted for convenience, but only from a local
/// origin: a web page must not be able to drive the API through an <img> tag.
#[tokio::test]
async fn query_token_from_foreign_origin_is_rejected() {
    let (instance, port) = start_api().await;
    let (status, _) = request(
        port,
        &format!(
            "GET /api/v1/status?token={SECRET} HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(
        status.contains("403"),
        "cross-origin query-token request must be 403, got: {status}"
    );
    let _ = instance.stop().await;
}

/// The happy path still works, so the tests above prove rejection rather than a
/// blanket denial.
#[tokio::test]
async fn correct_token_is_accepted() {
    let (instance, port) = start_api().await;
    let (status, body) = request(
        port,
        &format!(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(
        status.contains("200"),
        "correct token must be 200, got: {status}"
    );
    assert!(
        body.contains("flux-core"),
        "status body must describe the engine, got: {body}"
    );
    let _ = instance.stop().await;
}

/// A rejected state-changing request must not have executed: the selected
/// outbound stays as configured.
#[tokio::test]
async fn rejected_request_does_not_execute_its_side_effect() {
    let api_port = get_free_tcp_port().await;
    let cfg = Config::from_json_str(&format!(
        r#"{{
            "api": {{ "listen": "127.0.0.1:{api_port}", "secret": "{SECRET}" }},
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "blocked" }},
                {{ "type": "selector", "tag": "sel", "outbounds": ["direct", "blocked"], "default": "direct" }}
            ]
        }}"#
    ))
    .expect("config");
    let instance = Instance::new(cfg).expect("instance");
    instance.start().await.expect("start");
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", api_port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Try to switch the selector without credentials.
    let (status, _) = request(
        api_port,
        "PUT /api/v1/outbounds/sel/select HTTP/1.1\r\nHost: localhost\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"outbound\":\"blocked\"}",
    )
    .await;
    assert!(
        status.contains("401"),
        "unauthenticated PUT must be 401, got: {status}"
    );

    // The selection must be unchanged.
    let sel = instance.registry.get_outbound("sel").expect("selector");
    assert_eq!(
        sel.current_selected().as_deref(),
        Some("direct"),
        "a rejected request must not change state"
    );
    let _ = instance.stop().await;
}

// ---------------------------------------------------------------------------
// Request framing: smuggling pairs and method discipline
// ---------------------------------------------------------------------------

/// `Content-Length` + `Transfer-Encoding` in one request is the classic request
/// smuggling pair. We do not implement chunked bodies, so the header must be
/// refused rather than ignored: ignoring it makes the body length zero here while
/// a front-end proxy may forward a body that becomes the next request.
#[tokio::test]
async fn transfer_encoding_is_refused() {
    let (instance, port) = start_api().await;
    let (resp, _body) = request(
        port,
        &format!(
            "POST /api/v1/route/test HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\n\
             Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ),
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 400"),
        "a Transfer-Encoding header must be refused, got: {resp}"
    );
    let _ = instance.stop().await;
}

/// Two conflicting `Content-Length` headers must be a hard error, not a
/// last-one-wins decision.
#[tokio::test]
async fn conflicting_content_lengths_are_refused() {
    let (instance, port) = start_api().await;
    let (resp, _body) = request(
        port,
        &format!(
            "POST /api/v1/route/test HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\n\
             Content-Length: 2\r\nContent-Length: 40\r\n\r\n{{}}"
        ),
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 400"),
        "conflicting Content-Length headers must be refused, got: {resp}"
    );
    let _ = instance.stop().await;
}

/// A non-numeric Content-Length must be rejected, not silently treated as zero.
#[tokio::test]
async fn a_non_numeric_content_length_is_refused() {
    let (instance, port) = start_api().await;
    let (resp, _body) = request(
        port,
        &format!(
            "POST /api/v1/route/test HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\n\
             Content-Length: abc\r\n\r\n"
        ),
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 400"),
        "a non-numeric Content-Length must be refused, got: {resp}"
    );
    let _ = instance.stop().await;
}

/// A `..` segment must not be normalised into a different endpoint.
#[tokio::test]
async fn a_dot_segment_does_not_reach_another_endpoint() {
    let (instance, port) = start_api().await;
    for uri in [
        "/api/v1/outbounds/../status",
        "/api/v1/./status",
        "/api/v1/status/",
        "/api/v1//status",
    ] {
        let (resp, _body) = request(
            port,
            &format!("GET {uri} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(
            !resp.contains("uptime") && !resp.contains("version"),
            "{uri} reached an endpoint it should not: {resp}"
        );
    }
    let _ = instance.stop().await;
}

/// An unknown method on a known path must be a 4xx, never a silent success.
#[tokio::test]
async fn an_unknown_method_is_not_dispatched() {
    let (instance, port) = start_api().await;
    for method in ["DELETE", "PATCH", "TRACE", "FOOBAR"] {
        let (resp, _body) = request(
            port,
            &format!(
                "{method} /api/v1/status HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {SECRET}\r\n\r\n"
            ),
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 4") || resp.starts_with("HTTP/1.1 5"),
            "{method} on /status returned {resp}"
        );
        assert!(
            !resp.contains("uptime"),
            "{method} dispatched a GET handler: {resp}"
        );
    }
    let _ = instance.stop().await;
}
