//! Remote rule set fetching over plain HTTP/1.1 (http:// and https://).
//!
//! Intentionally minimal and dependency-free: TCP via tokio, TLS via the
//! existing `flux-transport` rustls wrapper with webpki root verification.
//! Redirects (301/302/303/307/308) are followed up to 3 times; responses are
//! bounded by a hard size cap and an overall timeout.

use flux_types::{FluxError, FluxResult, TargetAddress};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
const MAX_HEADER_SIZE: usize = 64 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: u32 = 3;

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
    is_tls: bool,
}

fn parse_url(url: &str) -> FluxResult<ParsedUrl> {
    let (is_tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(FluxError::Config(format!(
            "remote rule set URL must start with http:// or https://: '{}'",
            url
        )));
    };

    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };

    let default_port = if is_tls { 443 } else { 80 };
    let (host, port) = if host_port.starts_with('[') {
        match host_port.split_once("]:") {
            Some((h, p)) => (
                h.trim_start_matches('[').to_string(),
                p.parse::<u16>().map_err(|e| {
                    FluxError::Config(format!("invalid port in rule set URL '{}': {}", url, e))
                })?,
            ),
            None => (host_port.trim_matches(['[', ']']).to_string(), default_port),
        }
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        (
            h.to_string(),
            p.parse::<u16>().map_err(|e| {
                FluxError::Config(format!("invalid port in rule set URL '{}': {}", url, e))
            })?,
        )
    } else {
        (host_port.to_string(), default_port)
    };

    if host.is_empty() {
        return Err(FluxError::Config(format!(
            "empty host in rule set URL '{}'",
            url
        )));
    }

    Ok(ParsedUrl {
        host,
        port,
        path,
        is_tls,
    })
}

/// Fetches a remote rule set over HTTP(S), following redirects.
/// DNS resolution goes through the instance resolver (no system-resolver leaks).
pub async fn fetch_remote_ruleset(
    url: &str,
    resolver: &Arc<flux_dns::DnsResolver>,
) -> FluxResult<String> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        match fetch_once(&current, resolver).await? {
            FetchResult::Body(body) => return Ok(body),
            FetchResult::Redirect(location) => {
                current = location;
            }
        }
    }
    Err(FluxError::Network(format!(
        "remote rule set '{}': too many redirects",
        url
    )))
}

enum FetchResult {
    Body(String),
    Redirect(String),
}

async fn fetch_once(url: &str, resolver: &Arc<flux_dns::DnsResolver>) -> FluxResult<FetchResult> {
    let parsed = parse_url(url)?;

    let target = TargetAddress::domain(parsed.host.clone(), parsed.port);
    let addr = resolver.resolve(&target).await?;

    let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
        FluxError::Network(format!("remote rule set '{}': connect failed: {}", url, e))
    })?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: flux-core-ruleset/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        parsed.path, parsed.host
    );

    let fut = async {
        let mut boxed: flux_types::BoxedStream = if parsed.is_tls {
            let tls_cfg = flux_transport::tls::TlsClientConfig::new(parsed.host.clone())
                .with_alpn(vec!["http/1.1".into()]);
            Box::new(flux_transport::tls::TlsTransport::connect(stream, &tls_cfg).await?)
        } else {
            Box::new(stream)
        };

        boxed.write_all(request.as_bytes()).await?;

        // Read headers.
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        let header_end;
        loop {
            if buf.len() > MAX_HEADER_SIZE {
                return Err(FluxError::Protocol {
                    protocol: "http",
                    message: "remote rule set response headers too large".into(),
                });
            }
            let mut chunk = [0u8; 8192];
            let n = boxed.read(&mut chunk).await?;
            if n == 0 {
                return Err(FluxError::Protocol {
                    protocol: "http",
                    message: "connection closed before response headers".into(),
                });
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }

        let header_str = String::from_utf8_lossy(&buf[..header_end]).into_owned();
        let status: u16 = header_str
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| FluxError::Protocol {
                protocol: "http",
                message: "malformed HTTP status line in rule set response".into(),
            })?;

        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let location = header_str
                .lines()
                .find_map(|l| {
                    l.split_once(':').and_then(|(k, v)| {
                        if k.trim().eq_ignore_ascii_case("location") {
                            Some(v.trim().to_string())
                        } else {
                            None
                        }
                    })
                })
                .ok_or_else(|| FluxError::Protocol {
                    protocol: "http",
                    message: "redirect without Location header".into(),
                })?;
            return Ok(FetchResult::Redirect(location));
        }

        if status != 200 {
            return Err(FluxError::Network(format!(
                "remote rule set fetch failed with HTTP status {}",
                status
            )));
        }

        // Read body until EOF (Connection: close), with a hard size cap.
        let mut body = buf.split_off(header_end);
        let mut chunk = [0u8; 16384];
        loop {
            let n = boxed.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() > MAX_RESPONSE_SIZE {
                return Err(FluxError::Protocol {
                    protocol: "http",
                    message: "remote rule set response exceeds 16 MiB limit".into(),
                });
            }
        }

        Ok(FetchResult::Body(
            String::from_utf8_lossy(&body).into_owned(),
        ))
    };

    tokio::time::timeout(FETCH_TIMEOUT, fut)
        .await
        .map_err(|_| FluxError::Timeout(format!("remote rule set '{}' fetch timed out", url)))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let u = parse_url("https://example.com/list.txt").unwrap();
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/list.txt");
        assert!(u.is_tls);

        let u = parse_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/");
        assert!(!u.is_tls);

        assert!(parse_url("ftp://example.com/x").is_err());
        assert!(parse_url("https:///x").is_err());
    }
}
