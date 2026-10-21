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
    // One budget for the whole operation: a per-hop timeout let a slow-drip host
    // hold a refresh for MAX_REDIRECTS × FETCH_TIMEOUT.
    let deadline = tokio::time::Instant::now() + FETCH_TIMEOUT;
    for _ in 0..=MAX_REDIRECTS {
        let result = tokio::time::timeout_at(deadline, fetch_once(&current, resolver))
            .await
            .map_err(|_| {
                FluxError::Timeout(format!(
                    "remote rule set '{}': fetch exceeded {:?}",
                    url, FETCH_TIMEOUT
                ))
            })??;
        match result {
            FetchResult::Body(body) => return Ok(body),
            FetchResult::Redirect(location) => {
                // Redirects may be relative (`/new/list.txt`) and each hop must be
                // re-validated: a public URL must not be able to pivot to an
                // internal host.
                let next = resolve_location(&current, &location)?;
                // A redirect to another origin is refused: a hostile rule-set host
                // could otherwise point the fetch at 127.0.0.1, an RFC 1918 address
                // or a cloud metadata endpoint (SSRF).
                if !same_registrable_scope(&next, url) {
                    return Err(FluxError::Config(format!(
                        "remote rule set '{}': refusing redirect to a different origin ('{}')",
                        url, next
                    )));
                }
                current = next;
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

/// Resolves a possibly-relative `Location` against the request URL.
fn resolve_location(base: &str, location: &str) -> FluxResult<String> {
    let location = location.trim();
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    let (scheme, rest) = base
        .split_once("://")
        .ok_or_else(|| FluxError::Config(format!("invalid base URL '{}' during redirect", base)))?;
    if location.starts_with("//") {
        return Ok(format!("{scheme}:{location}"));
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    if location.starts_with('/') {
        return Ok(format!("{scheme}://{authority}{location}"));
    }
    // Relative to the current path's directory.
    let path = &rest[authority.len()..];
    let dir = match path.rfind('/') {
        Some(idx) => &path[..=idx],
        None => "/",
    };
    Ok(format!("{scheme}://{authority}{dir}{location}"))
}

/// True when two URLs share the same scheme and authority.
fn same_registrable_scope(a: &str, b: &str) -> bool {
    fn authority(url: &str) -> Option<(&str, &str)> {
        let (scheme, rest) = url.split_once("://")?;
        let host_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        Some((scheme, host_port))
    }
    match (authority(a), authority(b)) {
        (Some(x), Some(y)) => x.0.eq_ignore_ascii_case(y.0) && x.1.eq_ignore_ascii_case(y.1),
        _ => false,
    }
}

async fn fetch_once(url: &str, resolver: &Arc<flux_dns::DnsResolver>) -> FluxResult<FetchResult> {
    // Resolve + connect + TLS + exchange all run inside the same budget: these
    // used to sit outside it, so a black-holed host could hang the fetch for the
    // OS-level connect timeout instead of `FETCH_TIMEOUT`.
    tokio::time::timeout(FETCH_TIMEOUT, fetch_once_inner(url, resolver))
        .await
        .map_err(|_| FluxError::Timeout(format!("remote rule set '{}' fetch timed out", url)))?
}

async fn fetch_once_inner(
    url: &str,
    resolver: &Arc<flux_dns::DnsResolver>,
) -> FluxResult<FetchResult> {
    let parsed = parse_url(url)?;

    let target = TargetAddress::domain(parsed.host.clone(), parsed.port);
    let addr = resolver.resolve(&target).await?;

    let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
        FluxError::Network(format!("remote rule set '{}': connect failed: {}", url, e))
    })?;

    // `Host` must include a non-default port (RFC 7230 §5.4), otherwise vhosts on
    // custom ports reject the request.
    let default_port = if parsed.is_tls { 443 } else { 80 };
    let host_header = if parsed.port == default_port {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: flux-core-ruleset/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        parsed.path, host_header
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

        // Reject compressing responses: the rule-set parser reads plain text, and
        // a gzipped body would be silently parsed as mojibake (i.e. an empty rule
        // set, which makes every `rule_set` rule match nothing).
        if let Some(encoding) = header_str.lines().find_map(|l| {
            l.split_once(':').and_then(|(k, v)| {
                k.trim()
                    .eq_ignore_ascii_case("content-encoding")
                    .then(|| v.trim().to_ascii_lowercase())
            })
        }) && !encoding.is_empty()
            && encoding != "identity"
        {
            return Err(FluxError::Protocol {
                protocol: "http",
                message: format!(
                    "remote rule set returned Content-Encoding: {encoding} (only identity is supported)"
                ),
            });
        }

        let chunked = header_str.lines().any(|l| {
            l.split_once(':').is_some_and(|(k, v)| {
                k.trim().eq_ignore_ascii_case("transfer-encoding")
                    && v.to_ascii_lowercase().contains("chunked")
            })
        });
        let content_length: Option<usize> = header_str.lines().find_map(|l| {
            l.split_once(':').and_then(|(k, v)| {
                k.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().ok())
                    .flatten()
            })
        });

        // Read the raw body with a hard size cap. `Content-Length` is honoured
        // when present so the read terminates deterministically even if the
        // server keeps the connection open.
        let mut raw = buf.split_off(header_end);
        let mut chunk = [0u8; 16384];
        loop {
            if let Some(expected) = content_length
                && !chunked
                && raw.len() >= expected
            {
                raw.truncate(expected);
                break;
            }
            // A chunked body ends at `0\r\n\r\n`; waiting for EOF made every
            // keep-alive server stall into the fetch timeout even though the body
            // was already complete.
            if chunked && raw.ends_with(b"0\r\n\r\n") {
                break;
            }
            let n = boxed.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            if raw.len() > MAX_RESPONSE_SIZE {
                return Err(FluxError::Protocol {
                    protocol: "http",
                    message: "remote rule set response exceeds 16 MiB limit".into(),
                });
            }
        }
        if let Some(expected) = content_length
            && !chunked
            && raw.len() < expected
        {
            return Err(FluxError::Protocol {
                protocol: "http",
                message: format!(
                    "remote rule set truncated: got {} of {} bytes",
                    raw.len(),
                    expected
                ),
            });
        }

        // `Transfer-Encoding: chunked` framing must be removed before parsing,
        // otherwise the hex size lines are parsed as rule lines.
        let body = if chunked { decode_chunked(&raw)? } else { raw };

        Ok(FetchResult::Body(
            String::from_utf8_lossy(&body).into_owned(),
        ))
    };

    // The outer `fetch_once` already bounds the whole attempt.
    fut.await
}

/// Decodes an HTTP/1.1 chunked transfer-encoded body.
fn decode_chunked(mut input: &[u8]) -> FluxResult<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    loop {
        // Chunk size line: hex digits, optionally followed by `;ext`.
        let Some(line_end) = input.windows(2).position(|w| w == b"\r\n") else {
            return Err(FluxError::Protocol {
                protocol: "http",
                message: "truncated chunk size line".into(),
            });
        };
        let size_line = &input[..line_end];
        let size_str = size_line.split(|b| *b == b';').next().unwrap_or_default();
        let size_str = std::str::from_utf8(size_str).map_err(|_| FluxError::Protocol {
            protocol: "http",
            message: "non-UTF-8 chunk size".into(),
        })?;
        let size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| FluxError::Protocol {
            protocol: "http",
            message: format!("invalid chunk size '{size_str}'"),
        })?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if input.len() < size {
            return Err(FluxError::Protocol {
                protocol: "http",
                message: "chunk shorter than its declared size".into(),
            });
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size..];
        // Trailing CRLF of the chunk data.
        if input.starts_with(b"\r\n") {
            input = &input[2..];
        }
    }
}

#[cfg(test)]
mod chunked_tests {
    use super::*;

    #[test]
    fn decodes_simple_chunked_body() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"hello world");
    }

    #[test]
    fn decodes_chunk_extensions_and_keeps_content() {
        // Chunk extensions after `;` must be ignored, not treated as data.
        let body = b"4;name=value\r\nabcd\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"abcd");
    }

    #[test]
    fn rejects_truncated_chunk() {
        let body = b"a\r\nshort";
        assert!(decode_chunked(body).is_err());
    }

    #[test]
    fn rejects_missing_size_line() {
        assert!(decode_chunked(b"no-crlf-here").is_err());
    }

    #[test]
    fn rejects_invalid_hex_size() {
        assert!(decode_chunked(b"zz\r\ndata\r\n").is_err());
    }
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

#[cfg(test)]
mod redirect_tests {
    use super::*;

    #[test]
    fn absolute_redirects_pass_through() {
        assert_eq!(
            resolve_location("https://a.example/list.txt", "https://b.example/x").unwrap(),
            "https://b.example/x"
        );
    }

    #[test]
    fn root_relative_redirects_keep_the_authority() {
        assert_eq!(
            resolve_location("https://a.example/dir/list.txt", "/other.txt").unwrap(),
            "https://a.example/other.txt"
        );
    }

    #[test]
    fn path_relative_redirects_use_the_current_directory() {
        assert_eq!(
            resolve_location("https://a.example/dir/list.txt", "next.txt").unwrap(),
            "https://a.example/dir/next.txt"
        );
    }

    #[test]
    fn protocol_relative_redirects_inherit_the_scheme() {
        assert_eq!(
            resolve_location("https://a.example/x", "//cdn.example/y").unwrap(),
            "https://cdn.example/y"
        );
    }

    #[test]
    fn scope_detection_compares_scheme_and_authority() {
        assert!(same_registrable_scope(
            "https://a.example/x",
            "https://a.example/y"
        ));
        assert!(!same_registrable_scope(
            "https://a.example/x",
            "http://a.example/y"
        ));
        assert!(!same_registrable_scope(
            "https://a.example/x",
            "https://b.example/x"
        ));
    }
}
