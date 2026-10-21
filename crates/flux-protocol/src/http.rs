use base64::prelude::*;
use flux_types::{FluxError, FluxResult, TargetAddress};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct HttpHandshake;

impl HttpHandshake {
    /// Server-side: parse HTTP CONNECT or standard forward GET/POST request from incoming stream (No Auth).
    pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
    ) -> FluxResult<(TargetAddress, Option<Vec<u8>>)> {
        let (target, prefix, _) = Self::server_handshake_with_auth(stream, None).await?;
        Ok((target, prefix))
    }

    /// Server-side: parse HTTP request with optional Proxy-Authorization (RFC 7235 Basic Auth).
    pub async fn server_handshake_with_auth<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        users: Option<&[(String, String)]>,
    ) -> FluxResult<(TargetAddress, Option<Vec<u8>>, Option<String>)> {
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 512];
        let mut header_end = None;

        // Read until \r\n\r\n or \n\n (end of HTTP headers)
        while buf.len() < 8192 {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| FluxError::Protocol {
                    protocol: "http",
                    message: format!("failed to read http header: {}", e),
                })?;
            if n == 0 {
                return Err(FluxError::Protocol {
                    protocol: "http",
                    message: "unexpected EOF reading http header".into(),
                });
            }
            buf.extend_from_slice(&chunk[..n]);

            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(pos + 4);
                break;
            } else if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
                header_end = Some(pos + 2);
                break;
            }
        }

        let h_end = header_end.ok_or_else(|| FluxError::Protocol {
            protocol: "http",
            message: "http header too large or missing terminal CRLF".into(),
        })?;

        let header_str = String::from_utf8_lossy(&buf[..h_end]);
        let mut lines = header_str.lines();
        let request_line = lines.next().ok_or_else(|| FluxError::Protocol {
            protocol: "http",
            message: "empty http request".into(),
        })?;

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let uri = parts.next().unwrap_or("");
        let version = parts.next().unwrap_or("HTTP/1.1");

        // Parse Proxy-Authorization if users are configured
        let mut authenticated_user: Option<String> = None;
        let mut proxy_auth_header_val: Option<String> = None;

        for line in header_str.lines() {
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("proxy-authorization")
            {
                proxy_auth_header_val = Some(v.trim().to_string());
            }
        }

        if let Some(user_list) = users
            && !user_list.is_empty()
        {
            let mut auth_ok = false;
            if let Some(auth_val) = &proxy_auth_header_val
                && let Some(b64) = auth_val.strip_prefix("Basic ")
                && let Ok(decoded) = BASE64_STANDARD.decode(b64.trim())
            {
                let cred_str = String::from_utf8_lossy(&decoded);
                if let Some((u, p)) = cred_str.split_once(':')
                    && user_list.iter().any(|(lu, lp)| {
                        flux_common::constant_time_eq_str(lu, u)
                            && flux_common::constant_time_eq_str(lp, p)
                    })
                {
                    auth_ok = true;
                    authenticated_user = Some(u.to_string());
                }
            }

            if !auth_ok {
                let resp = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"flux-core\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                stream.write_all(resp.as_bytes()).await?;
                stream.flush().await?;
                return Err(FluxError::AuthFailed(
                    "HTTP proxy authentication required".into(),
                ));
            }
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            let target: TargetAddress = uri.parse().map_err(|_| FluxError::Protocol {
                protocol: "http",
                message: format!("invalid target in CONNECT: {}", uri),
            })?;

            // Send 200 Connection Established
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            stream.flush().await?;

            let prefix = if buf.len() > h_end {
                Some(buf[h_end..].to_vec())
            } else {
                None
            };

            Ok((target, prefix, authenticated_user))
        } else {
            // Forward proxy request in absolute-URI form
            // (`http://example.com/path`, `https://example.com/path`) or in
            // origin-form (`/path` with a `Host:` header).
            let (target, path) = if uri.starts_with("http://") || uri.starts_with("https://") {
                // An absolute `https://` URI means the client expects TLS to the
                // origin. This proxy speaks plain HTTP to the upstream, so the
                // default port must follow the scheme: dialling 443 in cleartext
                // (or 80 for an https URL) silently sends the request to the
                // wrong service over an unencrypted connection.
                let is_tls_uri = uri.starts_with("https://");
                let default_port = if is_tls_uri { 443 } else { 80 };
                if is_tls_uri {
                    return Err(FluxError::Protocol {
                        protocol: "http",
                        message: "absolute-form https:// requests are not supported by the HTTP \
                                  proxy; use CONNECT for TLS destinations"
                            .into(),
                    });
                }
                let without_scheme = uri.split_once("://").map(|(_, rest)| rest).unwrap_or(uri);
                let (host_and_port, path) = match without_scheme.split_once('/') {
                    Some((hp, p)) => (hp, format!("/{}", p)),
                    None => (without_scheme, "/".to_string()),
                };
                let target: TargetAddress = if host_and_port.contains(':') {
                    host_and_port.parse()?
                } else {
                    format!("{}:{}", host_and_port, default_port).parse()?
                };
                (target, path)
            } else if let Some(host_hdr) = header_str.lines().find_map(|l| {
                if let Some((k, v)) = l.split_once(':')
                    && k.trim().eq_ignore_ascii_case("host")
                {
                    Some(v.trim())
                } else {
                    None
                }
            }) {
                let target: TargetAddress = if host_hdr.contains(':') {
                    host_hdr.parse()?
                } else {
                    format!("{}:80", host_hdr).parse()?
                };
                let path = if uri.is_empty() {
                    "/".to_string()
                } else {
                    uri.to_string()
                };
                (target, path)
            } else {
                return Err(FluxError::Protocol {
                    protocol: "http",
                    message: format!(
                        "unsupported http proxy request (no absolute URI or Host header): {}",
                        method
                    ),
                });
            };

            // Reconstruct HTTP request line in origin-form: METHOD /path HTTP/1.1
            // Filter out Proxy-Authorization so credentials are not leaked upstream
            let new_request_line = format!("{} {} {}\r\n", method, path, version);
            let mut reconstructed = Vec::new();
            reconstructed.extend_from_slice(new_request_line.as_bytes());

            // `header_str` includes the terminating blank line, so `lines()`
            // yields a trailing empty element; emitting it verbatim would produce
            // `\r\n\r\n\r\n` and terminate the header block one line early.
            for line in header_str.lines().skip(1).take_while(|l| !l.is_empty()) {
                if let Some((k, _)) = line.split_once(':')
                    && k.trim().eq_ignore_ascii_case("proxy-authorization")
                {
                    continue; // Skip auth header upstream
                }
                reconstructed.extend_from_slice(line.as_bytes());
                reconstructed.extend_from_slice(b"\r\n");
            }
            reconstructed.extend_from_slice(b"\r\n");

            // Append any body payload already read
            if buf.len() > h_end {
                reconstructed.extend_from_slice(&buf[h_end..]);
            }

            Ok((target, Some(reconstructed), authenticated_user))
        }
    }

    /// Client-side: establish HTTP CONNECT tunnel through an HTTP proxy.
    pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        target: &TargetAddress,
    ) -> FluxResult<Option<Vec<u8>>> {
        Self::client_handshake_with_auth(stream, target, None).await
    }

    /// Client-side: establish HTTP CONNECT tunnel with optional Basic credentials.
    /// Returns any excess buffered payload received beyond the 200 Connection Established header.
    pub async fn client_handshake_with_auth<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        target: &TargetAddress,
        auth: Option<(&str, &str)>,
    ) -> FluxResult<Option<Vec<u8>>> {
        let auth_hdr = if let Some((user, pass)) = auth {
            let cred = format!("{}:{}", user, pass);
            let b64 = BASE64_STANDARD.encode(cred);
            format!("Proxy-Authorization: Basic {}\r\n", b64)
        } else {
            String::new()
        };

        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}Proxy-Connection: Keep-Alive\r\n\r\n",
            target, target, auth_hdr
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        // Read response until \r\n\r\n
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 256];
        let mut header_end = None;

        while buf.len() < 4096 {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| FluxError::Protocol {
                    protocol: "http",
                    message: format!("failed to read http connect response: {}", e),
                })?;
            if n == 0 {
                return Err(FluxError::Protocol {
                    protocol: "http",
                    message: "unexpected EOF reading http connect response".into(),
                });
            }
            buf.extend_from_slice(&chunk[..n]);

            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(pos + 4);
                break;
            } else if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
                header_end = Some(pos + 2);
                break;
            }
        }

        let h_end = header_end.ok_or_else(|| FluxError::Protocol {
            protocol: "http",
            message: "http connect response header too large or missing terminal CRLF".into(),
        })?;

        let resp_str = String::from_utf8_lossy(&buf[..h_end]);
        let first_line = resp_str.lines().next().unwrap_or("");
        // Parse the status code rather than substring-matching "200": a reason
        // phrase containing "200", or a code like 2000, would otherwise pass.
        let status = first_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok());
        if status != Some(200) {
            return Err(FluxError::Protocol {
                protocol: "http",
                message: format!("http proxy connect failed: {}", first_line),
            });
        }

        let excess = if buf.len() > h_end {
            Some(buf[h_end..].to_vec())
        } else {
            None
        };

        Ok(excess)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http_connect_handshake() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let srv = tokio::spawn(async move {
            let (target, _) = HttpHandshake::server_handshake(&mut server).await.unwrap();
            assert_eq!(target.host(), "example.com");
            assert_eq!(target.port(), 443);
        });

        let cli = tokio::spawn(async move {
            let target = TargetAddress::domain("example.com", 443);
            HttpHandshake::client_handshake(&mut client, &target)
                .await
                .unwrap();
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }

    #[tokio::test]
    async fn test_http_proxy_auth() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let allowed = vec![("agent".to_string(), "supersecret".to_string())];

        let srv = tokio::spawn(async move {
            let (target, _, user) =
                HttpHandshake::server_handshake_with_auth(&mut server, Some(&allowed))
                    .await
                    .unwrap();
            assert_eq!(target.host(), "example.com");
            assert_eq!(user, Some("agent".to_string()));
        });

        let cli = tokio::spawn(async move {
            let target = TargetAddress::domain("example.com", 443);
            HttpHandshake::client_handshake_with_auth(
                &mut client,
                &target,
                Some(("agent", "supersecret")),
            )
            .await
            .unwrap();
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }
}

#[cfg(test)]
mod proxy_semantics_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Feeds a raw request to the server-side handshake and returns the result,
    /// plus everything the server wrote back.
    async fn feed(
        request: &[u8],
    ) -> (
        FluxResult<(TargetAddress, Option<Vec<u8>>, Option<String>)>,
        Vec<u8>,
    ) {
        let (mut client, mut server) = tokio::io::duplex(8192);
        client.write_all(request).await.unwrap();
        // Close the write side so the server never blocks waiting for more bytes.
        drop(client);

        let res = HttpHandshake::server_handshake_with_auth(&mut server, Some(&[])).await;
        // Drain whatever the server wrote (200 / 407 responses).
        let mut written = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            tokio::io::AsyncReadExt::read_to_end(&mut server, &mut written),
        )
        .await;
        (res, written)
    }

    /// An absolute `https://` URI must be refused: forwarding it in cleartext
    /// silently downgrades TLS to plaintext on port 443.
    #[tokio::test]
    async fn absolute_https_uri_is_rejected() {
        let (res, _) =
            feed(b"GET https://example.com/secret HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        let err = res.expect_err("https:// absolute form must be rejected");
        assert!(
            err.to_string().contains("not supported"),
            "unexpected error: {err}"
        );
    }

    /// Absolute `http://` form is rewritten to origin-form, and the upstream
    /// request must contain exactly one blank line (the header block terminator).
    #[tokio::test]
    async fn absolute_http_uri_is_rewritten_without_extra_crlf() {
        let (res, written) =
            feed(b"GET http://example.com/a?b=c HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n").await;
        let (target, prefix, _) = res.expect("absolute http:// form must be accepted");
        assert_eq!(target.host(), "example.com");
        assert_eq!(target.port(), 80);

        let head = prefix.expect("rewritten request must be returned");
        let text = String::from_utf8_lossy(&head);
        assert!(
            text.starts_with("GET /a?b=c HTTP/1.1\r\n"),
            "request line must be origin-form, got: {text:?}"
        );
        assert!(
            !text.contains("\r\n\r\n\r\n"),
            "header block must terminate exactly once, got: {text:?}"
        );
        // `written` holds the 200/407 reply; a forwarded request sends none.
        assert!(written.is_empty() || written.starts_with(b"HTTP/1.1 4"));
    }

    /// Origin-form with a Host header must default to port 80.
    #[tokio::test]
    async fn origin_form_uses_the_host_header() {
        let (res, _) = feed(b"GET /path HTTP/1.1\r\nHost: example.org\r\n\r\n").await;
        let (target, _, _) = res.expect("origin-form with Host must be accepted");
        assert_eq!(target.host(), "example.org");
        assert_eq!(target.port(), 80);
    }

    /// A request with neither an absolute URI nor a Host header is unusable and
    /// must be rejected rather than guessed at.
    #[tokio::test]
    async fn request_without_host_is_rejected() {
        let (res, _) = feed(b"GET /path HTTP/1.1\r\n\r\n").await;
        assert!(res.is_err(), "a request with no target must be rejected");
    }

    /// Proxy credentials must never be forwarded to the origin server.
    #[tokio::test]
    async fn proxy_authorization_is_stripped_upstream() {
        let allowed = vec![("agent".to_string(), "pw".to_string())];
        let (mut client, mut server) = tokio::io::duplex(8192);
        use base64::Engine;
        let cred = base64::engine::general_purpose::STANDARD.encode("agent:pw");
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {cred}\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        drop(client);

        let (_, prefix, user) =
            HttpHandshake::server_handshake_with_auth(&mut server, Some(&allowed))
                .await
                .expect("authenticated request must be accepted");
        assert_eq!(user.as_deref(), Some("agent"));
        let head = prefix.expect("rewritten request must be returned");
        let text = String::from_utf8_lossy(&head);
        assert!(
            !text.to_ascii_lowercase().contains("proxy-authorization"),
            "proxy credentials leaked upstream: {text:?}"
        );
    }
}
