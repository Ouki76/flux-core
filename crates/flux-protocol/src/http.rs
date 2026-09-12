use base64::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use flux_types::{FluxError, FluxResult, TargetAddress};

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
        let mut byte = [0u8; 1];

        // Read until \r\n\r\n (end of HTTP headers)
        while buf.len() < 8192 {
            stream.read_exact(&mut byte).await.map_err(|e| {
                FluxError::Protocol {
                    protocol: "http",
                    message: format!("failed to read http header byte: {}", e),
                }
            })?;
            buf.push(byte[0]);

            if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
                break;
            }
        }

        let header_str = String::from_utf8_lossy(&buf);
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

        if let Some(user_list) = users && !user_list.is_empty() {
            let mut auth_ok = false;
            if let Some(auth_val) = &proxy_auth_header_val
                && let Some(b64) = auth_val.strip_prefix("Basic ")
                && let Ok(decoded) = BASE64_STANDARD.decode(b64.trim())
            {
                let cred_str = String::from_utf8_lossy(&decoded);
                if let Some((u, p)) = cred_str.split_once(':')
                    && user_list.iter().any(|(lu, lp)| lu == u && lp == p)
                {
                    auth_ok = true;
                    authenticated_user = Some(u.to_string());
                }
            }

            if !auth_ok {
                let resp = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"flux-core\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                stream.write_all(resp.as_bytes()).await?;
                stream.flush().await?;
                return Err(FluxError::AuthFailed("HTTP proxy authentication required".into()));
            }
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            let target: TargetAddress = uri.parse().map_err(|_| FluxError::Protocol {
                protocol: "http",
                message: format!("invalid target in CONNECT: {}", uri),
            })?;

            // Send 200 Connection Established
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            stream.flush().await?;

            Ok((target, None, authenticated_user))
        } else {
            // Forward proxy GET/POST/HEAD http://example.com:80/path
            if uri.starts_with("http://") || uri.starts_with("https://") {
                let without_scheme = uri.split_once("://").map(|(_, rest)| rest).unwrap_or(uri);
                let (host_and_port, path) = match without_scheme.split_once('/') {
                    Some((hp, p)) => (hp, format!("/{}", p)),
                    None => (without_scheme, "/".to_string()),
                };
                let target: TargetAddress = if host_and_port.contains(':') {
                    host_and_port.parse()?
                } else {
                    format!("{}:80", host_and_port).parse()?
                };

                // Reconstruct HTTP request line in origin-form: METHOD /path HTTP/1.1
                // Filter out Proxy-Authorization so credentials are not leaked upstream
                let new_request_line = format!("{} {} {}\r\n", method, path, version);
                let mut reconstructed = Vec::new();
                reconstructed.extend_from_slice(new_request_line.as_bytes());

                for line in header_str.lines().skip(1) {
                    if let Some((k, _)) = line.split_once(':')
                        && k.trim().eq_ignore_ascii_case("proxy-authorization")
                    {
                        continue; // Skip auth header upstream
                    }
                    reconstructed.extend_from_slice(line.as_bytes());
                    reconstructed.extend_from_slice(b"\r\n");
                }
                reconstructed.extend_from_slice(b"\r\n");

                Ok((target, Some(reconstructed), authenticated_user))
            } else {
                Err(FluxError::Protocol {
                    protocol: "http",
                    message: format!("unsupported http proxy method: {}", method),
                })
            }
        }
    }

    /// Client-side: establish HTTP CONNECT tunnel through an HTTP proxy.
    pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        target: &TargetAddress,
    ) -> FluxResult<()> {
        Self::client_handshake_with_auth(stream, target, None).await
    }

    /// Client-side: establish HTTP CONNECT tunnel with optional Basic credentials.
    pub async fn client_handshake_with_auth<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        target: &TargetAddress,
        auth: Option<(&str, &str)>,
    ) -> FluxResult<()> {
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
        let mut byte = [0u8; 1];
        while buf.len() < 4096 {
            stream.read_exact(&mut byte).await?;
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
                break;
            }
        }

        let resp_str = String::from_utf8_lossy(&buf);
        let first_line = resp_str.lines().next().unwrap_or("");
        if !first_line.contains("200") {
            return Err(FluxError::Protocol {
                protocol: "http",
                message: format!("http proxy connect failed: {}", first_line),
            });
        }

        Ok(())
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
            HttpHandshake::client_handshake(&mut client, &target).await.unwrap();
        });

        srv.await.unwrap();
        cli.await.unwrap();
    }

    #[tokio::test]
    async fn test_http_proxy_auth() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let allowed = vec![("agent".to_string(), "supersecret".to_string())];

        let srv = tokio::spawn(async move {
            let (target, _, user) = HttpHandshake::server_handshake_with_auth(&mut server, Some(&allowed))
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
