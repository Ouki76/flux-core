use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use flux_types::{FluxError, FluxResult, TargetAddress};

pub struct HttpHandshake;

impl HttpHandshake {
    /// Server-side: parse HTTP CONNECT or standard forward GET/POST request from incoming stream.
    /// Returns target address and optional reconstructed prefix bytes for origin-form requests.
    pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
    ) -> FluxResult<(TargetAddress, Option<Vec<u8>>)> {
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

        if method.eq_ignore_ascii_case("CONNECT") {
            let target: TargetAddress = uri.parse().map_err(|_| FluxError::Protocol {
                protocol: "http",
                message: format!("invalid target in CONNECT: {}", uri),
            })?;

            // Send 200 Connection Established
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            stream.flush().await?;

            Ok((target, None))
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
                let new_request_line = format!("{} {} {}\r\n", method, path, version);
                let remaining_headers = header_str.split_once("\r\n").map(|(_, rest)| rest).unwrap_or("");
                let mut reconstructed = Vec::new();
                reconstructed.extend_from_slice(new_request_line.as_bytes());
                reconstructed.extend_from_slice(remaining_headers.as_bytes());

                Ok((target, Some(reconstructed)))
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
        let req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
            target, target
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
}
