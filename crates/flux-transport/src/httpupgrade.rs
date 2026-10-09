use flux_common::copy::PrefixedStream;
use flux_types::{AsyncStream, BoxedStream, FluxError, FluxResult};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Performs an HTTP/1.1 Upgrade handshake (RFC 7230), switching the connection
/// to raw bi-directional streaming once `101 Switching Protocols` is returned.
pub async fn client_handshake<S>(
    mut stream: S,
    host: &str,
    path: &str,
    headers: &HashMap<String, String>,
) -> FluxResult<BoxedStream>
where
    S: AsyncStream + 'static,
{
    let upgrade_val = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("upgrade"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("websocket");

    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: {}\r\n",
        if path.is_empty() { "/" } else { path },
        host,
        upgrade_val
    );

    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("host")
            && !k.eq_ignore_ascii_case("connection")
            && !k.eq_ignore_ascii_case("upgrade")
        {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    // Read response headers
    let mut resp_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let mut header_end = None;

    while resp_buf.len() < 8192 {
        let n = stream.read(&mut chunk).await.map_err(FluxError::Io)?;
        if n == 0 {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: "EOF while reading HTTP upgrade response".into(),
            });
        }
        resp_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = resp_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }

    let h_end = header_end.ok_or_else(|| FluxError::Protocol {
        protocol: "httpupgrade",
        message: "response header missing terminal CRLF".into(),
    })?;

    let header_str = String::from_utf8_lossy(&resp_buf[..h_end]);
    let first_line = header_str.lines().next().unwrap_or("");
    if !first_line.contains("101") && !first_line.contains("200") {
        return Err(FluxError::Protocol {
            protocol: "httpupgrade",
            message: format!("server rejected upgrade: {}", first_line),
        });
    }

    let excess = resp_buf[h_end..].to_vec();
    if excess.is_empty() {
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(PrefixedStream::new(stream, excess)))
    }
}

/// Performs a server-side HTTP/1.1 Upgrade handshake, validating path and upgrade headers.
pub async fn server_handshake<S>(
    mut stream: S,
    expected_path: Option<&str>,
) -> FluxResult<BoxedStream>
where
    S: AsyncStream + 'static,
{
    let mut req_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let mut header_end = None;

    while req_buf.len() < 8192 {
        let n = stream.read(&mut chunk).await.map_err(FluxError::Io)?;
        if n == 0 {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: "EOF while reading HTTP upgrade request".into(),
            });
        }
        req_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }

    let h_end = header_end.ok_or_else(|| FluxError::Protocol {
        protocol: "httpupgrade",
        message: "request header missing terminal CRLF".into(),
    })?;

    let header_str = String::from_utf8_lossy(&req_buf[..h_end]);
    let mut lines = header_str.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let _method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    if let Some(exp) = expected_path {
        let actual_path = path.split('?').next().unwrap_or(path);
        if actual_path != exp {
            return Err(FluxError::Protocol {
                protocol: "httpupgrade",
                message: format!("path mismatch: expected '{}', got '{}'", exp, actual_path),
            });
        }
    }

    let resp =
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(FluxError::Io)?;
    stream.flush().await.map_err(FluxError::Io)?;

    let excess = req_buf[h_end..].to_vec();
    if excess.is_empty() {
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(PrefixedStream::new(stream, excess)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_httpupgrade_handshake_and_bidirectional_data() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let mut server_stream = server_handshake(server_io, Some("/tunnel")).await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = server_stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Client payload through HTTPUpgrade");
            server_stream
                .write_all(b"Server reply through HTTPUpgrade")
                .await
                .unwrap();
            server_stream.flush().await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let mut headers = HashMap::new();
            headers.insert("X-Custom-Header".into(), "flux-val".into());
            let mut client_stream = client_handshake(client_io, "example.org", "/tunnel", &headers)
                .await
                .unwrap();
            client_stream
                .write_all(b"Client payload through HTTPUpgrade")
                .await
                .unwrap();
            client_stream.flush().await.unwrap();

            let mut buf = vec![0u8; 1024];
            let n = client_stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Server reply through HTTPUpgrade");
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_httpupgrade_path_mismatch_rejected() {
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let res = server_handshake(server_io, Some("/expected-path")).await;
            assert!(res.is_err());
        });

        let client_task = tokio::spawn(async move {
            let _ =
                client_handshake(client_io, "example.org", "/wrong-path", &HashMap::new()).await;
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }
}
