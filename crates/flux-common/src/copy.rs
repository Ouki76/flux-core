use tokio::io::{AsyncRead, AsyncWrite};

pub const DEFAULT_COPY_BUFFER_SIZE: usize = 128 * 1024; // 128 KB matches Linux TCP socket wmem/rmem

/// Bidirectional copy between two streams using lock-free Tokio copy with 256KB buffers.
pub async fn copy_bidirectional<A, B>(mut a: A, mut b: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, DEFAULT_COPY_BUFFER_SIZE, DEFAULT_COPY_BUFFER_SIZE).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_copy_bidirectional() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (proxy_in, mut proxy_out) = tokio::io::duplex(1024);

        let t1 = tokio::spawn(async move {
            client.write_all(b"hello from client").await.unwrap();
            client.shutdown().await.unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut client, &mut buf).await.unwrap();
            assert_eq!(buf, b"reply from server");
        });

        let t2 = tokio::spawn(async move {
            let mut buf = vec![0u8; 17];
            tokio::io::AsyncReadExt::read_exact(&mut proxy_out, &mut buf).await.unwrap();
            assert_eq!(&buf, b"hello from client");
            proxy_out.write_all(b"reply from server").await.unwrap();
            proxy_out.shutdown().await.unwrap();
        });

        let (up, down) = copy_bidirectional(server, proxy_in).await.unwrap();
        assert_eq!(up, 17);
        assert_eq!(down, 17);

        t1.await.unwrap();
        t2.await.unwrap();
    }
}
