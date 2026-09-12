#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::io;
#[cfg(target_os = "linux")]
use tokio::io::Interest;
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
struct Pipe {
    reader: libc::c_int,
    writer: libc::c_int,
}

#[cfg(target_os = "linux")]
impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // Expand in-kernel pipe capacity to 1MB to saturate multi-gigabit connections
        unsafe {
            libc::fcntl(fds[0], libc::F_SETPIPE_SZ, 1048576);
        };
        Ok(Self {
            reader: fds[0],
            writer: fds[1],
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.reader);
            libc::close(self.writer);
        }
    }
}

/// Linux zero-copy unidirectional splice between two TCP streams via an in-kernel pipe.
#[cfg(target_os = "linux")]
async fn splice_direction(read_stream: &TcpStream, write_stream: &TcpStream) -> io::Result<u64> {
    let pipe = Pipe::new()?;
    let mut transferred: u64 = 0;
    const SPLICE_CHUNK: usize = 1048576; // 1 MB batch size

    loop {
        // 1. Drain socket into pipe in a non-blocking kernel loop
        let mut pipe_filled = 0usize;
        let mut eof = false;

        read_stream
            .async_io(Interest::READABLE, || {
                loop {
                    let to_splice = SPLICE_CHUNK.saturating_sub(pipe_filled);
                    if to_splice == 0 {
                        return Ok(());
                    }

                    let res = unsafe {
                        libc::splice(
                            read_stream.as_raw_fd(),
                            std::ptr::null_mut(),
                            pipe.writer,
                            std::ptr::null_mut(),
                            to_splice,
                            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                        )
                    };
                    if res < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::WouldBlock {
                            if pipe_filled > 0 {
                                return Ok(());
                            }
                            return Err(err);
                        }
                        return Err(err);
                    }
                    if res == 0 {
                        eof = true;
                        return Ok(());
                    }
                    pipe_filled += res as usize;
                }
            })
            .await?;

        if eof && pipe_filled == 0 {
            unsafe {
                libc::shutdown(write_stream.as_raw_fd(), libc::SHUT_WR);
            }
            break;
        }

        // 2. Drain in-kernel pipe into output socket in a non-blocking loop
        let mut pipe_rem = pipe_filled;
        while pipe_rem > 0 {
            let mut n_written = 0;
            write_stream
                .async_io(Interest::WRITABLE, || {
                    loop {
                        if pipe_rem == 0 {
                            return Ok(());
                        }
                        let res = unsafe {
                            libc::splice(
                                pipe.reader,
                                std::ptr::null_mut(),
                                write_stream.as_raw_fd(),
                                std::ptr::null_mut(),
                                pipe_rem,
                                libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
                            )
                        };
                        if res < 0 {
                            let err = io::Error::last_os_error();
                            if err.kind() == io::ErrorKind::WouldBlock {
                                if n_written > 0 {
                                    return Ok(());
                                }
                                return Err(err);
                            }
                            return Err(err);
                        }
                        n_written += res as usize;
                        pipe_rem -= res as usize;
                    }
                })
                .await?;

            transferred += n_written as u64;
        }

        if eof {
            unsafe {
                libc::shutdown(write_stream.as_raw_fd(), libc::SHUT_WR);
            }
            break;
        }
    }

    Ok(transferred)
}

/// Linux zero-copy bidirectional splice.
/// Falls back to standard copy_bidirectional if splice is unsupported or on non-Linux OS.
pub async fn copy_bidirectional_zero_copy(
    a: &TcpStream,
    b: &TcpStream,
) -> io::Result<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        let t1 = splice_direction(a, b);
        let t2 = splice_direction(b, a);
        tokio::try_join!(t1, t2)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut ca = a.try_clone().await?;
        let mut cb = b.try_clone().await?;
        crate::copy::copy_bidirectional(&mut ca, &mut cb).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_zero_copy_splice() {
        // Setup echo target server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 12];
            socket.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"SPLICE_HELLO");
            socket.write_all(b"SPLICE_REPLY").await.unwrap();
        });

        // Setup proxy listener
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        // Run proxy relay with copy_bidirectional_zero_copy
        tokio::spawn(async move {
            let (client_stream, _) = proxy_listener.accept().await.unwrap();
            let target_stream = TcpStream::connect(echo_addr).await.unwrap();
            let _ = copy_bidirectional_zero_copy(&client_stream, &target_stream).await;
        });

        // Client connects to proxy
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"SPLICE_HELLO").await.unwrap();
        let _ = client.shutdown().await;

        let mut buf = vec![0u8; 12];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"SPLICE_REPLY");
    }
}
