use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
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
        // SAFETY: `fds` is a live two-element array, which is exactly the buffer `pipe2`
        // writes two `c_int` descriptors into.
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // Set in-kernel pipe capacity to 256KB (fewer wakeups per MB on the splice
        // hot path; kernel pipe pages are allocated lazily, so idle pipes cost ~0).
        // SAFETY: a plain fd plus integer arguments; the return value is deliberately
        // ignored because a kernel that refuses the size is not an error.
        unsafe {
            libc::fcntl(fds[0], libc::F_SETPIPE_SZ, 262144);
        };
        Ok(Self {
            reader: fds[0],
            writer: fds[1],
        })
    }

    /// Drains any remaining bytes from the in-kernel pipe in non-blocking mode
    /// to prevent cross-connection data leakage when recycled into the pool.
    fn drain(&self) -> bool {
        let mut scratch = [0u8; 16384];
        loop {
            // SAFETY: `self.reader` is an open pipe descriptor owned by this `Pipe`, and
            // `scratch` is a live array of the length passed alongside its pointer.
            let res = unsafe {
                libc::read(
                    self.reader,
                    scratch.as_mut_ptr() as *mut libc::c_void,
                    scratch.len(),
                )
            };
            if res < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EAGAIN)
                    || err.raw_os_error() == Some(libc::EWOULDBLOCK)
                {
                    return true;
                }
                return false;
            } else if res == 0 {
                return true;
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Pipe {
    fn drop(&mut self) {
        // SAFETY: `Drop` runs once per `Pipe`, and both descriptors were created by
        // `Pipe::new` and are owned by it, so each is closed exactly once.
        unsafe {
            libc::close(self.reader);
            libc::close(self.writer);
        }
    }
}

#[cfg(target_os = "linux")]
struct PipePool {
    pool: parking_lot::Mutex<Vec<Pipe>>,
}

#[cfg(target_os = "linux")]
impl PipePool {
    fn global() -> &'static Self {
        static INSTANCE: std::sync::OnceLock<PipePool> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(|| PipePool {
            pool: parking_lot::Mutex::new(Vec::with_capacity(64)),
        })
    }

    fn acquire() -> io::Result<PooledPipe> {
        if let Some(pipe) = Self::global().pool.lock().pop() {
            return Ok(PooledPipe { pipe: Some(pipe) });
        }
        let pipe = Pipe::new()?;
        Ok(PooledPipe { pipe: Some(pipe) })
    }

    fn release(pipe: Pipe) {
        if !pipe.drain() {
            // Do not recycle pipe if draining failed or descriptors encountered an error
            return;
        }
        let mut guard = Self::global().pool.lock();
        if guard.len() < 128 {
            guard.push(pipe);
        }
    }
}

#[cfg(target_os = "linux")]
struct PooledPipe {
    pipe: Option<Pipe>,
}

#[cfg(target_os = "linux")]
impl std::ops::Deref for PooledPipe {
    type Target = Pipe;
    fn deref(&self) -> &Self::Target {
        self.pipe.as_ref().unwrap()
    }
}

#[cfg(target_os = "linux")]
impl Drop for PooledPipe {
    fn drop(&mut self) {
        if let Some(pipe) = self.pipe.take() {
            PipePool::release(pipe);
        }
    }
}

/// Linux zero-copy unidirectional splice between two TCP streams via an in-kernel pipe.
#[cfg(target_os = "linux")]
async fn splice_direction(
    read_stream: &TcpStream,
    write_stream: &TcpStream,
    c1: Option<&std::sync::atomic::AtomicU64>,
    c2: Option<&std::sync::atomic::AtomicU64>,
) -> io::Result<u64> {
    let pipe = PipePool::acquire()?;
    let mut transferred: u64 = 0;
    const SPLICE_CHUNK: usize = 262144; // Matches the enlarged in-kernel pipe size

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

                    // SAFETY: both descriptors are alive for the call (borrowed from
                    // `read_stream` and the `Pipe`), the offsets are null because neither
                    // side seeks, and the length never exceeds the pipe's capacity.
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
                        if err.raw_os_error() == Some(libc::EINTR) {
                            continue; // interrupted by a signal: retry
                        }
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.raw_os_error() == Some(libc::ENOSPC)
                        {
                            if pipe_filled > 0 {
                                return Ok(());
                            }
                            return Err(io::Error::from_raw_os_error(libc::EAGAIN));
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
            // SAFETY: `write_stream` is alive and its descriptor valid; `shutdown` with
            // SHUT_WR only affects the write half.
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
                        // SAFETY: as above — both descriptors live, null offsets, length
                        // bounded by the pipe's contents.
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
                            if err.raw_os_error() == Some(libc::EINTR) {
                                continue; // interrupted by a signal: retry
                            }
                            if err.kind() == io::ErrorKind::WouldBlock
                                || err.raw_os_error() == Some(libc::ENOSPC)
                            {
                                if n_written > 0 {
                                    return Ok(());
                                }
                                return Err(io::Error::from_raw_os_error(libc::EAGAIN));
                            }
                            return Err(err);
                        }
                        n_written += res as usize;
                        pipe_rem -= res as usize;
                    }
                })
                .await?;

            transferred += n_written as u64;
            if let Some(c) = c1 {
                c.fetch_add(n_written as u64, std::sync::atomic::Ordering::Relaxed);
            }
            if let Some(c) = c2 {
                c.fetch_add(n_written as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }

        if eof {
            // SAFETY: `write_stream` is alive and its descriptor valid.
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
pub async fn copy_bidirectional_zero_copy(a: &TcpStream, b: &TcpStream) -> io::Result<(u64, u64)> {
    copy_bidirectional_zero_copy_metered(a, b, None, None, None, None).await
}

async fn copy_direction_ref(
    read_stream: &TcpStream,
    write_stream: &TcpStream,
    c1: Option<&std::sync::atomic::AtomicU64>,
    c2: Option<&std::sync::atomic::AtomicU64>,
) -> io::Result<u64> {
    let mut transferred: u64 = 0;
    let mut buf = [0u8; 16384];
    loop {
        read_stream.readable().await?;
        let n = match read_stream.try_read(&mut buf) {
            Ok(0) => {
                #[cfg(unix)]
                // SAFETY: `write_stream` is alive and its descriptor valid.
                unsafe {
                    use std::os::fd::AsRawFd;
                    libc::shutdown(write_stream.as_raw_fd(), libc::SHUT_WR);
                };
                break;
            }
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };

        let mut pos = 0;
        while pos < n {
            write_stream.writable().await?;
            match write_stream.try_write(&buf[pos..n]) {
                Ok(w) => {
                    pos += w;
                    transferred += w as u64;
                    if let Some(c) = c1 {
                        c.fetch_add(w as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Some(c) = c2 {
                        c.fetch_add(w as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(transferred)
}

/// Linux zero-copy bidirectional splice with optional real-time atomic traffic metering.
pub async fn copy_bidirectional_zero_copy_metered(
    a: &TcpStream,
    b: &TcpStream,
    a_to_b_1: Option<&std::sync::atomic::AtomicU64>,
    a_to_b_2: Option<&std::sync::atomic::AtomicU64>,
    b_to_a_1: Option<&std::sync::atomic::AtomicU64>,
    b_to_a_2: Option<&std::sync::atomic::AtomicU64>,
) -> io::Result<(u64, u64)> {
    // The fallback copy futures each hold a 16KB inline buffer; boxing them keeps
    // the per-connection spawned task small (~KBs instead of ~35KB) in the common
    // splice path. The box is heap-allocated only when the fallback actually runs.
    #[cfg(target_os = "linux")]
    {
        let t1 = splice_direction(a, b, a_to_b_1, a_to_b_2);
        let t2 = splice_direction(b, a, b_to_a_1, b_to_a_2);
        match tokio::try_join!(t1, t2) {
            Ok(res) => Ok(res),
            Err(e) => {
                let code = e.raw_os_error();
                if code == Some(libc::EINVAL)
                    || code == Some(libc::ENOSYS)
                    || code == Some(libc::EMFILE)
                    || code == Some(libc::ENFILE)
                {
                    let f1 = Box::pin(copy_direction_ref(a, b, a_to_b_1, a_to_b_2));
                    let f2 = Box::pin(copy_direction_ref(b, a, b_to_a_1, b_to_a_2));
                    tokio::try_join!(f1, f2)
                } else {
                    Err(e)
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let f1 = Box::pin(copy_direction_ref(a, b, a_to_b_1, a_to_b_2));
        let f2 = Box::pin(copy_direction_ref(b, a, b_to_a_1, b_to_a_2));
        tokio::try_join!(f1, f2)
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

    #[test]
    #[cfg(target_os = "linux")]
    fn test_pipe_drain_on_recycle() {
        let pipe = Pipe::new().unwrap();
        // Write dirty bytes to pipe
        // SAFETY: `pipe.writer` is an open descriptor owned by `pipe`, and the static byte
        // string outlives the call with the length passed matching it.
        unsafe {
            libc::write(
                pipe.writer,
                b"DIRTY_LEAKED_BYTES".as_ptr() as *const libc::c_void,
                18,
            );
        }
        // Draining must empty the pipe
        assert!(pipe.drain());
        // Second drain must also succeed and report clean
        assert!(pipe.drain());
    }
}
