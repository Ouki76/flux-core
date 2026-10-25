//! Counts heap allocations per relayed UDP datagram.
//!
//! The profiler said ~33 % of the proxy's instructions were in `malloc`/`free` under a UDP
//! load, which is a *symptom*. This measures the cause directly: a counting global
//! allocator wrapped around a live instance, so the number is allocations per datagram
//! rather than an inference from instruction shares.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every method forwards to `System` with the same arguments it was given, so the
// allocator contract — non-null distinct regions for live allocations, matching layouts on
// dealloc and realloc — is exactly the system allocator's own.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract; this forwards it.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout are the ones a previous `alloc` or `realloc`
        // returned, as the caller guarantees.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the pointer is a live allocation made with `layout`, which the caller
        // guarantees; `new_size` is the requested size.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

async fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::main]
async fn main() {
    // UDP echo target.
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], from).await;
        }
    });

    let port = free_port().await;
    let cfg = format!(
        r#"{{"log":{{"level":"error"}},"inbounds":[{{"tag":"in","carrier":{{"type":"tcp","listen":"127.0.0.1","listen_port":{port}}},"protocol":{{"type":"socks"}}}}],"outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
    );
    let instance =
        flux_app::Instance::new(flux_app::Config::from_json_str(&cfg).expect("parse config"))
            .expect("build instance");
    instance.start().await.expect("start");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // SOCKS5 UDP ASSOCIATE.
    let mut ctrl = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut hello = [0u8; 2];
    use tokio::io::AsyncReadExt;
    ctrl.read_exact(&mut hello).await.unwrap();
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
        .await
        .unwrap();
    let mut rep = [0u8; 10];
    ctrl.read_exact(&mut rep).await.unwrap();
    let relay: std::net::SocketAddr = format!(
        "{}:{}",
        std::net::Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]),
        u16::from_be_bytes([rep[8], rep[9]])
    )
    .parse()
    .unwrap();

    let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = vec![0x5Au8; 1200];
    let mut dgram = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    dgram.extend_from_slice(&echo_port.to_be_bytes());
    dgram.extend_from_slice(&payload);

    // Warm up so first-touch allocations (route cache, endpoint dial, buffers that grow
    // once) are not charged to the measurement.
    let mut buf = vec![0u8; 65535];
    for _ in 0..200 {
        cli.send_to(&dgram, relay).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), cli.recv(&mut buf)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    const N: usize = 2000;
    let before = ALLOCS.load(Ordering::Relaxed);
    for _ in 0..N {
        cli.send_to(&dgram, relay).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), cli.recv(&mut buf)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = ALLOCS.load(Ordering::Relaxed);

    let total = after - before;
    println!(
        "UDP: allocations for {N} datagrams: {total}  ({:.2} per datagram)",
        total as f64 / N as f64
    );

    // --- TCP: does the allocator scale with bytes moved, or with connections? ---
    let tcp_echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_echo_port = tcp_echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = tcp_echo.accept().await {
            tokio::spawn(async move {
                let mut b = vec![0u8; 64 * 1024];
                while let Ok(n) = c.read(&mut b).await {
                    if n == 0 || c.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let mut conn = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    conn.read_exact(&mut hello).await.unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&tcp_echo_port.to_be_bytes());
    conn.write_all(&req).await.unwrap();
    conn.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00, "the CONNECT must succeed");

    let chunk = vec![0x5Au8; 64 * 1024];
    let mut sink = vec![0u8; 64 * 1024];
    let mib = 64usize;
    // Warm up so per-connection allocations are not charged to the measurement.
    conn.write_all(&chunk).await.unwrap();
    let mut got = 0;
    while got < chunk.len() {
        got += conn.read(&mut sink[..chunk.len() - got]).await.unwrap();
    }

    let before = ALLOCS.load(Ordering::Relaxed);
    for _ in 0..mib {
        conn.write_all(&chunk).await.unwrap();
        let mut got = 0;
        while got < chunk.len() {
            got += conn.read(&mut sink[..chunk.len() - got]).await.unwrap();
        }
    }
    let after = ALLOCS.load(Ordering::Relaxed);
    println!(
        "TCP: allocations for {mib} MiB relayed: {} ({:.2} per MiB)",
        after - before,
        (after - before) as f64 / mib as f64
    );
    instance.stop().await.ok();
}
