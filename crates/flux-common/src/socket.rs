use flux_types::{FluxError, FluxResult};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

/// Applies kernel socket performance tuning: TCP_NODELAY and SO_KEEPALIVE while preserving Linux TCP autotuning.
pub fn optimize_tcp_socket(socket: &tokio::net::TcpStream) {
    let _ = socket.set_nodelay(true);
    let sock_ref = socket2::SockRef::from(socket);
    let _ = sock_ref.set_keepalive(true);
}

/// Creates a TCP listener with `SO_REUSEADDR` and `SO_REUSEPORT` enabled
/// to support seamless zero-downtime hot-reload (`SIGHUP`).
pub fn create_reuse_port_listener(addr: SocketAddr) -> FluxResult<tokio::net::TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(FluxError::Io)?;
    let _ = socket.set_nonblocking(true);
    let _ = socket.set_reuse_address(true);
    #[cfg(all(unix, not(target_os = "solaris")))]
    {
        let _ = socket.set_reuse_port(true);
    }
    socket.bind(&addr.into()).map_err(FluxError::Io)?;
    socket.listen(1024).map_err(FluxError::Io)?;
    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener).map_err(FluxError::Io)
}
