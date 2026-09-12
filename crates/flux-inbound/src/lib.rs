pub mod socks;
pub mod http;
pub mod mixed;
pub mod vless;
pub mod tun;
pub mod trojan;
pub mod shadowsocks;

pub use socks::*;
pub use http::*;
pub use mixed::*;
pub use vless::*;
pub use tun::*;
pub use trojan::*;
pub use shadowsocks::*;

/// Applies kernel socket performance tuning: TCP_NODELAY and SO_KEEPALIVE while preserving Linux TCP autotuning.
pub fn optimize_tcp_socket(socket: &tokio::net::TcpStream) {
    let _ = socket.set_nodelay(true);
    let sock_ref = socket2::SockRef::from(socket);
    let _ = sock_ref.set_keepalive(true);
}
