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

/// Applies kernel socket performance tuning: TCP_NODELAY, SO_KEEPALIVE, and 256KB rmem/wmem.
pub fn optimize_tcp_socket(socket: &tokio::net::TcpStream) {
    let _ = socket.set_nodelay(true);
    let sock_ref = socket2::SockRef::from(socket);
    let _ = sock_ref.set_send_buffer_size(256 * 1024);
    let _ = sock_ref.set_recv_buffer_size(256 * 1024);
    let _ = sock_ref.set_keepalive(true);
}
