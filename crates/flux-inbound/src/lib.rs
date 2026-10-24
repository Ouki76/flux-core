#![warn(missing_docs)]

//! Inbounds: everything that accepts connections.
//!
//! Each module is one way in — a client-facing protocol (SOCKS5, HTTP, mixed), a
//! server-side proxy protocol (VLESS, VMess, Trojan, Shadowsocks, TUIC, Hysteria 2,
//! WireGuard) or a transparent interceptor (REDIRECT, TPROXY, TUN). They all implement
//! the same [`Inbound`](flux_types::traits::Inbound) trait, and the contract that matters
//! is on `stop`: it releases the listening socket before it resolves.

/// The DNS listener: UDP and TCP answers.
pub mod dns;
/// Plain HTTP proxying.
pub mod http;
/// Hysteria 2 over QUIC.
pub mod hysteria2;
/// A port that accepts SOCKS5 and HTTP on the same socket.
pub mod mixed;
/// The REDIRECT (nat) transparent interceptor.
pub mod redirect;
/// Shadowsocks.
pub mod shadowsocks;
/// SOCKS5.
pub mod socks;
/// The TPROXY transparent interceptor.
pub mod tproxy;
/// Trojan.
pub mod trojan;
/// TUIC v5 over QUIC.
pub mod tuic;
/// The TUN device: a userspace IP stack.
pub mod tun;
/// VLESS.
pub mod vless;
/// VMess.
pub mod vmess;
/// WireGuard and AmneziaWG.
pub mod wireguard;

pub use dns::*;
pub use http::*;
pub use hysteria2::*;
pub use mixed::*;
pub use redirect::*;
pub use shadowsocks::*;
pub use socks::*;
pub use tproxy::*;
pub use trojan::*;
pub use tuic::*;
pub use tun::*;
pub use vless::*;
pub use vmess::*;
pub use wireguard::*;

pub use flux_common::{create_reuse_port_listener, optimize_tcp_socket};

use flux_types::FluxResult;
use std::future::Future;

/// The long-lived background tasks an inbound spawns in `start()`.
///
/// `Inbound::stop()` has to mean *stopped*, and the value of "stopped" that a
/// caller can observe is "the listening socket is closed". The socket is owned
/// by the accept loop (or, for UDP, by the receive loop), so as long as that
/// task is alive its file descriptor is open and an immediate rebind of the
/// same port fails with `EADDRINUSE` even though `stop()` already returned.
/// Signalling a shutdown channel is therefore not enough: the task has to be
/// joined.
///
/// Every inbound registers its listener-owning tasks here and `stop()`
/// `join().await`s them, which is what makes `stop()` synchronously release the
/// port.
#[derive(Default)]
pub struct InboundTasks {
    handles: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl InboundTasks {
    /// An empty set; `stop` on it is a no-op.
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawns a task and remembers its handle so `stop()` can join it.
    pub fn spawn<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.add(tokio::spawn(task));
    }

    /// Registers an already-spawned task.
    pub fn add(&self, handle: tokio::task::JoinHandle<()>) {
        self.lock().push(handle);
    }

    /// Waits for every registered task to finish, then forgets them.
    ///
    /// A panicking task is reported as an error, but the remaining joins still
    /// run: the point of this function is that no listener is left behind, and
    /// that holds whether or not one task failed.
    pub async fn join(&self) -> FluxResult<()> {
        let handles: Vec<_> = std::mem::take(&mut *self.lock());
        let mut first_error = None;
        for handle in handles {
            match handle.await {
                Ok(()) => {}
                // A task that was aborted by its own runtime teardown cannot
                // leave a listener behind, so this is not an error.
                Err(e) if e.is_cancelled() => {}
                Err(e) => {
                    tracing::warn!(error = %e, "an inbound task failed while shutting down");
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
        match first_error {
            Some(e) => Err(flux_types::FluxError::Internal(format!(
                "an inbound task panicked while shutting down: {e}"
            ))),
            None => Ok(()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<tokio::task::JoinHandle<()>>> {
        self.handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod task_tracking_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// `join()` on an inbound that never started is a no-op, not an error: it
    /// is called on every `stop()`, including the "never started" one.
    #[tokio::test]
    async fn joining_nothing_is_ok() {
        let tasks = InboundTasks::new();
        tasks.join().await.expect("join without tasks must succeed");
    }

    /// The whole point of the type: `join()` must not resolve before the task
    /// it tracks has actually finished. On a single-threaded runtime nothing
    /// else can advance the spawned task, so a `join()` that merely dropped the
    /// handle would return with `finished == false`.
    #[tokio::test(flavor = "current_thread")]
    async fn join_waits_for_the_task() {
        let tasks = InboundTasks::new();
        let finished = Arc::new(AtomicBool::new(false));
        let flag = finished.clone();
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            flag.store(true, Ordering::SeqCst);
        });

        tasks.join().await.expect("join");
        assert!(
            finished.load(Ordering::SeqCst),
            "join() returned before the tracked task finished"
        );

        // Joined handles are forgotten, so a second join is a cheap no-op.
        tasks.join().await.expect("stopping twice must succeed");
    }
}
