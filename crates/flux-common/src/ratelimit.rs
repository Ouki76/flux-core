//! Connection rate limiting for inbound listeners: per-IP token bucket plus a
//! global concurrent-connection cap. Designed for the accept hot path:
//! lock-free fast path via sharded DashMap, O(1) per check.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Hard ceiling for the per-IP bucket map; when exceeded, stale buckets are swept.
const MAX_TRACKED_IPS: usize = 100_000;
/// Buckets idle longer than this are evicted during a sweep.
const BUCKET_IDLE_EVICT: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Per-IP token-bucket + global concurrency limiter.
pub struct RateLimiter {
    per_ip: DashMap<IpAddr, Bucket>,
    /// Tokens (connections) refilled per second per IP.
    rate_per_sec: f64,
    /// Maximum burst size per IP.
    burst: f64,
    /// Global concurrent connection cap (0 = unlimited).
    max_concurrent: usize,
    concurrent: AtomicUsize,
}

/// RAII guard for an accepted connection slot; decrements the global
/// concurrency counter on drop.
pub struct ConnGuard {
    limiter: Arc<RateLimiter>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.limiter.concurrent.fetch_sub(1, Ordering::Relaxed);
    }
}

impl RateLimiter {
    /// `rate_per_sec`: sustained new connections per second allowed per IP.
    /// `burst`: short-term burst allowance per IP. `max_concurrent`: global cap.
    pub fn new(rate_per_sec: u32, burst: u32, max_concurrent: u32) -> Arc<Self> {
        Arc::new(Self {
            per_ip: DashMap::new(),
            rate_per_sec: f64::from(rate_per_sec),
            burst: f64::from(burst),
            max_concurrent: max_concurrent as usize,
            concurrent: AtomicUsize::new(0),
        })
    }

    /// Attempts to admit a new connection from `ip`.
    /// Returns `Some(guard)` when admitted; the guard must be held for the
    /// connection lifetime. Returns `None` when rejected.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        // Global concurrency cap first (cheapest check).
        if self.max_concurrent > 0 {
            let mut cur = self.concurrent.load(Ordering::Relaxed);
            loop {
                if cur >= self.max_concurrent {
                    return None;
                }
                match self.concurrent.compare_exchange_weak(
                    cur,
                    cur + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
        }

        // Per-IP token bucket.
        if self.rate_per_sec > 0.0 {
            if self.per_ip.len() > MAX_TRACKED_IPS {
                self.sweep_stale();
            }
            let mut entry = self.per_ip.entry(ip).or_insert(Bucket {
                tokens: self.burst,
                last_refill: Instant::now(),
            });
            let now = Instant::now();
            let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
            entry.tokens = (entry.tokens + elapsed * self.rate_per_sec).min(self.burst);
            entry.last_refill = now;
            if entry.tokens < 1.0 {
                // Over the per-IP rate: roll back the global slot.
                drop(entry);
                if self.max_concurrent > 0 {
                    self.concurrent.fetch_sub(1, Ordering::Relaxed);
                }
                return None;
            }
            entry.tokens -= 1.0;
        }

        Some(ConnGuard {
            limiter: self.clone(),
        })
    }

    /// Evicts long-idle per-IP buckets to bound memory under IP-spoofed floods.
    fn sweep_stale(&self) {
        let now = Instant::now();
        self.per_ip
            .retain(|_, b| now.duration_since(b.last_refill) < BUCKET_IDLE_EVICT);
        // If the map is still oversized (all entries fresh), drop it entirely:
        // rebuilding buckets is cheaper than unbounded memory growth.
        if self.per_ip.len() > MAX_TRACKED_IPS {
            self.per_ip.clear();
        }
    }

    /// Current global concurrent connection count.
    pub fn concurrent(&self) -> usize {
        self.concurrent.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_ip_token_bucket() {
        let rl = RateLimiter::new(1, 3, 0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Burst of 3 allowed.
        let g1 = rl.try_acquire(ip);
        let g2 = rl.try_acquire(ip);
        let g3 = rl.try_acquire(ip);
        assert!(g1.is_some() && g2.is_some() && g3.is_some());
        // 4th rejected: bucket empty.
        assert!(rl.try_acquire(ip).is_none());

        // A different IP is unaffected.
        let other: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(rl.try_acquire(other).is_some());

        drop((g1, g2, g3));
        // After 1.1s the bucket refills by ~1 token.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(rl.try_acquire(ip).is_some());
    }

    #[test]
    fn test_global_concurrent_cap() {
        let rl = RateLimiter::new(0, 0, 2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let g1 = rl.try_acquire(ip).unwrap();
        let g2 = rl.try_acquire(ip).unwrap();
        assert!(rl.try_acquire(ip).is_none());
        assert_eq!(rl.concurrent(), 2);
        drop(g1);
        assert_eq!(rl.concurrent(), 1);
        assert!(rl.try_acquire(ip).is_some());
        drop(g2);
    }

    #[test]
    fn test_rate_rejection_rolls_back_global_slot() {
        let rl = RateLimiter::new(1, 1, 10);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let g1 = rl.try_acquire(ip).unwrap();
        assert_eq!(rl.concurrent(), 1);
        // Rejected by the per-IP bucket; global slot must be returned.
        assert!(rl.try_acquire(ip).is_none());
        assert_eq!(rl.concurrent(), 1);
        drop(g1);
        assert_eq!(rl.concurrent(), 0);
    }
}
