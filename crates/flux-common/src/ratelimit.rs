//! Connection rate limiting for inbound listeners: per-IP token bucket plus a
//! global concurrent-connection cap. Designed for the accept hot path:
//! lock-free fast path via sharded DashMap, O(1) per check.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Hard ceiling for the per-IP bucket map; when exceeded, buckets are swept.
const MAX_TRACKED_IPS: usize = 100_000;
/// After a sweep the map is cut back to this watermark. A sweep is O(n), so it
/// must not be triggered by every admission once the ceiling is reached.
const TRACKED_IPS_LOW_WATER: usize = MAX_TRACKED_IPS / 4;
/// Buckets idle longer than this are evicted during a sweep even if they could
/// still be mid-refill: ten silent minutes is treated as a new client.
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
            // Saturating: `Instant` is monotonic (`CLOCK_MONOTONIC`), so a
            // backwards step cannot happen on a sane system — and if it somehow
            // did, a negative elapsed must never subtract tokens or mint them.
            let elapsed = now
                .saturating_duration_since(entry.last_refill)
                .as_secs_f64();
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

    /// Time for an empty bucket to refill to `burst`.
    ///
    /// A bucket idle at least this long holds no rate-limit state: dropping it
    /// cannot grant its client an extra connection, so it is the cheapest thing
    /// a sweep can reclaim.
    fn refill_time(&self) -> std::time::Duration {
        if self.rate_per_sec <= 0.0 || !self.burst.is_finite() || self.burst <= 0.0 {
            return BUCKET_IDLE_EVICT;
        }
        // `Duration::from_secs_f64` panics on NaN/inf and `burst / rate` can
        // overflow for a pathological configuration; clamp instead.
        let secs = (self.burst / self.rate_per_sec).clamp(0.0, BUCKET_IDLE_EVICT.as_secs_f64());
        std::time::Duration::from_secs_f64(secs)
    }

    /// Bounds the per-IP map under an IP-spoofed flood without ever handing a
    /// client a fresh burst.
    ///
    /// Eviction is ordered by how much state a bucket still holds, because a
    /// bucket's only state is "how many tokens short of `burst` it is":
    ///
    /// 1. buckets that have already refilled (or been silent for
    ///    [`BUCKET_IDLE_EVICT`]) are dropped for free — they restrict nothing;
    /// 2. if the map is still oversized, the *fullest* buckets go first: one at
    ///    9.9/10 tokens constrains its client far less than one at 0/10;
    /// 3. if every bucket is exhausted, a bounded sample is kept. The map is
    ///    never cleared: a wholesale clear would reset every client's bucket,
    ///    so a flood would switch the per-IP limit off on demand.
    fn sweep_stale(&self) {
        let now = Instant::now();

        let horizon = self.refill_time().min(BUCKET_IDLE_EVICT);
        self.per_ip
            .retain(|_, b| now.saturating_duration_since(b.last_refill) < horizon);
        if self.per_ip.len() <= TRACKED_IPS_LOW_WATER {
            return;
        }

        // Halving the token cutoff converges in a handful of O(n) passes.
        let mut cutoff = self.burst;
        while self.per_ip.len() > TRACKED_IPS_LOW_WATER && cutoff > 0.0 {
            cutoff /= 2.0;
            self.per_ip.retain(|_, b| b.tokens < cutoff);
        }

        if self.per_ip.len() > TRACKED_IPS_LOW_WATER {
            // Every remaining bucket is exhausted, so every eviction costs the
            // same; keep a bounded sample rather than wiping the map.
            let seen = AtomicUsize::new(0);
            self.per_ip
                .retain(|_, _| seen.fetch_add(1, Ordering::Relaxed) < TRACKED_IPS_LOW_WATER);
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
    use std::net::Ipv4Addr;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicUsize;

    fn parse_ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_per_ip_token_bucket() {
        let rl = RateLimiter::new(1, 3, 0);
        let ip = parse_ip("1.2.3.4");

        // Burst of 3 allowed.
        let g1 = rl.try_acquire(ip);
        let g2 = rl.try_acquire(ip);
        let g3 = rl.try_acquire(ip);
        assert!(g1.is_some() && g2.is_some() && g3.is_some());
        // 4th rejected: bucket empty.
        assert!(rl.try_acquire(ip).is_none());

        // A different IP is unaffected.
        let other = parse_ip("5.6.7.8");
        assert!(rl.try_acquire(other).is_some());

        drop((g1, g2, g3));
        // After 1.1s the bucket refills by ~1 token.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(rl.try_acquire(ip).is_some());
    }

    #[test]
    fn test_global_concurrent_cap() {
        let rl = RateLimiter::new(0, 0, 2);
        let ip = parse_ip("1.2.3.4");
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
        let ip = parse_ip("1.2.3.4");
        let g1 = rl.try_acquire(ip).unwrap();
        assert_eq!(rl.concurrent(), 1);
        // Rejected by the per-IP bucket; global slot must be returned.
        assert!(rl.try_acquire(ip).is_none());
        assert_eq!(rl.concurrent(), 1);
        drop(g1);
        assert_eq!(rl.concurrent(), 0);
    }

    /// A rejection taken at the *global* cap must not decrement a slot it never
    /// took: the counter is unsigned, so a stray `fetch_sub` wraps to ~usize::MAX
    /// and the cap silently vanishes for the rest of the process's life.
    #[test]
    fn cap_rejection_never_decrements_the_concurrency_counter() {
        // Plenty of per-IP burst, so the only possible rejection is the cap.
        let rl = RateLimiter::new(1, 100, 2);
        let ip = parse_ip("1.2.3.4");
        let g1 = rl.try_acquire(ip).unwrap();
        let g2 = rl.try_acquire(ip).unwrap();
        assert_eq!(rl.concurrent(), 2);

        for _ in 0..1_000 {
            assert!(rl.try_acquire(ip).is_none());
        }
        assert_eq!(
            rl.concurrent(),
            2,
            "rejections at the cap changed the live count"
        );

        drop(g1);
        assert_eq!(rl.concurrent(), 1);
        drop(g2);
        assert_eq!(rl.concurrent(), 0);
    }

    /// The global cap must admit exactly `max_concurrent` callers when 32
    /// threads race for it, never more (over-admission) and never fewer
    /// (lost compare-exchange counts).
    #[test]
    fn global_cap_is_exact_under_contention() {
        const THREADS: usize = 32;
        const CAP: usize = 8;
        let rl = RateLimiter::new(0, 0, CAP as u32);
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();

        for _ in 0..THREADS {
            let rl = Arc::clone(&rl);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                // Hold the slot until every thread has tried.
                let guard = rl.try_acquire(parse_ip("192.0.2.1"));
                barrier.wait();
                guard.is_some()
            }));
        }

        let admitted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, CAP, "{admitted} callers admitted, cap is {CAP}");
        assert_eq!(rl.concurrent(), 0, "every admitted slot must be returned");
    }

    /// The same for the per-IP bucket: 16 threads hammering one IP with a burst
    /// of 8 may take away exactly 8 connections.
    #[test]
    fn per_ip_burst_is_exact_under_contention() {
        const THREADS: usize = 16;
        const BURST: usize = 8;
        // 1 token/s: a refill would need a > 1 s stall inside the test.
        let rl = RateLimiter::new(1, BURST as u32, 0);
        let ip = parse_ip("192.0.2.7");
        let barrier = Arc::new(Barrier::new(THREADS));
        let admitted = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..THREADS {
            let rl = Arc::clone(&rl);
            let barrier = Arc::clone(&barrier);
            let admitted = Arc::clone(&admitted);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..BURST {
                    if rl.try_acquire(ip).is_some() {
                        admitted.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let n = admitted.load(Ordering::Relaxed);
        assert_eq!(
            n, BURST,
            "{n} connections admitted for a burst of {BURST}: the bucket either \
             lost or double-counted tokens under contention"
        );
    }

    /// A clock that went backwards (a `last_refill` in the future) must not
    /// panic, must not drain the bucket with a negative elapsed time, and must
    /// not mint tokens.
    #[test]
    fn a_bucket_stamped_in_the_future_cannot_mint_tokens() {
        let rl = RateLimiter::new(1, 3, 0);
        let ip = parse_ip("198.51.100.10");
        rl.per_ip.insert(
            ip,
            Bucket {
                tokens: 1.0,
                last_refill: Instant::now() + std::time::Duration::from_secs(3_600),
            },
        );
        assert!(
            rl.try_acquire(ip).is_some(),
            "the single token must still be spendable"
        );
        assert!(
            rl.try_acquire(ip).is_none(),
            "a future timestamp refilled the bucket"
        );
        let tokens = rl.per_ip.get(&ip).map(|b| b.tokens).unwrap_or(f64::NAN);
        assert!(
            (0.0..=rl.burst).contains(&tokens),
            "tokens {tokens} outside [0, burst] after a backwards clock step"
        );
    }

    /// Refill is additive and must be clamped at `burst`. An unclamped refill
    /// (a missing `.min(burst)`) lets a long-idle IP open an unbounded number of
    /// connections the instant it comes back.
    ///
    /// The bucket is inspected directly: at `u32::MAX` tokens/s it is full
    /// again within a nanosecond, so counting admissions could not distinguish
    /// "refilled to burst" from "refilled to a million".
    #[test]
    fn refill_is_clamped_at_burst() {
        let rl = RateLimiter::new(u32::MAX, 5, 0);
        let ip = parse_ip("198.51.100.9");
        drop(rl.try_acquire(ip).unwrap()); // bucket exists, one token spent
        std::thread::sleep(std::time::Duration::from_millis(2));
        drop(rl.try_acquire(ip).unwrap()); // ~8.6e6 tokens of refill if unclamped
        let tokens = rl.per_ip.get(&ip).map(|b| b.tokens).unwrap_or(f64::NAN);
        assert_eq!(
            tokens, 4.0,
            "bucket holds {tokens} tokens after refill-and-spend: refill must be \
             clamped at burst ({})",
            rl.burst
        );
    }

    /// Tier-1 eviction: a bucket that has had long enough to refill to `burst`
    /// carries no rate-limit state, so dropping it costs nothing and keeps the
    /// map bounded under an IP-spoofed flood.
    #[test]
    fn buckets_with_no_remaining_state_are_evicted() {
        let rl = RateLimiter::new(u32::MAX, 1, 0); // refill time ~0.23 ns
        for i in 0..1_000u32 {
            let _ = rl.try_acquire(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i)));
        }
        assert_eq!(rl.per_ip.len(), 1_000);
        std::thread::sleep(std::time::Duration::from_millis(2));
        rl.sweep_stale();
        assert!(
            rl.per_ip.len() < 1_000,
            "sweep kept {} state-free buckets",
            rl.per_ip.len()
        );
    }

    /// The map is a memory bound, not a suggestion: 2x the ceiling in distinct
    /// sources must not grow it past the ceiling.
    #[test]
    fn tracked_ip_map_stays_bounded_under_a_spoofed_flood() {
        let rl = RateLimiter::new(1, 10, 0);
        for i in 0..(MAX_TRACKED_IPS * 2) {
            let _ = rl.try_acquire(IpAddr::V4(Ipv4Addr::from(0x0A00_0000u32 + i as u32)));
        }
        let len = rl.per_ip.len();
        // The sweep is triggered lazily, so the map may sit exactly one entry
        // above the ceiling until the next admission.
        assert!(
            len <= MAX_TRACKED_IPS + 1,
            "map holds {len} buckets, ceiling is {MAX_TRACKED_IPS}"
        );
    }

    /// The dangerous one: exceeding the ceiling must not wipe the map. A
    /// wholesale clear resets *every* client's bucket, so an attacker who can
    /// create enough distinct source addresses can hand itself (and everyone
    /// else) a fresh burst on demand — a per-IP rate limit that a flood
    /// switches off.
    #[test]
    fn flood_eviction_must_not_reset_an_exhausted_bucket() {
        const BURST: u32 = 10;
        let rl = RateLimiter::new(1, BURST, 0);
        let attacker = parse_ip("203.0.113.7");

        let spent: Vec<_> = (0..BURST)
            .filter_map(|_| rl.try_acquire(attacker))
            .collect();
        assert_eq!(spent.len() as u32, BURST);
        assert!(rl.try_acquire(attacker).is_none(), "bucket must be empty");

        // One connection from each of many distinct sources — what the accept
        // path sees during a source-spoofed flood.
        for i in 0..=MAX_TRACKED_IPS {
            let _ = rl.try_acquire(IpAddr::V4(Ipv4Addr::from(0x0A00_0000u32 + i as u32)));
        }

        match rl.per_ip.get(&attacker) {
            None => panic!(
                "the sweep evicted (and so reset) a bucket that was still \
                 mid-refill: the attacker got a fresh burst"
            ),
            Some(b) => assert!(
                b.tokens < f64::from(BURST),
                "the sweep refilled the attacker's bucket to {} tokens",
                b.tokens
            ),
        }
    }
}
