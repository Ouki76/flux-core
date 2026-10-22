use parking_lot::Mutex;
use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

pub const DEFAULT_BUFFER_SIZE: usize = 16 * 1024; // 16 KB
pub const PACKET_BUFFER_SIZE: usize = 65536; // 64 KB for UDP datagrams

/// Hard ceiling on a pool's per-buffer size. A pooled buffer is allocated
/// eagerly (`vec![0u8; buffer_size]`) on every miss, so an implausible size is a
/// configuration error that must be loud at construction instead of an
/// out-of-memory abort on the first acquisition under load.
pub const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024; // 16 MB

const NUM_SHARDS: usize = 16;

/// Per-thread rotating shard cursor.
///
/// A single shared atomic cursor made every acquire/release contend on one
/// cache line across all worker threads. A thread-local cursor spreads shards
/// evenly without any cross-core traffic.
fn next_counter() -> usize {
    thread_local! {
        static CURSOR: Cell<usize> = const { Cell::new(0) };
    }
    CURSOR.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        v
    })
}

/// A thread-safe, 16-way sharded buffer pool reusing buffers without malloc pressure or lock contention.
///
/// # Security contract
///
/// A buffer handed out by [`BufferPool::acquire`] is served to a *different*
/// connection than the one that last used the allocation — that is the whole
/// point of pooling. Every buffer is therefore **scrubbed before it is pooled**
/// (see [`BufferPool::release`]), so `acquire()` yields `buffer_size` zeroed
/// bytes and never the previous tenant's payload.
pub struct BufferPool {
    buffer_size: usize,
    shards: [Mutex<Vec<Vec<u8>>>; NUM_SHARDS],
    /// Shards actually used, capped by `max_capacity` so that a small cap is
    /// honoured exactly instead of being rounded up to one buffer per shard.
    shards_used: usize,
    shard_capacity: usize,
}

impl BufferPool {
    /// `buffer_size` bytes per buffer, `max_capacity` buffers retained overall.
    ///
    /// `max_capacity` is a memory ceiling, not a hint: the pool holds at most
    /// that many buffers and drops the rest, so a burst of connections cannot
    /// permanently pin arbitrary memory.
    pub fn new(buffer_size: usize, max_capacity: usize) -> Self {
        assert!(
            buffer_size <= MAX_BUFFER_SIZE,
            "buffer size {buffer_size} exceeds the {MAX_BUFFER_SIZE}-byte ceiling"
        );
        // A zero-length buffer reads as EOF on every call, which would silently
        // tear down every connection that used the pool.
        let buffer_size = buffer_size.max(1);
        let shards_used = NUM_SHARDS.min(max_capacity.max(1));
        let shard_capacity = if max_capacity == 0 {
            0
        } else {
            (max_capacity / shards_used).max(1)
        };
        Self {
            buffer_size,
            shards: std::array::from_fn(|_| Mutex::new(Vec::with_capacity(shard_capacity))),
            shards_used,
            shard_capacity,
        }
    }

    pub fn default_pool() -> &'static Self {
        static INSTANCE: OnceLock<BufferPool> = OnceLock::new();
        INSTANCE.get_or_init(|| BufferPool::new(DEFAULT_BUFFER_SIZE, 256))
    }

    pub fn packet_pool() -> &'static Self {
        static PACKET_INSTANCE: OnceLock<BufferPool> = OnceLock::new();
        PACKET_INSTANCE.get_or_init(|| BufferPool::new(PACKET_BUFFER_SIZE, 64))
    }

    fn shard_index(&self) -> usize {
        next_counter() % self.shards_used
    }

    /// Acquire a zeroed buffer of exactly `buffer_size` bytes.
    pub fn acquire(&self) -> Vec<u8> {
        let idx = self.shard_index();
        let mut guard = self.shards[idx].lock();
        guard.pop().unwrap_or_else(|| vec![0u8; self.buffer_size])
    }

    /// Acquire a buffer wrapped in RAII BufferGuard that returns to pool upon drop.
    pub fn acquire_guard(&'static self) -> BufferGuard {
        BufferGuard {
            buf: Some(self.acquire()),
            pool: self,
        }
    }

    /// Releases a buffer back to the pool.
    ///
    /// The contents **are** scrubbed. A pooled buffer is handed to the next
    /// connection, so leaving the previous connection's bytes in it made
    /// "read the buffer past what I wrote" a cross-tenant disclosure one
    /// careless call site away — the pool cannot verify that every caller
    /// slices `..n` before touching the bytes, so it does not rely on it.
    ///
    /// Cost, measured on this machine (`memset` runs at ~134 GB/s): ~120 ns for
    /// a 16 KiB release — the TCP copy path releases once per 16 KiB moved, so
    /// that is well under 1 % of a core per GiB/s relayed — and ~490 ns for the
    /// 64 KiB packet pool, once per datagram. Over half of the pool's
    /// acquire/release cycle at that size, which is the price of not handing a
    /// connection the previous connection's payload. The buffer is zeroed here,
    /// on release, rather than on acquisition so that pooled memory never holds
    /// payload at rest.
    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() < self.buffer_size {
            return;
        }
        // A caller that grew the allocation (a `reserve`, an `extend` past the
        // buffer size) must not pin that capacity here: with `shard_capacity`
        // slots, one rogue 1 MiB vector would keep megabytes alive for a pool
        // that advertises `buffer_size`. Drop instead of caching.
        if buf.capacity() > self.buffer_size.saturating_mul(2) {
            return;
        }
        // Normalise the logical length so callers always observe `buffer_size`.
        if buf.len() != self.buffer_size {
            buf.resize(self.buffer_size, 0);
        }
        buf.fill(0);
        let idx = self.shard_index();
        let mut guard = self.shards[idx].lock();
        if guard.len() < self.shard_capacity {
            guard.push(buf);
        }
    }
}

pub struct BufferGuard {
    buf: Option<Vec<u8>>,
    pool: &'static BufferPool,
}

impl Deref for BufferGuard {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        match &self.buf {
            Some(b) => b,
            None => unreachable!("BufferGuard dereferenced after drop"),
        }
    }
}

impl DerefMut for BufferGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.buf {
            Some(b) => b,
            None => unreachable!("BufferGuard dereferenced after drop"),
        }
    }
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.release(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Number of buffers the pool is currently holding across all shards.
    fn pooled_total(pool: &BufferPool) -> usize {
        pool.shards.iter().map(|s| s.lock().len()).sum()
    }

    /// Every allocation currently retained by the pool, as raw addresses.
    fn pooled_ptrs(pool: &BufferPool) -> Vec<usize> {
        pool.shards
            .iter()
            .flat_map(|s| {
                s.lock()
                    .iter()
                    .map(|b| b.as_ptr() as usize)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn test_buffer_pool_reuse() {
        let pool = BufferPool::new(4096, 4);
        let b1 = pool.acquire();
        assert_eq!(b1.len(), 4096);
        pool.release(b1);

        let b2 = pool.acquire();
        assert_eq!(b2.len(), 4096);
    }

    /// The security question this pool exists to answer: an acquired buffer is
    /// handed to a *different* connection than the one that last used the
    /// allocation. It must therefore carry no trace of the previous tenant.
    ///
    /// Reproduces the leak exactly: tenant A writes a recognisable pattern into
    /// the buffer it was given, releases it, and the next acquisition of *that
    /// same allocation* (matched by pointer, so the test cannot pass vacuously)
    /// must observe zeros — not A's bytes.
    #[test]
    fn pooled_buffer_never_carries_the_previous_tenants_bytes() {
        const SECRET: u8 = 0xAA;
        let pool = BufferPool::new(1024, 32);

        let mut tenant_a = pool.acquire();
        tenant_a.fill(SECRET);
        let released = tenant_a.as_ptr();
        pool.release(tenant_a);

        let mut found = false;
        let mut held = Vec::new();
        for _ in 0..NUM_SHARDS * 2 {
            let buf = pool.acquire();
            if buf.as_ptr() == released {
                found = true;
                assert_eq!(
                    buf.len(),
                    1024,
                    "len must be restored to buffer_size (pooled buffers are \
                     full-length so `read(&mut buf[..])` works)"
                );
                assert!(
                    buf.iter().all(|&b| b == 0),
                    "recycled buffer still holds the previous tenant's 0xAA \
                     bytes: first 8 = {:02x?}",
                    &buf[..8]
                );
            }
            held.push(buf);
        }
        assert!(
            found,
            "the released allocation was never handed back, so this test \
             proved nothing"
        );
    }

    /// A pooled buffer is reused without re-allocation, so the *allocation*
    /// must survive the round trip while its *contents* must not.
    #[test]
    fn release_reuses_the_allocation_but_scrubs_the_contents() {
        let pool = BufferPool::new(64 * 1024, 8);
        let mut buf = pool.acquire();
        let ptr = buf.as_ptr() as usize;
        buf[0] = 0xAB;
        buf[64 * 1024 - 1] = 0xCD;
        pool.release(buf);

        let ptrs = pooled_ptrs(&pool);
        assert!(
            ptrs.contains(&ptr),
            "released buffer must be retained for reuse (no malloc churn)"
        );
        // Contents must be gone: the allocation is about to serve someone else.
        let retained = pool
            .shards
            .iter()
            .flat_map(|s| {
                s.lock()
                    .iter()
                    .map(|b| (b.as_ptr(), b.iter().any(|&x| x != 0)))
                    .collect::<Vec<_>>()
            })
            .find(|(p, _)| *p as usize == ptr)
            .expect("buffer retained");
        assert!(
            !retained.1,
            "release must scrub the buffer before pooling it"
        );
    }

    /// The pool is a bounded cache: `max_capacity` is a memory ceiling under
    /// load, so it must hold for *every* cap value, including ones smaller than
    /// the shard count.
    #[test]
    fn pool_never_retains_more_than_the_requested_cap() {
        for cap in [0usize, 1, 4, 15, 16, 17, 256] {
            let pool = BufferPool::new(512, cap);
            let flood = cap.max(1) * 4 + 8;
            let bufs: Vec<_> = (0..flood).map(|_| pool.acquire()).collect();
            for b in bufs {
                pool.release(b);
            }
            let total = pooled_total(&pool);
            assert!(
                total <= cap,
                "cap {cap}: pool retained {total} buffers after releasing {flood}"
            );
        }
    }

    /// `acquire()` must always yield exactly `buffer_size` (callers read into
    /// `&mut buf[..]`), whatever odd shape the vector was in when it was
    /// released.
    #[test]
    fn acquired_buffers_are_always_exactly_buffer_size() {
        let pool = BufferPool::new(1024, 8);

        let mut grown = pool.acquire();
        grown.extend_from_slice(&[0x5Au8; 100]);
        pool.release(grown);

        let mut truncated = pool.acquire();
        truncated.truncate(7);
        pool.release(truncated);

        for _ in 0..NUM_SHARDS * 2 {
            let b = pool.acquire();
            assert_eq!(b.len(), 1024, "len must be normalised on release");
            assert!(b.iter().all(|&x| x == 0));
        }
    }

    /// The pool advertises `buffer_size` per buffer; a caller that inflated an
    /// allocation must not make the pool pin that inflated size forever.
    #[test]
    fn inflated_allocations_are_dropped_not_pinned() {
        let pool = BufferPool::new(1024, 8);
        let mut fat = pool.acquire();
        fat.reserve(1 << 20);
        pool.release(fat);
        assert_eq!(
            pooled_total(&pool),
            0,
            "a 1 MiB allocation was pinned by a 1 KiB pool"
        );
        assert_eq!(pool.acquire().len(), 1024);
    }

    /// A vector too small to serve as a pool buffer must be dropped, not
    /// pooled, and must not poison the pool with a short buffer.
    #[test]
    fn undersized_allocations_are_dropped_not_pooled() {
        let pool = BufferPool::new(4096, 8);
        pool.release(Vec::new());
        pool.release(vec![0u8; 16]);
        assert_eq!(
            pooled_total(&pool),
            0,
            "undersized vectors must not be pooled"
        );
        assert_eq!(pool.acquire().len(), 4096);
    }

    /// A zero-byte buffer pool would hand out `vec![]`, and every
    /// `read(&mut buf[..])` would return 0 — indistinguishable from EOF. The
    /// constructor must not let that happen.
    #[test]
    fn zero_sized_pool_never_hands_out_an_empty_buffer() {
        let pool = BufferPool::new(0, 4);
        let b = pool.acquire();
        assert!(!b.is_empty(), "an empty buffer reads as EOF on every call");
        assert_eq!(b.len(), pool.buffer_size);
    }

    /// A huge buffer size would be an unbounded allocation attempt on the very
    /// first acquire; it is a configuration/programmer error, so it is loud.
    #[test]
    #[should_panic(expected = "buffer size")]
    fn huge_buffer_size_is_rejected() {
        let _ = BufferPool::new(usize::MAX, 8);
    }

    #[test]
    fn test_buffer_guard_raii() {
        let pool: &'static BufferPool = Box::leak(Box::new(BufferPool::new(256, 64)));
        {
            let mut guard = pool.acquire_guard();
            assert_eq!(guard.len(), 256);
            guard[0] = 42;
        }
        let b2 = pool.acquire();
        assert_eq!(b2.len(), 256);
        assert!(b2.iter().all(|&b| b == 0), "guard must scrub on drop");
    }

    /// `BufferGuard` is the only route back into the pool and it is neither
    /// `Clone` nor multi-owned (`Option::take` in `Drop`), so a buffer cannot be
    /// released twice; two live guards must mean two live allocations.
    #[test]
    fn guards_release_exactly_one_buffer_each_and_never_duplicate_it() {
        let pool: &'static BufferPool = Box::leak(Box::new(BufferPool::new(256, 64)));
        assert_eq!(pooled_total(pool), 0);
        {
            let _a = pool.acquire_guard();
            let _b = pool.acquire_guard();
            assert_eq!(
                pooled_total(pool),
                0,
                "a buffer must not be visible to the pool while a guard owns it"
            );
        }
        assert_eq!(
            pooled_total(pool),
            2,
            "each guard releases exactly one buffer"
        );

        let ptrs = pooled_ptrs(pool);
        let mut unique = ptrs.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            ptrs.len(),
            unique.len(),
            "the pool stored the same allocation twice: {ptrs:?}"
        );
    }

    /// Two live acquisitions must never alias, from any number of threads, and
    /// no thread may ever read a byte another thread wrote.
    #[test]
    fn concurrent_live_acquisitions_are_distinct_and_isolated() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 64;
        const SIZE: usize = 4096;

        let pool = Arc::new(BufferPool::new(SIZE, 64));
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));
        let live: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        for t in 0..THREADS {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            let live = Arc::clone(&live);
            handles.push(std::thread::spawn(move || {
                let tag = 0xA0u8 + t as u8;
                for round in 0..ROUNDS {
                    let mut buf = pool.acquire();
                    assert_eq!(buf.len(), SIZE);
                    buf.fill(tag);

                    // Every thread holds its buffer here: all of them are live
                    // at the same instant.
                    barrier.wait();
                    if round == 0 {
                        live.lock().push(buf.as_ptr() as usize);
                    }
                    assert!(
                        buf.iter().all(|&b| b == tag),
                        "thread {t} saw a foreign write: two live acquisitions alias"
                    );
                    barrier.wait();

                    pool.release(buf);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let mut ptrs = live.lock().clone();
        ptrs.sort_unstable();
        ptrs.dedup();
        assert_eq!(
            ptrs.len(),
            THREADS,
            "concurrent acquisitions shared an address: {ptrs:?}"
        );
    }
}
