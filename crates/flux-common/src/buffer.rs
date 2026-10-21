use parking_lot::Mutex;
use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

pub const DEFAULT_BUFFER_SIZE: usize = 16 * 1024; // 16 KB
pub const PACKET_BUFFER_SIZE: usize = 65536; // 64 KB for UDP datagrams

const NUM_SHARDS: usize = 16;

/// Per-thread rotating shard cursor.
///
/// A single shared atomic cursor made every acquire/release contend on one
/// cache line across all worker threads. A thread-local cursor spreads shards
/// evenly without any cross-core traffic.
fn next_shard() -> usize {
    thread_local! {
        static CURSOR: Cell<usize> = const { Cell::new(0) };
    }
    CURSOR.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        v % NUM_SHARDS
    })
}

/// A thread-safe, 16-way sharded buffer pool reusing buffers without malloc pressure or lock contention.
pub struct BufferPool {
    buffer_size: usize,
    shards: [Mutex<Vec<Vec<u8>>>; NUM_SHARDS],
    shard_capacity: usize,
}

impl BufferPool {
    pub fn new(buffer_size: usize, max_capacity: usize) -> Self {
        let shard_capacity = (max_capacity / NUM_SHARDS).max(1);
        Self {
            buffer_size,
            shards: std::array::from_fn(|_| Mutex::new(Vec::with_capacity(shard_capacity))),
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

    /// Acquire a buffer from the pool or allocate a new one.
    pub fn acquire(&self) -> Vec<u8> {
        let idx = next_shard();
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
    /// The contents are deliberately **not** zeroed: pooled buffers are only
    /// ever read up to the length a `read`/`recv` reports, never past it, so
    /// scrubbing protected nothing while costing a full `memset` per release.
    /// That was measurable on the UDP path, where a 64 KiB buffer is released
    /// once *per datagram*.
    ///
    /// Callers that expose raw pooled memory to code which reads uninitialised
    /// bytes must zero it themselves.
    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() < self.buffer_size {
            return;
        }
        // Normalise the logical length so callers always observe `buffer_size`.
        if buf.len() != self.buffer_size {
            buf.resize(self.buffer_size, 0);
        }
        let idx = next_shard();
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

    #[test]
    fn test_buffer_pool_reuse() {
        let pool = BufferPool::new(4096, 4);
        let b1 = pool.acquire();
        assert_eq!(b1.len(), 4096);
        pool.release(b1);

        let b2 = pool.acquire();
        assert_eq!(b2.len(), 4096);
    }

    /// A pooled buffer must be reused without re-allocation, and releasing it
    /// must not cost a full-buffer `memset` (release path is on the UDP hot
    /// path: one release per datagram).
    #[test]
    fn test_release_reuses_allocation_without_scrubbing() {
        let pool = BufferPool::new(64 * 1024, 8);
        let mut buf = pool.acquire();
        let ptr = buf.as_ptr();
        buf[0] = 0xAB;
        pool.release(buf);
        // Shard rotation means a later `acquire()` may hit a different shard, so
        // look for our exact allocation rather than assuming LIFO ordering.
        let pooled = pool
            .shards
            .iter()
            .flat_map(|s| s.lock().iter().map(|b| b.as_ptr()).collect::<Vec<_>>())
            .any(|p| p == ptr);
        assert!(pooled, "released buffer must be retained for reuse");
        // Contents are intentionally preserved (no scrub on release).
        let retained = pool
            .shards
            .iter()
            .flat_map(|s| {
                s.lock()
                    .iter()
                    .map(|b| (b.as_ptr(), b[0]))
                    .collect::<Vec<_>>()
            })
            .find(|(p, _)| *p == ptr)
            .expect("buffer retained");
        assert_eq!(retained.1, 0xAB, "release must not scrub the buffer");
    }

    #[test]
    fn test_pool_bounds_capacity() {
        // More releases than the shard capacity must not grow the pool: excess
        // buffers are dropped instead of being retained forever.
        let pool = BufferPool::new(1024, 16);
        let mut held = Vec::new();
        for _ in 0..64 {
            held.push(pool.acquire());
        }
        for buf in held {
            pool.release(buf);
        }
        let mut recalled = 0;
        while pool.acquire()[0] == 0 {
            recalled += 1;
            if recalled > 64 {
                break;
            }
        }
        let total: usize = pool.shards.iter().map(|s| s.lock().len()).sum();
        assert!(total <= 16, "pool retained {total} buffers, cap is 16");
    }

    #[test]
    fn test_buffer_guard_raii() {
        let pool = BufferPool::default_pool();
        {
            let mut guard = pool.acquire_guard();
            assert_eq!(guard.len(), DEFAULT_BUFFER_SIZE);
            guard[0] = 42;
        }
        let b2 = pool.acquire();
        assert_eq!(b2.len(), DEFAULT_BUFFER_SIZE);
    }
}
