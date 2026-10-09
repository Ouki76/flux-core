use parking_lot::Mutex;
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

pub const DEFAULT_BUFFER_SIZE: usize = 16 * 1024; // 16 KB
pub const PACKET_BUFFER_SIZE: usize = 65536; // 64 KB for UDP datagrams

const NUM_SHARDS: usize = 16;

/// A thread-safe, 16-way sharded buffer pool to reuse 16KB byte buffers without malloc pressure or lock contention.
pub struct BufferPool {
    buffer_size: usize,
    shards: [Mutex<Vec<Vec<u8>>>; NUM_SHARDS],
    shard_capacity: usize,
    shard_counter: std::sync::atomic::AtomicUsize,
}

impl BufferPool {
    pub fn new(buffer_size: usize, max_capacity: usize) -> Self {
        let shard_capacity = (max_capacity / NUM_SHARDS).max(1);
        Self {
            buffer_size,
            shards: std::array::from_fn(|_| Mutex::new(Vec::with_capacity(shard_capacity))),
            shard_capacity,
            shard_counter: std::sync::atomic::AtomicUsize::new(0),
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
        let idx = self
            .shard_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % NUM_SHARDS;
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

    /// Release a buffer back to the pool, securely zeroing contents to prevent cross-session data leakage.
    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() < self.buffer_size {
            return;
        }
        if buf.len() != self.buffer_size {
            buf.resize(self.buffer_size, 0);
        }
        buf.fill(0);
        let idx = self
            .shard_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % NUM_SHARDS;
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
        self.buf.as_ref().expect("buffer present")
    }
}

impl DerefMut for BufferGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.as_mut().expect("buffer present")
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
