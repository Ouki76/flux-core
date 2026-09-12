use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;
use bytes::Bytes;
use parking_lot::Mutex;

pub const DEFAULT_BUFFER_SIZE: usize = 16 * 1024; // 16 KB

/// A thread-safe buffer pool to reuse 16KB byte buffers without malloc pressure.
pub struct BufferPool {
    buffer_size: usize,
    pool: Mutex<Vec<Vec<u8>>>,
    max_capacity: usize,
}

impl BufferPool {
    pub fn new(buffer_size: usize, max_capacity: usize) -> Self {
        Self {
            buffer_size,
            pool: Mutex::new(Vec::with_capacity(max_capacity)),
            max_capacity,
        }
    }

    pub fn default_pool() -> &'static Self {
        static INSTANCE: OnceLock<BufferPool> = OnceLock::new();
        INSTANCE.get_or_init(|| BufferPool::new(DEFAULT_BUFFER_SIZE, 64))
    }

    /// Acquire a buffer from the pool or allocate a new one.
    pub fn acquire(&self) -> Vec<u8> {
        let mut guard = self.pool.lock();
        guard.pop().unwrap_or_else(|| vec![0u8; self.buffer_size])
    }

    /// Acquire a buffer wrapped in RAII BufferGuard that returns to pool upon drop.
    pub fn acquire_guard(&'static self) -> BufferGuard {
        BufferGuard {
            buf: Some(self.acquire()),
            pool: self,
        }
    }

    /// Release a buffer back to the pool.
    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() < self.buffer_size {
            return;
        }
        buf.clear();
        buf.resize(self.buffer_size, 0);
        let mut guard = self.pool.lock();
        if guard.len() < self.max_capacity {
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

/// Helper to wrap bytes into zero-copy Bytes.
pub fn into_bytes(buf: &[u8]) -> Bytes {
    Bytes::copy_from_slice(buf)
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
