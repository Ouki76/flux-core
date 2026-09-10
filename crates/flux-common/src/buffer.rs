use std::sync::Mutex;
use bytes::Bytes;

pub const DEFAULT_BUFFER_SIZE: usize = 16 * 1024; // 16 KB

/// A simple thread-safe buffer pool to reuse 16KB-32KB byte buffers without malloc pressure.
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
        static INSTANCE: std::sync::OnceLock<BufferPool> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(|| BufferPool::new(DEFAULT_BUFFER_SIZE, 512))
    }

    /// Acquire a buffer from the pool or allocate a new one.
    pub fn acquire(&self) -> Vec<u8> {
        let mut guard = self.pool.lock().unwrap();
        guard.pop().unwrap_or_else(|| vec![0u8; self.buffer_size])
    }

    /// Release a buffer back to the pool.
    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() < self.buffer_size {
            return;
        }
        buf.resize(self.buffer_size, 0);
        let mut guard = self.pool.lock().unwrap();
        if guard.len() < self.max_capacity {
            guard.push(buf);
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
}
