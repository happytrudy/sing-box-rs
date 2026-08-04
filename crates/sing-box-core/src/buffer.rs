use std::sync::{Arc, Mutex, OnceLock};

const UDP_BUFFER_SIZE: usize = u16::MAX as usize;
const MAX_RETAINED_BUFFERS: usize = 256;

#[derive(Clone, Default)]
pub(crate) struct PacketBufferPool {
    buffers: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PacketBufferPool {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn acquire(&self) -> PacketBufferLease {
        let mut buffer = self
            .buffers
            .lock()
            .expect("packet buffer pool lock")
            .pop()
            .unwrap_or_else(|| vec![0; UDP_BUFFER_SIZE]);
        buffer.resize(UDP_BUFFER_SIZE, 0);
        PacketBufferLease {
            pool: self.clone(),
            buffer: Some(buffer),
        }
    }

    pub(crate) fn recycle(&self, mut buffer: Vec<u8>) {
        if buffer.capacity() < UDP_BUFFER_SIZE {
            return;
        }
        buffer.clear();
        let mut buffers = self.buffers.lock().expect("packet buffer pool lock");
        if buffers.len() < MAX_RETAINED_BUFFERS {
            buffers.push(buffer);
        }
    }

    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.buffers.lock().expect("packet buffer pool lock").len()
    }
}

pub(crate) struct PacketBufferLease {
    pool: PacketBufferPool,
    buffer: Option<Vec<u8>>,
}

impl PacketBufferLease {
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer
            .as_mut()
            .expect("packet buffer lease")
            .as_mut_slice()
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        self.buffer.take().expect("packet buffer lease")
    }
}

impl Drop for PacketBufferLease {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.recycle(buffer);
        }
    }
}

pub(crate) fn shared_packet_buffer_pool() -> PacketBufferPool {
    static POOL: OnceLock<PacketBufferPool> = OnceLock::new();
    POOL.get_or_init(PacketBufferPool::default).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_returns_the_same_allocation_to_the_pool() {
        let pool = PacketBufferPool::new();
        let first = pool.acquire();
        let first_ptr = first.buffer.as_ref().unwrap().as_ptr();
        drop(first);
        assert_eq!(pool.available(), 1);

        let second = pool.acquire();
        assert_eq!(second.buffer.as_ref().unwrap().as_ptr(), first_ptr);
    }
}
