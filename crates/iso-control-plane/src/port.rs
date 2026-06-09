//! Host-port allocator for ingress forwards.
//!
//! Each ingress forward (ssh is just one — nothing special) gets an externally
//! bound host port assigned from a fixed range. Like the slot allocator, the
//! durable record of which ports are taken lives in the store; this is rebuilt
//! from it on startup.

use std::collections::HashSet;

pub struct PortAllocator {
    base: u16,
    end: u16, // exclusive
    used: HashSet<u16>,
    cursor: usize,
}

impl PortAllocator {
    pub fn new(base: u16, end: u16) -> Self {
        Self {
            base,
            end: end.max(base),
            used: HashSet::new(),
            cursor: 0,
        }
    }

    /// Allocate the next free host port, or `None` if the range is exhausted.
    pub fn allocate(&mut self) -> Option<u16> {
        let span = (self.end - self.base) as usize;
        for off in 0..span {
            let port = self.base + (((self.cursor + off) % span) as u16);
            if self.used.insert(port) {
                self.cursor = (self.cursor + off + 1) % span;
                return Some(port);
            }
        }
        None
    }

    /// Mark a port used (recovery from the store).
    pub fn reserve(&mut self, port: u16) {
        if (self.base..self.end).contains(&port) {
            self.used.insert(port);
        }
    }

    pub fn free(&mut self, port: u16) {
        self.used.remove(&port);
    }

    pub fn in_use(&self) -> usize {
        self.used.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_distinct_and_recycles() {
        let mut a = PortAllocator::new(20000, 20003);
        let p0 = a.allocate().unwrap();
        let p1 = a.allocate().unwrap();
        let p2 = a.allocate().unwrap();
        assert_eq!((p0, p1, p2), (20000, 20001, 20002));
        assert!(a.allocate().is_none());
        a.free(p1);
        assert_eq!(a.allocate().unwrap(), 20001);
    }

    #[test]
    fn reserve_excludes() {
        let mut a = PortAllocator::new(20000, 20002);
        a.reserve(20000);
        assert_eq!(a.allocate().unwrap(), 20001);
        assert!(a.allocate().is_none());
    }
}
