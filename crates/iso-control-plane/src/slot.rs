//! Placement-slot allocator.
//!
//! The slot *is* the network allocation (see the network manager). This is a
//! simple rotating bitmap; the durable record of which slots are taken lives in
//! SQLite, and the allocator is rebuilt from it on startup.

use iso_common::SlotId;

pub struct SlotAllocator {
    used: Vec<bool>,
    cursor: usize,
}

impl SlotAllocator {
    pub fn new(capacity: usize) -> Self {
        Self {
            used: vec![false; capacity],
            cursor: 0,
        }
    }

    /// Allocate the next free slot, scanning from the cursor (so freed slots
    /// aren't immediately reused — a small cooldown, per the network design).
    pub fn allocate(&mut self) -> Option<SlotId> {
        let n = self.used.len();
        for i in 0..n {
            let idx = (self.cursor + i) % n;
            if !self.used[idx] {
                self.used[idx] = true;
                self.cursor = (idx + 1) % n;
                return SlotId::new(idx as u16).ok();
            }
        }
        None
    }

    /// Mark a slot used (recovery from the store).
    pub fn reserve(&mut self, slot: SlotId) {
        let i = slot.get() as usize;
        if i < self.used.len() {
            self.used[i] = true;
        }
    }

    pub fn free(&mut self, slot: SlotId) {
        let i = slot.get() as usize;
        if i < self.used.len() {
            self.used[i] = false;
        }
    }

    pub fn in_use(&self) -> usize {
        self.used.iter().filter(|u| **u).count()
    }

    pub fn capacity(&self) -> usize {
        self.used.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_increasing_then_reuses_freed() {
        let mut a = SlotAllocator::new(4);
        let s0 = a.allocate().unwrap();
        let s1 = a.allocate().unwrap();
        assert_eq!((s0.get(), s1.get()), (0, 1));
        assert_eq!(a.in_use(), 2);
        a.free(s0);
        // cursor has moved past 0; we fill 2,3 then wrap to reuse 0.
        assert_eq!(a.allocate().unwrap().get(), 2);
        assert_eq!(a.allocate().unwrap().get(), 3);
        assert_eq!(a.allocate().unwrap().get(), 0);
        assert!(a.allocate().is_none(), "exhausted");
    }

    #[test]
    fn reserve_marks_used() {
        let mut a = SlotAllocator::new(4);
        a.reserve(SlotId::new(2).unwrap());
        assert_eq!(a.in_use(), 1);
        // allocation skips the reserved slot eventually.
        let got: Vec<u16> = std::iter::from_fn(|| a.allocate().map(|s| s.get())).collect();
        assert_eq!(got, vec![0, 1, 3]);
    }
}
