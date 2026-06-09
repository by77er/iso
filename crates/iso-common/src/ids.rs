//! Core identifier and primitive types shared across components.

use std::fmt;

use crate::error::{Error, Result};

/// Durable, globally-unique VM **identity**.
///
/// Owned by the control plane and stable for the lifetime of a VM across hosts
/// and restarts. Stored as the raw 128 bits of a UUID; rendered in canonical
/// hyphenated form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VmId(u128);

impl VmId {
    /// Wrap raw 128 bits as a `VmId`.
    pub const fn from_u128(v: u128) -> Self {
        Self(v)
    }

    /// The raw 128-bit value.
    pub const fn as_u128(self) -> u128 {
        self.0
    }
}

impl fmt::Display for VmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0.to_be_bytes();
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
        )
    }
}

impl fmt::Debug for VmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VmId({self})")
    }
}

/// Per-host, recyclable **placement** slot.
///
/// The slot *is* the network address allocation: every fixture (netns, tap,
/// veth `/31`, MAC) derives deterministically from it. Valid range is
/// `0..=32767` — `2^15` slots out of the `/16` veth space.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotId(u16);

impl SlotId {
    /// Largest valid slot (`2^15 - 1`).
    pub const MAX: u16 = 32767;

    /// Construct a slot, validating it is within range.
    pub const fn new(v: u16) -> Result<Self> {
        if v <= Self::MAX {
            Ok(Self(v))
        } else {
            Err(Error::SlotOutOfRange(v))
        }
    }

    /// The raw slot value.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlotId({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_range_is_enforced() {
        assert!(SlotId::new(0).is_ok());
        assert!(SlotId::new(SlotId::MAX).is_ok());
        assert!(matches!(
            SlotId::new(SlotId::MAX + 1),
            Err(Error::SlotOutOfRange(_))
        ));
    }

    #[test]
    fn vmid_renders_as_uuid() {
        let id = VmId::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        assert_eq!(id.to_string(), "01234567-89ab-cdef-0123-456789abcdef");
    }

}
