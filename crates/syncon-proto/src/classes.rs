//! Message classes for the Syncon protocol.
//!
//! Each class defines its behavior (reliable/datagram), max body size, and idempotency rules.

/// Protocol version (normative: 1).
pub const VERSION: u8 = 1;

/// Message classes in the Syncon protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Class {
    /// Control messages (opcodes like ping/pong/ack).
    Control = 1,
    /// Clipboard data (text or images). Latest generation wins.
    Clipboard = 2,
    /// Notification mirroring.
    Notify = 3,
    /// Input datagrams (pointer/keyboard).
    Input = 4,
    /// Handoff tokens (app id, title, URL).
    Handoff = 5,
    /// Blob metadata (file transfer).
    BlobMeta = 6,
    /// Presence/heartbeat.
    Presence = 7,
    /// Hello message (plaintext inside TLS).
    Hello = 8,
}

impl Class {
    /// Returns the maximum allowed body length for this class (in bytes).
    pub const fn max_body(&self) -> u32 {
        match self {
            Class::Control => 1024,
            Class::Clipboard => 16 * 1024, // 16 KiB
            Class::Notify => 8 * 1024,    // 8 KiB
            Class::Input => 256,
            Class::Handoff => 4 * 1024,   // 4 KiB
            Class::BlobMeta => 1024,
            Class::Presence => 128,
            Class::Hello => 256,
        }
    }

    /// Returns `true` if this class is sent over a reliable stream.
    pub const fn is_reliable(&self) -> bool {
        match self {
            Class::Input => false, // Datagram
            _ => true,            // All others are reliable streams
        }
    }

    /// Returns `true` if this class uses latest-wins semantics.
    pub const fn is_latest_wins(&self) -> bool {
        match self {
            Class::Clipboard | Class::Handoff | Class::Presence => true,
            _ => false,
        }
    }

    /// Returns the class value as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Creates a `Class` from a `u8` value.
    /// Returns `None` for unknown values (per spec: ignore unknown classes).
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Class::Control),
            2 => Some(Class::Clipboard),
            3 => Some(Class::Notify),
            4 => Some(Class::Input),
            5 => Some(Class::Handoff),
            6 => Some(Class::BlobMeta),
            7 => Some(Class::Presence),
            8 => Some(Class::Hello),
            _ => None,
        }
    }
}

/// Flags for the envelope header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u16);

impl Flags {
    /// No flags set.
    pub const NONE: Self = Self(0);

    /// Flag bit 0: Ack requested.
    pub const ACK_REQUESTED: u16 = 1 << 0;
    /// Flag bit 1: Body is an ack.
    pub const IS_ACK: u16 = 1 << 1;
    /// Flag bit 2: Sent as 0-RTT early data.
    pub const ZERO_RTT: u16 = 1 << 2;

    /// Creates a new `Flags` from a `u16`.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw `u16` value.
    pub const fn as_u16(&self) -> u16 {
        self.0
    }

    /// Returns `true` if the ack_requested flag is set.
    pub const fn ack_requested(&self) -> bool {
        (self.0 & Self::ACK_REQUESTED) != 0
    }

    /// Returns `true` if the is_ack flag is set.
    pub const fn is_ack(&self) -> bool {
        (self.0 & Self::IS_ACK) != 0
    }

    /// Returns `true` if the zero_rtt flag is set.
    pub const fn zero_rtt(&self) -> bool {
        (self.0 & Self::ZERO_RTT) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_max_body() {
        assert_eq!(Class::Control.max_body(), 1024);
        assert_eq!(Class::Clipboard.max_body(), 16 * 1024);
        assert_eq!(Class::Input.max_body(), 256);
    }

    #[test]
    fn test_class_reliability() {
        assert!(Class::Control.is_reliable());
        assert!(!Class::Input.is_reliable());
    }

    #[test]
    fn test_class_from_u8() {
        assert_eq!(Class::from_u8(1), Some(Class::Control));
        assert_eq!(Class::from_u8(8), Some(Class::Hello));
        assert_eq!(Class::from_u8(99), None); // Unknown
    }

    #[test]
    fn test_flags() {
        let flags = Flags::new(Flags::ACK_REQUESTED | Flags::IS_ACK);
        assert!(flags.ack_requested());
        assert!(flags.is_ack());
        assert!(!flags.zero_rtt());
    }
}
