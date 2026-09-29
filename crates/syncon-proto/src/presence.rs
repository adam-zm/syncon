//! Presence message for the Syncon protocol.
//!
//! Heartbeat message to detect liveness and measure RTT.
//!
//! Layout (128 bytes max):
//! ```text
//! u64 send_counter
//! u64 last_rx_counter     # last send_counter observed from the peer
//! u8  active              # 1 if the sender considers the session active
//! ```

/// Presence message (heartbeat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presence {
    /// Monotonic counter incremented by the sender.
    pub send_counter: u64,
    /// Last `send_counter` received from the peer.
    pub last_rx_counter: u64,
    /// 1 if the sender considers the session active, 0 otherwise.
    pub active: u8,
}

impl Presence {
    /// Fixed size of the Presence message (17 bytes).
    pub const SIZE: usize = 17;

    /// Creates a new Presence message.
    pub fn new(send_counter: u64, last_rx_counter: u64, active: bool) -> Self {
        Self {
            send_counter,
            last_rx_counter,
            active: if active { 1 } else { 0 },
        }
    }

    /// Serializes the Presence message into a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);

        // send_counter (u64, little-endian)
        bytes.extend_from_slice(&self.send_counter.to_le_bytes());

        // last_rx_counter (u64, little-endian)
        bytes.extend_from_slice(&self.last_rx_counter.to_le_bytes());

        // active (u8)
        bytes.push(self.active);

        bytes
    }

    /// Deserializes a Presence message from a byte slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let send_counter = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);

        let last_rx_counter = u64::from_le_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);

        let active = data[16];

        Some(Self {
            send_counter,
            last_rx_counter,
            active,
        })
    }

    /// Returns `true` if the session is considered active.
    pub fn is_active(&self) -> bool {
        self.active == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presence_roundtrip() {
        let presence = Presence::new(42, 100, true);
        let bytes = presence.to_bytes();
        let parsed = Presence::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.send_counter, 42);
        assert_eq!(parsed.last_rx_counter, 100);
        assert!(parsed.is_active());
    }

    #[test]
    fn test_presence_inactive() {
        let presence = Presence::new(1, 0, false);
        assert!(!presence.is_active());
        let bytes = presence.to_bytes();
        let parsed = Presence::from_bytes(&bytes).unwrap();
        assert!(!parsed.is_active());
    }

    #[test]
    fn test_presence_too_short() {
        let data = vec![0u8; Presence::SIZE - 1];
        assert!(Presence::from_bytes(&data).is_none());
    }
}
