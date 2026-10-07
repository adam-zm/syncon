//! Control messages for the Syncon protocol.
//!
//! Sent as the body of an envelope with `class = Class::Control`.
//!
//! Layout:
//! ```text
//! u16 opcode
//! ... (opcode-specific payload)
//! ```

use crate::classes::Class;

/// Control opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ControlOpcode {
    /// Ping: `u64` monotonic ms from sender's arbitrary clock.
    Ping = 1,
    /// Pong: echo of the Ping's `u64`.
    Pong = 2,
    /// Ack: `u8 class`, `u64 seq`.
    Ack = 3,
    /// Unpair: empty payload. Receiver deletes the pin and closes.
    Unpair = 4,
    /// Features: `u32` bits currently granted by the human.
    Features = 5,
    /// PairConfirm: empty payload. The human on the sender confirmed the SAS.
    PairConfirm = 6,
    /// PairReject: empty payload. The sender cancelled or saw a SAS mismatch.
    PairReject = 7,
}

impl ControlOpcode {
    /// Returns the opcode as a `u16`.
    pub const fn as_u16(&self) -> u16 {
        *self as u16
    }

    /// Creates a `ControlOpcode` from a `u16`.
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(ControlOpcode::Ping),
            2 => Some(ControlOpcode::Pong),
            3 => Some(ControlOpcode::Ack),
            4 => Some(ControlOpcode::Unpair),
            5 => Some(ControlOpcode::Features),
            6 => Some(ControlOpcode::PairConfirm),
            7 => Some(ControlOpcode::PairReject),
            _ => None,
        }
    }
}

/// Control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// Ping with a monotonic timestamp.
    Ping(u64),
    /// Pong with the echoed timestamp.
    Pong(u64),
    /// Ack for a specific class and sequence number.
    Ack { class: Class, seq: u64 },
    /// Unpair request.
    Unpair,
    /// Features granted by the human.
    Features(u32),
    /// SAS confirmed by the sender's human (pairing only).
    PairConfirm,
    /// SAS rejected or pairing cancelled by the sender (pairing only).
    PairReject,
}

impl Control {
    /// Serializes the Control message into a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        match self {
            Control::Ping(ts) => {
                bytes.extend_from_slice(&ControlOpcode::Ping.as_u16().to_le_bytes());
                bytes.extend_from_slice(&ts.to_le_bytes());
            }
            Control::Pong(ts) => {
                bytes.extend_from_slice(&ControlOpcode::Pong.as_u16().to_le_bytes());
                bytes.extend_from_slice(&ts.to_le_bytes());
            }
            Control::Ack { class, seq } => {
                bytes.extend_from_slice(&ControlOpcode::Ack.as_u16().to_le_bytes());
                bytes.push(class.as_u8());
                bytes.extend_from_slice(&seq.to_le_bytes());
            }
            Control::Unpair => {
                bytes.extend_from_slice(&ControlOpcode::Unpair.as_u16().to_le_bytes());
            }
            Control::Features(bits) => {
                bytes.extend_from_slice(&ControlOpcode::Features.as_u16().to_le_bytes());
                bytes.extend_from_slice(&bits.to_le_bytes());
            }
            Control::PairConfirm => {
                bytes.extend_from_slice(&ControlOpcode::PairConfirm.as_u16().to_le_bytes());
            }
            Control::PairReject => {
                bytes.extend_from_slice(&ControlOpcode::PairReject.as_u16().to_le_bytes());
            }
        }

        bytes
    }

    /// Deserializes a Control message from a byte slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        let opcode = u16::from_le_bytes([data[0], data[1]]);
        let opcode = ControlOpcode::from_u16(opcode)?;

        match opcode {
            ControlOpcode::Ping => {
                if data.len() < 10 {
                    return None;
                }
                let ts = u64::from_le_bytes([
                    data[2], data[3], data[4], data[5],
                    data[6], data[7], data[8], data[9],
                ]);
                Some(Control::Ping(ts))
            }
            ControlOpcode::Pong => {
                if data.len() < 10 {
                    return None;
                }
                let ts = u64::from_le_bytes([
                    data[2], data[3], data[4], data[5],
                    data[6], data[7], data[8], data[9],
                ]);
                Some(Control::Pong(ts))
            }
            ControlOpcode::Ack => {
                if data.len() < 11 {
                    return None;
                }
                let class = Class::from_u8(data[2])?;
                let seq = u64::from_le_bytes([
                    data[3], data[4], data[5], data[6],
                    data[7], data[8], data[9], data[10],
                ]);
                Some(Control::Ack { class, seq })
            }
            ControlOpcode::Unpair => {
                if data.len() < 2 {
                    return None;
                }
                Some(Control::Unpair)
            }
            ControlOpcode::Features => {
                if data.len() < 6 {
                    return None;
                }
                let bits = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                Some(Control::Features(bits))
            }
            ControlOpcode::PairConfirm => Some(Control::PairConfirm),
            ControlOpcode::PairReject => Some(Control::PairReject),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classes::Class;

    #[test]
    fn test_control_ping_roundtrip() {
        let control = Control::Ping(12345);
        let bytes = control.to_bytes();
        let parsed = Control::from_bytes(&bytes).unwrap();
        assert!(matches!(parsed, Control::Ping(12345)));
    }

    #[test]
    fn test_control_pong_roundtrip() {
        let control = Control::Pong(12345);
        let bytes = control.to_bytes();
        let parsed = Control::from_bytes(&bytes).unwrap();
        assert!(matches!(parsed, Control::Pong(12345)));
    }

    #[test]
    fn test_control_ack_roundtrip() {
        let control = Control::Ack {
            class: Class::Clipboard,
            seq: 42,
        };
        let bytes = control.to_bytes();
        let parsed = Control::from_bytes(&bytes).unwrap();
        assert!(matches!(parsed, Control::Ack { class: Class::Clipboard, seq: 42 }));
    }

    #[test]
    fn test_control_unpair_roundtrip() {
        let control = Control::Unpair;
        let bytes = control.to_bytes();
        let parsed = Control::from_bytes(&bytes).unwrap();
        assert!(matches!(parsed, Control::Unpair));
    }

    #[test]
    fn test_control_features_roundtrip() {
        let control = Control::Features(0b101);
        let bytes = control.to_bytes();
        let parsed = Control::from_bytes(&bytes).unwrap();
        assert!(matches!(parsed, Control::Features(0b101)));
    }

    #[test]
    fn test_control_pair_roundtrip() {
        for c in [Control::PairConfirm, Control::PairReject] {
            assert_eq!(Control::from_bytes(&c.to_bytes()), Some(c));
        }
    }

    #[test]
    fn test_control_too_short() {
        let data = vec![0u8; 1];
        assert!(Control::from_bytes(&data).is_none());
    }

    #[test]
    fn test_control_unknown_opcode() {
        let data = vec![0xFF, 0xFF]; // Unknown opcode
        assert!(Control::from_bytes(&data).is_none());
    }
}
