//! Envelope codec for the Syncon protocol.
//!
//! An envelope consists of a fixed 16-byte header followed by a body.
//! The header is packed in little-endian byte order.

use crate::classes::{Class, Flags, VERSION};

/// Fixed size of the envelope header (16 bytes).
pub const HEADER_SIZE: usize = 16;

/// Maximum body length allowed by the protocol (enforced per-class).
pub const MAX_BODY_LEN: u32 = 16 * 1024; // 16 KiB (clipboard max)

/// Error returned during envelope parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The version byte is not supported.
    UnsupportedVersion(u8),
    /// The class value is unknown.
    UnknownClass(u8),
    /// The body length exceeds the class maximum.
    BodyTooLarge { class: Class, body_len: u32, max: u32 },
    /// The sequence number is zero (illegal).
    ZeroSequence,
    /// The envelope data is too short to contain the header.
    TooShort,
}

/// An envelope header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub class: Class,
    pub flags: Flags,
    pub seq: u64,
    pub body_len: u32,
}

impl Header {
    /// Creates a new header with the given parameters.
    pub fn new(class: Class, flags: Flags, seq: u64, body_len: u32) -> Self {
        Self {
            version: VERSION,
            class,
            flags,
            seq,
            body_len,
        }
    }

    /// Serializes the header into a 16-byte array (little-endian).
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = self.version;
        bytes[1] = self.class.as_u8();
        // flags (u16) at offset 2
        bytes[2..4].copy_from_slice(&self.flags.as_u16().to_le_bytes());
        // seq (u64) at offset 4
        bytes[4..12].copy_from_slice(&self.seq.to_le_bytes());
        // body_len (u32) at offset 12
        bytes[12..16].copy_from_slice(&self.body_len.to_le_bytes());
        bytes
    }

    /// Deserializes a header from a 16-byte slice.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EnvelopeError> {
        if data.len() < HEADER_SIZE {
            return Err(EnvelopeError::TooShort);
        }

        let version = data[0];
        if version != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }

        let class = Class::from_u8(data[1])
            .ok_or_else(|| EnvelopeError::UnknownClass(data[1]))?;

        let flags = Flags::new(u16::from_le_bytes([data[2], data[3]]));
        let seq = u64::from_le_bytes([
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11],
        ]);
        let body_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

        // Validate seq != 0
        if seq == 0 {
            return Err(EnvelopeError::ZeroSequence);
        }

        // Validate body_len against class max
        if body_len > class.max_body() {
            return Err(EnvelopeError::BodyTooLarge {
                class,
                body_len,
                max: class.max_body(),
            });
        }

        Ok(Self {
            version,
            class,
            flags,
            seq,
            body_len,
        })
    }
}

/// A complete envelope (header + body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub header: Header,
    pub body: Vec<u8>,
}

impl Envelope {
    /// Creates a new envelope with the given header and body.
    /// Returns an error if the body length exceeds the class maximum.
    pub fn new(header: Header, body: Vec<u8>) -> Result<Self, EnvelopeError> {
        if body.len() as u32 > header.class.max_body() {
            return Err(EnvelopeError::BodyTooLarge {
                class: header.class,
                body_len: body.len() as u32,
                max: header.class.max_body(),
            });
        }
        Ok(Self { header, body })
    }

    /// Serializes the envelope into a byte vector (header + body).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_SIZE + self.body.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Deserializes an envelope from a byte slice.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EnvelopeError> {
        let header = Header::from_bytes(data)?;
        if data.len() < HEADER_SIZE + header.body_len as usize {
            return Err(EnvelopeError::TooShort);
        }
        let body = data[HEADER_SIZE..HEADER_SIZE + header.body_len as usize].to_vec();
        Ok(Self { header, body })
    }

    /// Returns the total size of the envelope (header + body).
    pub fn total_size(&self) -> usize {
        HEADER_SIZE + self.body.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = Header::new(
            Class::Clipboard,
            Flags::new(Flags::ACK_REQUESTED),
            42,
            1024,
        );
        let bytes = header.to_bytes();
        let parsed = Header::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, VERSION);
        assert_eq!(parsed.class, Class::Clipboard);
        assert_eq!(parsed.seq, 42);
        assert_eq!(parsed.body_len, 1024);
        assert!(parsed.flags.ack_requested());
    }

    #[test]
    fn test_header_zero_seq_rejected() {
        let header = Header {
            version: VERSION,
            class: Class::Presence,
            flags: Flags::NONE,
            seq: 0,
            body_len: 128,
        };
        let bytes = header.to_bytes();
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(EnvelopeError::ZeroSequence)
        ));
    }

    #[test]
    fn test_header_body_too_large() {
        let header = Header {
            version: VERSION,
            class: Class::Input,
            flags: Flags::NONE,
            seq: 1,
            body_len: 1024, // Input max is 256
        };
        let bytes = header.to_bytes();
        assert!(matches!(
            Header::from_bytes(&bytes),
            Err(EnvelopeError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn test_envelope_roundtrip() {
        let header = Header::new(Class::Presence, Flags::NONE, 1, 128);
        let body = vec![0u8; 128];
        let envelope = Envelope::new(header, body).unwrap();
        let bytes = envelope.to_bytes();
        let parsed = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.header.class, Class::Presence);
        assert_eq!(parsed.body, vec![0u8; 128]);
    }

    #[test]
    fn test_envelope_too_short() {
        let data = vec![0u8; HEADER_SIZE - 1];
        assert!(matches!(
            Envelope::from_bytes(&data),
            Err(EnvelopeError::TooShort)
        ));
    }
}
