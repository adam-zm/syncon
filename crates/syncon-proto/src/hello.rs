//! Hello message for the Syncon protocol.
//!
//! Sent as plaintext inside TLS during the initial handshake.
//!
//! Layout (256 bytes max):
//! ```text
//! u8   version            = 1
//! u8   role               = 0 desktop, 1 phone, 255 unknown
//! u16  reserved           = 0
//! [32] eph_x25519_pub
//! [32] sign_pub           must match the certificate
//! [32] dh_pub
//! u32  feature_bits
//! u16  max_body           proposal, see limits
//! [16] fingerprint        of sign_pub (SHA-256(sign_pub)[0..16])
//! ```

/// Role of the peer in the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// Desktop (e.g., Linux).
    Desktop = 0,
    /// Phone (e.g., Android).
    Phone = 1,
    /// Unknown role.
    Unknown = 255,
}

impl Role {
    /// Returns the role as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Creates a `Role` from a `u8`.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Role::Desktop,
            1 => Role::Phone,
            _ => Role::Unknown,
        }
    }
}

/// Feature bits for the Syncon protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureBits(u32);

impl FeatureBits {
    /// No features enabled.
    pub const NONE: Self = Self(0);

    /// Bit 0: Clipboard text.
    pub const CLIPBOARD_TEXT: u32 = 1 << 0;
    /// Bit 1: Clipboard image (not M0).
    pub const CLIPBOARD_IMAGE: u32 = 1 << 1;
    /// Bit 2: Notifications (not M0).
    pub const NOTIFICATIONS: u32 = 1 << 2;
    /// Bit 3: Blob transfer (not M0).
    pub const BLOB_TRANSFER: u32 = 1 << 3;
    /// Bit 4: Handoff (not M0).
    pub const HANDOFF: u32 = 1 << 4;
    /// Bit 5: Input datagrams (not M0).
    pub const INPUT_DATAGRAMS: u32 = 1 << 5;

    /// Creates a new `FeatureBits` from a `u32`.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw `u32` value.
    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// Returns `true` if clipboard text is enabled.
    pub const fn has_clipboard_text(&self) -> bool {
        (self.0 & Self::CLIPBOARD_TEXT) != 0
    }

    /// Returns `true` if clipboard images are enabled.
    pub const fn has_clipboard_image(&self) -> bool {
        (self.0 & Self::CLIPBOARD_IMAGE) != 0
    }

    /// Returns `true` if notifications are enabled.
    pub const fn has_notifications(&self) -> bool {
        (self.0 & Self::NOTIFICATIONS) != 0
    }

    /// Returns `true` if blob transfer is enabled.
    pub const fn has_blob_transfer(&self) -> bool {
        (self.0 & Self::BLOB_TRANSFER) != 0
    }

    /// Returns `true` if handoff is enabled.
    pub const fn has_handoff(&self) -> bool {
        (self.0 & Self::HANDOFF) != 0
    }

    /// Returns `true` if input datagrams are enabled.
    pub const fn has_input_datagrams(&self) -> bool {
        (self.0 & Self::INPUT_DATAGRAMS) != 0
    }
}

/// Fixed size of the Hello message (256 bytes max, but struct is fixed).
/// Layout: 1 + 1 + 2 + 32 + 32 + 32 + 4 + 2 + 16 = 122 bytes.
pub const HELLO_SIZE: usize = 122;

/// Hello message sent during the initial handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    pub version: u8,
    pub role: Role,
    pub reserved: u16,
    pub eph_x25519_pub: [u8; 32],
    pub sign_pub: [u8; 32],
    pub dh_pub: [u8; 32],
    pub feature_bits: FeatureBits,
    pub max_body: u16,
    pub fingerprint: [u8; 16],
}

impl Hello {
    /// Creates a new Hello message.
    pub fn new(
        role: Role,
        eph_x25519_pub: [u8; 32],
        sign_pub: [u8; 32],
        dh_pub: [u8; 32],
        feature_bits: FeatureBits,
        max_body: u16,
        fingerprint: [u8; 16],
    ) -> Self {
        Self {
            version: crate::VERSION,
            role,
            reserved: 0,
            eph_x25519_pub,
            sign_pub,
            dh_pub,
            feature_bits,
            max_body,
            fingerprint,
        }
    }

    /// Serializes the Hello message into a byte array.
    pub fn to_bytes(&self) -> [u8; HELLO_SIZE] {
        let mut bytes = [0u8; HELLO_SIZE];
        let mut offset = 0;

        // version (u8)
        bytes[offset] = self.version;
        offset += 1;

        // role (u8)
        bytes[offset] = self.role.as_u8();
        offset += 1;

        // reserved (u16, little-endian)
        bytes[offset..offset + 2].copy_from_slice(&self.reserved.to_le_bytes());
        offset += 2;

        // eph_x25519_pub (32 bytes)
        bytes[offset..offset + 32].copy_from_slice(&self.eph_x25519_pub);
        offset += 32;

        // sign_pub (32 bytes)
        bytes[offset..offset + 32].copy_from_slice(&self.sign_pub);
        offset += 32;

        // dh_pub (32 bytes)
        bytes[offset..offset + 32].copy_from_slice(&self.dh_pub);
        offset += 32;

        // feature_bits (u32, little-endian)
        bytes[offset..offset + 4].copy_from_slice(&self.feature_bits.as_u32().to_le_bytes());
        offset += 4;

        // max_body (u16, little-endian)
        bytes[offset..offset + 2].copy_from_slice(&self.max_body.to_le_bytes());
        offset += 2;

        // fingerprint (16 bytes)
        bytes[offset..offset + 16].copy_from_slice(&self.fingerprint);

        bytes
    }

    /// Deserializes a Hello message from a byte slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < HELLO_SIZE {
            return None;
        }

        let mut offset = 0;

        let version = data[offset];
        offset += 1;

        let role = Role::from_u8(data[offset]);
        offset += 1;

        let reserved = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let mut eph_x25519_pub = [0u8; 32];
        eph_x25519_pub.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut sign_pub = [0u8; 32];
        sign_pub.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut dh_pub = [0u8; 32];
        dh_pub.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let feature_bits = FeatureBits::new(u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]));
        offset += 4;

        let max_body = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let mut fingerprint = [0u8; 16];
        fingerprint.copy_from_slice(&data[offset..offset + 16]);

        Some(Self {
            version,
            role,
            reserved,
            eph_x25519_pub,
            sign_pub,
            dh_pub,
            feature_bits,
            max_body,
            fingerprint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_roundtrip() {
        let hello = Hello::new(
            Role::Desktop,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            FeatureBits::new(FeatureBits::CLIPBOARD_TEXT),
            1024,
            [4u8; 16],
        );

        let bytes = hello.to_bytes();
        let parsed = Hello::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, crate::VERSION);
        assert_eq!(parsed.role, Role::Desktop);
        assert_eq!(parsed.eph_x25519_pub, [1u8; 32]);
        assert_eq!(parsed.sign_pub, [2u8; 32]);
        assert_eq!(parsed.dh_pub, [3u8; 32]);
        assert!(parsed.feature_bits.has_clipboard_text());
        assert_eq!(parsed.max_body, 1024);
        assert_eq!(parsed.fingerprint, [4u8; 16]);
    }

    #[test]
    fn test_hello_too_short() {
        let data = vec![0u8; HELLO_SIZE - 1];
        assert!(Hello::from_bytes(&data).is_none());
    }

    #[test]
    fn test_feature_bits() {
        let bits = FeatureBits::new(
            FeatureBits::CLIPBOARD_TEXT | FeatureBits::NOTIFICATIONS | FeatureBits::INPUT_DATAGRAMS,
        );
        assert!(bits.has_clipboard_text());
        assert!(bits.has_notifications());
        assert!(bits.has_input_datagrams());
        assert!(!bits.has_clipboard_image());
    }
}
