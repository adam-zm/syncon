//! Clipboard message for the Syncon protocol.
//!
//! Layout (16 KiB max):
//! ```text
//! u64 generation          # latest wins, persisted across reconnect
//! u8  kind                # 1 = utf-8 text
//! u8  sensitive           # if 1, sender should not have sent it; receiver must drop
//! u16 reserved
//! u32 text_len
//! u8  text[text_len]
//! ```

/// Clipboard kind (type of content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClipboardKind {
    /// UTF-8 text.
    Text = 1,
    /// Image (not used in M0).
    Image = 2,
    /// Unknown kind.
    Unknown = 255,
}

impl ClipboardKind {
    /// Returns the kind as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Creates a `ClipboardKind` from a `u8`.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => ClipboardKind::Text,
            2 => ClipboardKind::Image,
            _ => ClipboardKind::Unknown,
        }
    }
}

/// Clipboard message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clipboard {
    /// Generation number (latest wins).
    pub generation: u64,
    /// Kind of clipboard content.
    pub kind: ClipboardKind,
    /// If 1, the content is sensitive and must be dropped.
    pub sensitive: bool,
    /// Reserved field (must be 0).
    pub reserved: u16,
    /// Text content (UTF-8).
    pub text: Vec<u8>,
}

impl Clipboard {
    /// Maximum text length (16 KiB).
    pub const MAX_TEXT_LEN: u32 = 16 * 1024;

    /// Creates a new Clipboard message with text content.
    pub fn new(generation: u64, text: Vec<u8>) -> Self {
        Self {
            generation,
            kind: ClipboardKind::Text,
            sensitive: false,
            reserved: 0,
            text,
        }
    }

    /// Creates a new sensitive Clipboard message.
    pub fn new_sensitive(generation: u64, text: Vec<u8>) -> Self {
        Self {
            generation,
            kind: ClipboardKind::Text,
            sensitive: true,
            reserved: 0,
            text,
        }
    }

    /// Serializes the Clipboard message into a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16 + self.text.len());

        // generation (u64, little-endian)
        bytes.extend_from_slice(&self.generation.to_le_bytes());

        // kind (u8)
        bytes.push(self.kind.as_u8());

        // sensitive (u8: 1 if true, 0 if false)
        bytes.push(if self.sensitive { 1 } else { 0 });

        // reserved (u16, little-endian)
        bytes.extend_from_slice(&self.reserved.to_le_bytes());

        // text_len (u32, little-endian)
        bytes.extend_from_slice(&(self.text.len() as u32).to_le_bytes());

        // text (UTF-8 bytes)
        bytes.extend_from_slice(&self.text);

        bytes
    }

    /// Deserializes a Clipboard message from a byte slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        let generation = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        let kind = ClipboardKind::from_u8(data[8]);
        let sensitive = data[9] == 1;
        let reserved = u16::from_le_bytes([data[10], data[11]]);
        let text_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        if data.len() < 16 + text_len {
            return None;
        }

        let text = data[16..16 + text_len].to_vec();

        Some(Self {
            generation,
            kind,
            sensitive,
            reserved,
            text,
        })
    }

    /// Returns `true` if the clipboard content is sensitive.
    pub fn is_sensitive(&self) -> bool {
        self.sensitive
    }

    /// Latest-wins apply: strictly greater generation, and never a sensitive clip.
    pub fn should_apply(&self, last_applied: u64) -> bool {
        !self.is_sensitive() && self.generation > last_applied
    }

    /// Returns the text as a UTF-8 string (if valid).
    pub fn text_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.text).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_roundtrip() {
        let clipboard = Clipboard::new(42, b"Hello, world!".to_vec());
        let bytes = clipboard.to_bytes();
        let parsed = Clipboard::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.generation, 42);
        assert_eq!(parsed.kind, ClipboardKind::Text);
        assert!(!parsed.is_sensitive());
        assert_eq!(parsed.text_str(), Some("Hello, world!"));
    }

    #[test]
    fn test_clipboard_sensitive() {
        let clipboard = Clipboard::new_sensitive(1, b"secret".to_vec());
        assert!(clipboard.is_sensitive());
        let bytes = clipboard.to_bytes();
        let parsed = Clipboard::from_bytes(&bytes).unwrap();
        assert!(parsed.is_sensitive());
    }

    #[test]
    fn test_clipboard_too_short() {
        let data = vec![0u8; 15];
        assert!(Clipboard::from_bytes(&data).is_none());
    }

    #[test]
    fn test_clipboard_generation_ignored_if_lower() {
        let applied = Clipboard::new(10, b"old".to_vec());
        assert!(applied.should_apply(0));
        assert!(!Clipboard::new(10, b"same".to_vec()).should_apply(applied.generation));
        assert!(!Clipboard::new(5, b"older".to_vec()).should_apply(applied.generation));
        assert!(Clipboard::new(11, b"newer".to_vec()).should_apply(applied.generation));
        assert!(!Clipboard::new_sensitive(12, b"secret".to_vec()).should_apply(applied.generation));
    }
}
