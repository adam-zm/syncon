//! Syncon protocol definitions: envelope codec, class enums, message bodies, version constant, size limits.
//!
//! This crate must not depend on sockets, tokio, or files.
#![forbid(unsafe_code)]

pub mod classes;
pub mod clipboard;
pub mod control;
pub mod envelope;
pub mod hello;
pub mod presence;

// Re-export key types for convenience.
pub use classes::{Class, Flags, VERSION};
pub use clipboard::Clipboard;
pub use control::Control;
pub use envelope::{Envelope, EnvelopeError, Header, HEADER_SIZE};
pub use hello::{FeatureBits, Hello, Role};
pub use presence::Presence;
