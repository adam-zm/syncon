//! Syncon crypto: identity bundle, SAS, HKDF, AEAD, cert generation, pin check.
//!
//! This crate must not depend on sockets.
#![forbid(unsafe_code)]

pub mod aead;
pub mod identity;
pub mod sas;

// Re-export key types for convenience.
pub use aead::{
    validate_nonce_uniqueness, x25519_shared, InnerAeadKey, NONCE_LEN, X25519_SHARED_LEN,
};
pub use identity::{
    compute_fingerprint, compute_fingerprint_hex, Identity, PublicIdentity, ED25519_PUB_LEN,
    FINGERPRINT_LEN, PUBLIC_IDENTITY_LEN, X25519_PUB_LEN,
};
pub use sas::{compute_sas, compute_sas_with_order, validate_sas_display, SasCode, EXPORTER_LEN};
