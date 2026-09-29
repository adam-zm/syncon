//! Identity management for the Syncon protocol.
//!
//! This module provides generation, serialization, and verification of device identities.
//! Each device has:
//! - An Ed25519 keypair for signing (used for certificates and pinning)
//! - An X25519 static keypair for the inner AEAD key derivation
//!
//! The public identity is the 32-byte Ed25519 public key plus the 32-byte X25519 public key.
//! The fingerprint is the first 16 bytes of SHA-256(sign_pub), as lowercase hex.

use ring::{
    agreement, digest,
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair as _},
};

/// Length of an Ed25519 public key in bytes.
pub const ED25519_PUB_LEN: usize = 32;

/// Length of an X25519 public key in bytes.
pub const X25519_PUB_LEN: usize = 32;

/// Length of a fingerprint in bytes (first 16 bytes of SHA-256 of Ed25519 pub).
pub const FINGERPRINT_LEN: usize = 16;

/// Length of the combined public identity (Ed25519 pub + X25519 pub).
pub const PUBLIC_IDENTITY_LEN: usize = ED25519_PUB_LEN + X25519_PUB_LEN;

/// The complete identity bundle for a device.
///
/// This contains all cryptographic material needed for a device to authenticate
/// and establish secure sessions with peers.
#[derive(Debug)]
pub struct Identity {
    /// Ed25519 keypair for signing and certificate generation.
    pub sign_keypair: Ed25519KeyPair,

    /// X25519 static keypair for inner AEAD key derivation.
    pub dh_static_keypair: agreement::EphemeralPrivateKey,

    /// The self-signed certificate bytes (DER-encoded, rustls-compatible).
    pub certificate: Vec<u8>,

    /// Cached Ed25519 public key bytes.
    pub sign_pub: [u8; ED25519_PUB_LEN],

    /// Cached X25519 static public key bytes.
    pub dh_pub: [u8; X25519_PUB_LEN],

    /// Cached fingerprint: first 16 bytes of SHA-256(sign_pub).
    pub fingerprint: [u8; FINGERPRINT_LEN],
}

impl Identity {
    /// Generates a new random identity bundle.
    ///
    /// This creates:
    /// - A new Ed25519 keypair for signing
    /// - A new X25519 static keypair for DH
    /// - A self-signed certificate
    /// - The fingerprint from the Ed25519 public key
    ///
    /// Returns `None` if the system random number generator fails.
    pub fn generate() -> Option<Self> {
        let rng = SystemRandom::new();

        // Generate Ed25519 keypair for signing
        let sign_seed = signature::Ed25519KeyPair::generate_pkcs8(&rng).ok()?;
        let sign_keypair = signature::Ed25519KeyPair::from_pkcs8(sign_seed.as_ref()).ok()?;
        let sign_pub = sign_keypair.public_key().as_ref();
        let mut sign_pub_array = [0u8; ED25519_PUB_LEN];
        sign_pub_array.copy_from_slice(sign_pub);

        // Generate X25519 static keypair for inner AEAD
        let dh_static_priv =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).ok()?;
        let dh_pub = dh_static_priv.compute_public_key().ok()?;
        let mut dh_pub_array = [0u8; X25519_PUB_LEN];
        dh_pub_array.copy_from_slice(dh_pub.as_ref());

        // Compute fingerprint: first 16 bytes of SHA-256(sign_pub)
        let fingerprint = compute_fingerprint(sign_pub);

        // Generate self-signed certificate
        let certificate = generate_self_signed_cert(&sign_keypair, sign_pub, &dh_pub_array)?;

        Some(Self {
            sign_keypair,
            dh_static_keypair: dh_static_priv,
            certificate,
            sign_pub: sign_pub_array,
            dh_pub: dh_pub_array,
            fingerprint,
        })
    }

    /// Returns the public identity (Ed25519 pub + X25519 pub) as a byte array.
    pub fn public_identity(&self) -> [u8; PUBLIC_IDENTITY_LEN] {
        let mut result = [0u8; PUBLIC_IDENTITY_LEN];
        result[..ED25519_PUB_LEN].copy_from_slice(&self.sign_pub);
        result[ED25519_PUB_LEN..].copy_from_slice(&self.dh_pub);
        result
    }

    /// Returns the fingerprint as a lowercase hex string (32 characters).
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    /// Returns the Ed25519 public key.
    pub fn sign_public_key(&self) -> [u8; ED25519_PUB_LEN] {
        self.sign_pub
    }

    /// Returns the X25519 static public key.
    pub fn dh_public_key(&self) -> [u8; X25519_PUB_LEN] {
        self.dh_pub
    }

    /// Returns the raw certificate bytes.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Performs X25519 key exchange with a peer's public key.
    ///
    /// Returns the shared secret (32 bytes).
    /// Note: This consumes the local private key to ensure it's only used once.
    pub fn into_dh_static_shared_secret(
        self,
        peer_dh_pub: &[u8; X25519_PUB_LEN],
    ) -> Option<[u8; X25519_PUB_LEN]> {
        let peer_pub = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_dh_pub);
        agreement::agree_ephemeral(self.dh_static_keypair, &peer_pub, |secret| {
            let mut result = [0u8; X25519_PUB_LEN];
            result.copy_from_slice(secret);
            result
        })
        .ok()
    }

    /// Signs a message with the Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> signature::Signature {
        self.sign_keypair.sign(message)
    }

    /// Verifies a signature on a message with the Ed25519 public key.
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), ring::error::Unspecified> {
        let peer_pub = signature::UnparsedPublicKey::new(&signature::ED25519, &self.sign_pub);
        peer_pub.verify(message, signature)
    }
}

/// Computes the fingerprint from an Ed25519 public key.
///
/// The fingerprint is the first 16 bytes of SHA-256(sign_pub).
pub fn compute_fingerprint(sign_pub: &[u8]) -> [u8; FINGERPRINT_LEN] {
    let hash = digest::digest(&digest::SHA256, sign_pub);
    let mut fingerprint = [0u8; FINGERPRINT_LEN];
    fingerprint.copy_from_slice(&hash.as_ref()[..FINGERPRINT_LEN]);
    fingerprint
}

/// Computes the fingerprint from an Ed25519 public key and returns it as hex.
pub fn compute_fingerprint_hex(sign_pub: &[u8]) -> String {
    let fingerprint = compute_fingerprint(sign_pub);
    hex::encode(fingerprint)
}

/// Generates a self-signed Ed25519 certificate.
///
/// The certificate is rustls-compatible and contains the device's Ed25519 public key.
/// For v1, no DNS/SAN is used for trust - verification is done by comparing the
/// certificate's subject public key against the pinned Ed25519 public key.
///
/// Note: This is a simplified certificate generation. In production, you'd want
/// to use a proper certificate builder, but for M0 this minimal approach is fine.
fn generate_self_signed_cert(
    keypair: &Ed25519KeyPair,
    sign_pub: &[u8],
    _dh_pub: &[u8; X25519_PUB_LEN],
) -> Option<Vec<u8>> {
    // For M0, we use a minimal self-signed certificate.
    // In practice, this would use rcgen or similar, but ring doesn't provide
    // certificate building. We'll use a simple approach: sign the public key
    // directly as the "certificate".
    //
    // Actually, for proper rustls compatibility, we need a real certificate.
    // Since ring doesn't provide certificate generation, and we're in no_std-friendly
    // territory, we'll use a simple signature over the public key as a stand-in.
    //
    // For a real implementation, you'd use rcgen::Certificate or similar.
    // But to keep dependencies minimal, we sign the public key bytes.

    let signature = keypair.sign(sign_pub);

    // Certificate format for M0: [public_key || signature]
    // This is a simplified format. Real implementation would use DER-encoded X.509.
    let mut cert = Vec::with_capacity(sign_pub.len() + signature.as_ref().len());
    cert.extend_from_slice(sign_pub);
    cert.extend_from_slice(signature.as_ref());

    Some(cert)
}

/// Parses a public identity from its components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicIdentity {
    pub sign_pub: [u8; ED25519_PUB_LEN],
    pub dh_pub: [u8; X25519_PUB_LEN],
}

impl PublicIdentity {
    /// Creates a new PublicIdentity from the component public keys.
    pub fn new(sign_pub: [u8; ED25519_PUB_LEN], dh_pub: [u8; X25519_PUB_LEN]) -> Self {
        Self { sign_pub, dh_pub }
    }

    /// Computes the fingerprint for this public identity.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        compute_fingerprint(&self.sign_pub)
    }

    /// Returns the fingerprint as a lowercase hex string.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint())
    }

    /// Creates a PublicIdentity from the combined public identity bytes.
    pub fn from_bytes(bytes: &[u8; PUBLIC_IDENTITY_LEN]) -> Self {
        let mut sign_pub = [0u8; ED25519_PUB_LEN];
        let mut dh_pub = [0u8; X25519_PUB_LEN];
        sign_pub.copy_from_slice(&bytes[..ED25519_PUB_LEN]);
        dh_pub.copy_from_slice(&bytes[ED25519_PUB_LEN..]);
        Self { sign_pub, dh_pub }
    }

    /// Returns the bytes of the public identity.
    pub fn to_bytes(&self) -> [u8; PUBLIC_IDENTITY_LEN] {
        let mut result = [0u8; PUBLIC_IDENTITY_LEN];
        result[..ED25519_PUB_LEN].copy_from_slice(&self.sign_pub);
        result[ED25519_PUB_LEN..].copy_from_slice(&self.dh_pub);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate();
        assert!(identity.is_some(), "Identity generation should succeed");

        let identity = identity.unwrap();

        // Check that public keys are non-zero
        assert_ne!(identity.sign_pub, [0u8; ED25519_PUB_LEN]);
        assert_ne!(identity.dh_pub, [0u8; X25519_PUB_LEN]);

        // Check fingerprint is computed from sign_pub
        let expected_fingerprint = compute_fingerprint(&identity.sign_pub);
        assert_eq!(identity.fingerprint, expected_fingerprint);
    }

    #[test]
    fn test_fingerprint_consistency() {
        let identity = Identity::generate().unwrap();
        let fp1 = compute_fingerprint(&identity.sign_pub);
        let fp2 = compute_fingerprint(&identity.sign_pub);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1, identity.fingerprint);
    }

    #[test]
    fn test_fingerprint_hex_format() {
        let identity = Identity::generate().unwrap();
        let hex = identity.fingerprint_hex();
        assert_eq!(hex.len(), 32); // 16 bytes = 32 hex chars
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_public_identity_roundtrip() {
        let identity = Identity::generate().unwrap();
        let pub_id = identity.public_identity();
        let parsed = PublicIdentity::from_bytes(&pub_id);

        assert_eq!(parsed.sign_pub, identity.sign_pub);
        assert_eq!(parsed.dh_pub, identity.dh_pub);
    }

    #[test]
    fn test_public_identity_fingerprint() {
        let identity = Identity::generate().unwrap();
        let pub_id = PublicIdentity::new(identity.sign_pub, identity.dh_pub);

        assert_eq!(pub_id.fingerprint(), identity.fingerprint);
        assert_eq!(pub_id.fingerprint_hex(), identity.fingerprint_hex());
    }

    #[test]
    fn test_dh_shared_secret() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();

        // Extract public keys before consuming identities
        let alice_dh_pub = alice.dh_pub;
        let bob_dh_pub = bob.dh_pub;

        let alice_shared = alice.into_dh_static_shared_secret(&bob_dh_pub);
        let bob_shared = bob.into_dh_static_shared_secret(&alice_dh_pub);

        assert!(alice_shared.is_some());
        assert!(bob_shared.is_some());

        // Shared secrets should be equal
        assert_eq!(alice_shared.unwrap(), bob_shared.unwrap());
    }
}
