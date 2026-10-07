//! Identity management for the Syncon protocol.
//!
//! This module provides generation, serialization, and verification of device identities.
//! Each device has:
//! - An Ed25519 keypair for signing (used for certificates and pinning)
//! - An X25519 static keypair for the inner AEAD key derivation
//!
//! The public identity is the 32-byte Ed25519 public key plus the 32-byte X25519 public key.
//! The fingerprint is the first 16 bytes of SHA-256(sign_pub), as lowercase hex.

use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use ring::{
    digest,
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
/// Both secrets are persistable (see [`Identity::to_secret_bytes`]) and the DH
/// key can be used any number of times.
pub struct Identity {
    sign_keypair: Ed25519KeyPair,
    sign_pkcs8: Vec<u8>,
    dh_secret: StaticSecret,

    /// Self-signed X.509 certificate (DER) over the Ed25519 key.
    pub certificate: Vec<u8>,

    /// Cached Ed25519 public key bytes.
    pub sign_pub: [u8; ED25519_PUB_LEN],

    /// Cached X25519 static public key bytes.
    pub dh_pub: [u8; X25519_PUB_LEN],

    /// Cached fingerprint: first 16 bytes of SHA-256(sign_pub).
    pub fingerprint: [u8; FINGERPRINT_LEN],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &hex::encode(self.fingerprint))
            .finish_non_exhaustive()
    }
}

/// Length of the X25519 static secret in bytes.
const DH_SECRET_LEN: usize = 32;

impl Identity {
    /// Generates a new random identity bundle.
    ///
    /// Returns `None` if the system random number generator fails.
    pub fn generate() -> Option<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).ok()?;
        let mut dh = [0u8; DH_SECRET_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut dh);
        Self::from_parts(pkcs8.as_ref().to_vec(), dh)
    }

    fn from_parts(sign_pkcs8: Vec<u8>, dh: [u8; DH_SECRET_LEN]) -> Option<Self> {
        let sign_keypair = Ed25519KeyPair::from_pkcs8(&sign_pkcs8).ok()?;
        let mut sign_pub = [0u8; ED25519_PUB_LEN];
        sign_pub.copy_from_slice(sign_keypair.public_key().as_ref());

        let dh_secret = StaticSecret::from(dh);
        let dh_pub = X25519Public::from(&dh_secret).to_bytes();
        let fingerprint = compute_fingerprint(&sign_pub);
        let certificate = generate_self_signed_cert(&sign_pkcs8)?;

        Some(Self {
            sign_keypair,
            sign_pkcs8,
            dh_secret,
            certificate,
            sign_pub,
            dh_pub,
            fingerprint,
        })
    }

    /// Serializes the secret material (`u16 pkcs8_len || pkcs8 || dh_secret`).
    /// Callers must store this with mode 0600.
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.sign_pkcs8.len() + DH_SECRET_LEN);
        out.extend_from_slice(&(self.sign_pkcs8.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.sign_pkcs8);
        out.extend_from_slice(&self.dh_secret.to_bytes());
        out
    }

    /// Restores an identity from [`Identity::to_secret_bytes`] output.
    pub fn from_secret_bytes(bytes: &[u8]) -> Option<Self> {
        let len = u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?) as usize;
        if bytes.len() != 2 + len + DH_SECRET_LEN {
            return None;
        }
        let dh: [u8; DH_SECRET_LEN] = bytes[2 + len..].try_into().ok()?;
        Self::from_parts(bytes[2..2 + len].to_vec(), dh)
    }

    /// PKCS#8 DER of the Ed25519 key, for the TLS stack.
    pub fn sign_pkcs8(&self) -> &[u8] {
        &self.sign_pkcs8
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

    /// X25519(local static, peer static). Returns `None` for a low-order peer key.
    pub fn dh_static_shared_secret(
        &self,
        peer_dh_pub: &[u8; X25519_PUB_LEN],
    ) -> Option<[u8; X25519_PUB_LEN]> {
        let shared = self.dh_secret.diffie_hellman(&X25519Public::from(*peer_dh_pub));
        shared.was_contributory().then(|| shared.to_bytes())
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

/// Generates a self-signed X.509 Ed25519 certificate. SAN/DNS carry no trust;
/// peers compare the subject public key against the pin.
fn generate_self_signed_cert(pkcs8: &[u8]) -> Option<Vec<u8>> {
    let der = rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8);
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_ED25519).ok()?;
    let params = rcgen::CertificateParams::new(vec!["syncon".to_string()]).ok()?;
    let cert = params.self_signed(&key).ok()?;
    Some(cert.der().to_vec())
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

        let alice_shared = alice.dh_static_shared_secret(&bob.dh_pub);
        let bob_shared = bob.dh_static_shared_secret(&alice.dh_pub);

        assert!(alice_shared.is_some());
        assert!(bob_shared.is_some());

        // Shared secrets should be equal
        assert_eq!(alice_shared.unwrap(), bob_shared.unwrap());
    }

    #[test]
    fn test_secret_roundtrip_and_cert() {
        let a = Identity::generate().unwrap();
        let b = Identity::from_secret_bytes(&a.to_secret_bytes()).unwrap();
        assert_eq!(a.sign_pub, b.sign_pub);
        assert_eq!(a.dh_pub, b.dh_pub);
        assert!(Identity::from_secret_bytes(&[0u8; 5]).is_none());
        // Ed25519 SPKI sits inside the certificate.
        assert!(a.certificate.windows(32).any(|w| w == a.sign_pub));
    }
}
