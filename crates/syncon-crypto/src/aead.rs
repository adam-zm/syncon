//! Inner AEAD encryption for the Syncon protocol.
//!
//! After TLS establishes a secure channel, Link adds an inner AEAD layer so that
//! a TLS-terminating relay (if ever introduced) cannot read clipboard, notifications,
//! or other sensitive data.
//!
//! The inner key is derived from:
//! - Static-static X25519 (between static DH keys)
//! - Ephemeral-ephemeral X25519 (from Hello message)
//! - TLS exporter for "link-inner-v1"
//!
//! The nonce construction ensures each side uses different nonces:
//! `nonce = class || seq || direction || 0`
//! where direction is 0 for the side with the lower sign_pub, 1 for the higher.

use crate::identity::{ED25519_PUB_LEN, X25519_PUB_LEN};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305},
    digest,
};

/// The magic string for the inner AEAD salt.
const AEAD_SALT: &[u8] = b"link-aead-v1";

/// The length of the inner AEAD key in bytes.
const AEAD_KEY_LEN: usize = 32;

/// The length of the nonce in bytes (12 bytes: class + seq + direction + padding).
pub const NONCE_LEN: usize = 12;

/// The length of the TLS exporter output in bytes.
const EXPORTER_LEN: usize = 32;

/// The HKDF info parameter is the transcript: SHA-256 of ordered Hello messages.
const TRANSCRIPT_LEN: usize = 32;

/// The shared secret length from X25519.
pub const X25519_SHARED_LEN: usize = 32;

/// IKM length for inner key derivation (static_shared || eph_shared || exporter).
const IKM_LEN: usize = X25519_SHARED_LEN * 2 + EXPORTER_LEN;

/// Inner AEAD key for encrypting/decrypting message bodies.
///
/// This key is derived from the static-static DH, ephemeral-ephemeral DH, and TLS exporter.
#[derive(Debug, Clone)]
pub struct InnerAeadKey {
    /// The raw key bytes (32 bytes for ChaCha20-Poly1305).
    key_bytes: [u8; AEAD_KEY_LEN],

    /// The direction bit for nonce construction (0 or 1).
    /// This is 0 if our sign_pub is lower, 1 if higher.
    our_direction: u8,
}

impl InnerAeadKey {
    /// Derives the inner AEAD key from the handshake materials.
    ///
    /// # Arguments
    ///
    /// * `static_shared` - X25519(local_dh_static_priv, peer_dh_static_pub) (32 bytes)
    /// * `eph_shared` - X25519(local_eph_priv, peer_eph_pub) from Hello (32 bytes)
    /// * `tls_exporter` - TLS-Exporter("link-inner-v1", 32) (32 bytes)
    /// * `local_hello_bytes` - Serialized local Hello message
    /// * `peer_hello_bytes` - Serialized peer Hello message
    /// * `local_sign_pub` - Local device's Ed25519 public key (32 bytes)
    /// * `peer_sign_pub` - Peer device's Ed25519 public key (32 bytes)
    ///
    /// # Algorithm
    ///
    /// ```text
    /// ikm  = static_shared || eph_shared || exporter
    /// transcript = SHA-256(local_hello_bytes || peer_hello_bytes)  [ordered by sign_pub]
    /// key  = HKDF-SHA256(ikm, salt = "link-aead-v1", info = transcript, len = 32)
    /// ```
    ///
    /// The direction for nonce construction is determined by comparing sign_pub values:
    /// - 0 if local_sign_pub < peer_sign_pub (lower)
    /// - 1 if local_sign_pub > peer_sign_pub (higher)
    pub fn derive(
        static_shared: &[u8; X25519_SHARED_LEN],
        eph_shared: &[u8; X25519_SHARED_LEN],
        tls_exporter: &[u8; EXPORTER_LEN],
        local_hello_bytes: &[u8],
        peer_hello_bytes: &[u8],
        local_sign_pub: &[u8; ED25519_PUB_LEN],
        peer_sign_pub: &[u8; ED25519_PUB_LEN],
    ) -> Self {
        // Build IKM: static_shared || eph_shared || exporter
        let mut ikm = [0u8; IKM_LEN];
        ikm[..X25519_SHARED_LEN].copy_from_slice(static_shared);
        ikm[X25519_SHARED_LEN..X25519_SHARED_LEN * 2].copy_from_slice(eph_shared);
        ikm[X25519_SHARED_LEN * 2..].copy_from_slice(tls_exporter);

        // Build transcript: SHA-256 of ordered Hello messages
        let transcript = compute_transcript(
            local_hello_bytes,
            peer_hello_bytes,
            local_sign_pub,
            peer_sign_pub,
        );

        // Derive key using HKDF-SHA256
        let key_bytes = hkdf_derive(&ikm, AEAD_SALT, &transcript);

        // Determine our direction
        let our_direction = if local_sign_pub.as_slice() <= peer_sign_pub.as_slice() {
            0
        } else {
            1
        };

        Self {
            key_bytes,
            our_direction,
        }
    }

    /// Returns the raw key bytes.
    pub fn key_bytes(&self) -> [u8; AEAD_KEY_LEN] {
        self.key_bytes
    }

    /// Returns our direction bit (0 or 1).
    pub fn our_direction(&self) -> u8 {
        self.our_direction
    }

    /// Constructs a nonce for encryption/decryption.
    ///
    /// The nonce is: `[class (1 byte) || seq (8 bytes LE) || direction (1 byte) || 0 (2 bytes)]`
    ///
    /// This ensures both sides use different nonces even with the same class and seq,
    /// preventing nonce reuse.
    pub fn build_nonce(&self, class: u8, seq: u64) -> [u8; NONCE_LEN] {
        self.nonce_for_direction(self.our_direction, class, seq)
    }

    fn nonce_for_direction(&self, direction: u8, class: u8, seq: u64) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];

        // class (1 byte)
        nonce[0] = class;

        // seq (8 bytes, little-endian)
        nonce[1..9].copy_from_slice(&seq.to_le_bytes());

        // direction (1 byte)
        nonce[9] = direction;

        // padding (2 bytes, must be 0)
        nonce[10..12].copy_from_slice(&[0u8; 2]);

        nonce
    }

    /// Encrypts a plaintext body using ChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `class` - The message class (for nonce construction)
    /// * `seq` - The sequence number (for nonce construction)
    /// * `plaintext` - The plaintext body to encrypt
    ///
    /// # Returns
    ///
    /// The ciphertext with the authentication tag appended.
    /// The length is plaintext.len() + CHACHA20_POLY1305.tag_len().
    pub fn encrypt(&self, class: u8, seq: u64, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.build_nonce(class, seq);

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.key_bytes).unwrap();
        let less_safe_key = LessSafeKey::new(unbound_key);

        // Encrypt with empty AAD (no associated data for envelope bodies)
        // seal_in_place_append_tag mutates the input and appends the tag
        let mut ciphertext = plaintext.to_vec();
        less_safe_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut ciphertext,
            )
            .unwrap();
        ciphertext
    }

    /// Decrypts a ciphertext body using ChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `class` - The message class (for nonce construction)
    /// * `seq` - The sequence number (for nonce construction)
    /// * `ciphertext` - The ciphertext with authentication tag
    ///
    /// # Returns
    ///
    /// The decrypted plaintext, or `None` if decryption fails (wrong key, nonce reuse, etc.).
    pub fn decrypt(&self, class: u8, seq: u64, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // Incoming messages were sealed with the peer's direction bit.
        let nonce = self.nonce_for_direction(self.our_direction ^ 1, class, seq);

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.key_bytes).unwrap();
        let less_safe_key = LessSafeKey::new(unbound_key);

        // The ciphertext includes the tag at the end
        // open_in_place handles the tag automatically
        let mut ciphertext_clone = ciphertext.to_vec();

        match less_safe_key.open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut ciphertext_clone,
        ) {
            Ok(plaintext) => Some(plaintext.to_vec()),
            Err(_) => None,
        }
    }
}

/// Computes the transcript: SHA-256 of ordered Hello messages.
///
/// The Hello messages are ordered by comparing sign_pub as unsigned big-endian:
/// lower sign_pub's Hello comes first.
fn compute_transcript(
    local_hello_bytes: &[u8],
    peer_hello_bytes: &[u8],
    local_sign_pub: &[u8; ED25519_PUB_LEN],
    peer_sign_pub: &[u8; ED25519_PUB_LEN],
) -> [u8; TRANSCRIPT_LEN] {
    // Determine ordering
    if local_sign_pub.as_slice() <= peer_sign_pub.as_slice() {
        // local is lower: local || peer
        let mut input = Vec::with_capacity(local_hello_bytes.len() + peer_hello_bytes.len());
        input.extend_from_slice(local_hello_bytes);
        input.extend_from_slice(peer_hello_bytes);
        let digest = digest::digest(&digest::SHA256, &input);
        let mut transcript = [0u8; TRANSCRIPT_LEN];
        transcript.copy_from_slice(&digest.as_ref()[..TRANSCRIPT_LEN]);
        transcript
    } else {
        // peer is lower: peer || local
        let mut input = Vec::with_capacity(peer_hello_bytes.len() + local_hello_bytes.len());
        input.extend_from_slice(peer_hello_bytes);
        input.extend_from_slice(local_hello_bytes);
        let digest = digest::digest(&digest::SHA256, &input);
        let mut transcript = [0u8; TRANSCRIPT_LEN];
        transcript.copy_from_slice(&digest.as_ref()[..TRANSCRIPT_LEN]);
        transcript
    }
}

/// Derives a key using HKDF-SHA256.
///
/// # Arguments
///
/// * `ikm` - Input keying material
/// * `salt` - Salt (can be empty, but we use "link-aead-v1")
/// * `info` - Context-specific info (transcript)
///
/// # Returns
///
/// A key of length `AEAD_KEY_LEN` (32 bytes).
fn hkdf_derive(ikm: &[u8], salt_bytes: &[u8], info: &[u8]) -> [u8; AEAD_KEY_LEN] {
    use ring::hkdf::{Salt, HKDF_SHA256};

    // Create salt from the salt bytes
    let salt = Salt::new(HKDF_SHA256, salt_bytes);

    // Extract PRK from IKM
    let prk = salt.extract(ikm);

    // Expand to get the output key material
    // HKDF_SHA256 implements KeyType and represents a 32-byte output
    let mut key = [0u8; AEAD_KEY_LEN];
    prk.expand(&[info], HKDF_SHA256)
        .unwrap()
        .fill(&mut key)
        .unwrap();
    key
}

/// X25519 helper for the Hello ephemeral. Returns `None` for a low-order peer key.
pub fn x25519_shared(
    private_key: x25519_dalek::EphemeralSecret,
    peer_public: &[u8; X25519_PUB_LEN],
) -> Option<[u8; X25519_SHARED_LEN]> {
    let shared = private_key.diffie_hellman(&x25519_dalek::PublicKey::from(*peer_public));
    shared.was_contributory().then(|| shared.to_bytes())
}

/// Validates that a nonce is unique for a given key.
///
/// This is a safety check. In practice, the sequence numbers should ensure uniqueness,
/// but this can help catch programming errors.
pub fn validate_nonce_uniqueness(nonce1: &[u8; NONCE_LEN], nonce2: &[u8; NONCE_LEN]) -> bool {
    // Nonces must differ in at least one byte
    // Most commonly they'll differ in class, seq, or direction
    nonce1 != nonce2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_construction() {
        let key = InnerAeadKey {
            key_bytes: [0u8; AEAD_KEY_LEN],
            our_direction: 0,
        };

        let nonce = key.build_nonce(2, 42); // class=2 (Clipboard), seq=42

        // Check structure: class || seq_le || direction || padding
        assert_eq!(nonce[0], 2);
        assert_eq!(&nonce[1..9], &42u64.to_le_bytes());
        assert_eq!(nonce[9], 0);
        assert_eq!(&nonce[10..12], &[0u8; 2]);
    }

    #[test]
    fn test_nonce_direction() {
        let key_lower = InnerAeadKey {
            key_bytes: [0u8; AEAD_KEY_LEN],
            our_direction: 0,
        };

        let key_higher = InnerAeadKey {
            key_bytes: [0u8; AEAD_KEY_LEN],
            our_direction: 1,
        };

        let nonce_lower = key_lower.build_nonce(1, 1);
        let nonce_higher = key_higher.build_nonce(1, 1);

        // Same class and seq, but different direction
        assert_eq!(nonce_lower[0..9], nonce_higher[0..9]); // class and seq match
        assert_ne!(nonce_lower[9], nonce_higher[9]); // direction differs

        // Nonces are different
        assert_ne!(nonce_lower, nonce_higher);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create a key with direction 0
        let key = InnerAeadKey {
            key_bytes: [42u8; AEAD_KEY_LEN], // Some arbitrary key
            our_direction: 0,
        };

        let plaintext = b"Hello, world!";
        let class = 2; // Clipboard
        let seq = 1;

        let peer = InnerAeadKey { key_bytes: key.key_bytes, our_direction: 1 };

        let ciphertext = key.encrypt(class, seq, plaintext);
        assert_eq!(peer.decrypt(class, seq, &ciphertext).unwrap(), plaintext);
        // Same side cannot open its own message: directions differ by design.
        assert!(key.decrypt(class, seq, &ciphertext).is_none());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = InnerAeadKey {
            key_bytes: [1u8; AEAD_KEY_LEN],
            our_direction: 0,
        };

        let key2 = InnerAeadKey {
            key_bytes: [2u8; AEAD_KEY_LEN],
            our_direction: 0,
        };

        let plaintext = b"Secret message";
        let ciphertext = key1.encrypt(1, 1, plaintext);

        // Decryption with wrong key should fail
        assert!(key2.decrypt(1, 1, &ciphertext).is_none());
    }

    #[test]
    fn test_decrypt_wrong_nonce() {
        let key = InnerAeadKey {
            key_bytes: [1u8; AEAD_KEY_LEN],
            our_direction: 0,
        };

        let plaintext = b"Secret message";
        let ciphertext = key.encrypt(1, 1, plaintext);

        // Decryption with wrong seq should fail (different nonce)
        assert!(key.decrypt(1, 2, &ciphertext).is_none());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = InnerAeadKey {
            key_bytes: [0u8; AEAD_KEY_LEN],
            our_direction: 0,
        };

        let nonce1 = key.build_nonce(1, 1);
        let nonce2 = key.build_nonce(1, 2);
        let nonce3 = key.build_nonce(2, 1);

        assert!(validate_nonce_uniqueness(&nonce1, &nonce2));
        assert!(validate_nonce_uniqueness(&nonce1, &nonce3));
        assert!(!validate_nonce_uniqueness(&nonce1, &nonce1));
    }

    #[test]
    fn test_transcript_ordering() {
        let hello_a = b"hello_a";
        let hello_b = b"hello_b";

        let sign_pub_a = [0u8; ED25519_PUB_LEN];
        let sign_pub_b = [1u8; ED25519_PUB_LEN];

        // sign_pub_a < sign_pub_b, so transcript should be SHA-256(hello_a || hello_b)
        let transcript_ab = compute_transcript(hello_a, hello_b, &sign_pub_a, &sign_pub_b);

        // Reverse: sign_pub_b > sign_pub_a, so transcript should be SHA-256(hello_b || hello_a)
        // But wait, if we pass hello_b as local and hello_a as peer, with sign_pub_b > sign_pub_a,
        // then peer is lower, so it should be SHA-256(hello_a || hello_b) - same result!
        let transcript_ba = compute_transcript(hello_b, hello_a, &sign_pub_b, &sign_pub_a);

        assert_eq!(
            transcript_ab, transcript_ba,
            "Transcript should be the same regardless of which side computes it"
        );
    }

    #[test]
    fn test_hkdf_derive_deterministic() {
        let ikm = [1u8; 64];
        let salt = b"link-aead-v1";
        let info = [2u8; 32];

        let key1 = hkdf_derive(&ikm, salt, &info);
        let key2 = hkdf_derive(&ikm, salt, &info);

        assert_eq!(key1, key2, "HKDF should produce deterministic output");
    }

    #[test]
    fn test_hkdf_derive_different_inputs() {
        let ikm1 = [1u8; 64];
        let ikm2 = [2u8; 64];
        let salt = b"link-aead-v1";
        let info = [0u8; 32];

        let key1 = hkdf_derive(&ikm1, salt, &info);
        let key2 = hkdf_derive(&ikm2, salt, &info);

        assert_ne!(key1, key2, "Different IKM should produce different keys");
    }
}
