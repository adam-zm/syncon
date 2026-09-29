//! Short Authentication String (SAS) computation for the Syncon protocol.
//!
//! The SAS is an 8-digit decimal code displayed on both devices during pairing.
//! Both sides compute the same code from shared information, allowing users to
//! verify they are pairing with the intended device.
//!
//! See [protocol.md](https://github.com/syncon/syncon/blob/main/docs/protocol.md) for details.

use crate::identity::{ED25519_PUB_LEN, X25519_PUB_LEN};
use ring::digest;

/// The magic string prefix for SAS computation.
const SAS_PREFIX: &[u8] = b"link-sas-v1";

/// The length of the TLS exporter output in bytes.
pub const EXPORTER_LEN: usize = 32;

/// The SAS code as an 8-digit number (0 to 99,999,999).
///
/// This is the raw numeric value before formatting for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SasCode(u32);

impl SasCode {
    /// Creates a new SAS code from the raw numeric value.
    ///
    /// Panics if the value is >= 100_000_000.
    pub fn new(value: u32) -> Self {
        assert!(value < 100_000_000, "SAS code must be < 100_000_000");
        Self(value)
    }

    /// Returns the raw numeric value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Returns the SAS code formatted for display: "XXXX XXXX" (8 digits, space-separated groups).
    pub fn display(&self) -> String {
        format!("{:08}", self.0)
            .chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Returns the SAS code as an 8-digit string without formatting.
    pub fn as_str(&self) -> String {
        format!("{:08}", self.0)
    }
}

/// Computes the SAS code from pairing information.
///
/// # Arguments
///
/// * `local_sign_pub` - Local device's Ed25519 public key (32 bytes)
/// * `peer_sign_pub` - Peer device's Ed25519 public key (32 bytes)
/// * `local_dh_pub` - Local device's X25519 public key (32 bytes)
/// * `peer_dh_pub` - Peer device's X25519 public key (32 bytes)
/// * `tls_exporter` - TLS exporter output for "link-sas-v1" (32 bytes)
///
/// # Returns
///
/// A `SasCode` containing the 8-digit SAS value, or `None` if inputs are invalid.
///
/// # Algorithm
///
/// ```text
/// digest = SHA-256(
///   "link-sas-v1" ||
///   lower_sign_pub || higher_sign_pub ||
///   lower_dh_pub   || higher_dh_pub   ||
///   tls_exporter("link-sas-v1", 32)
/// )
/// number = u32_be(digest[0..4]) mod 100_000_000
/// ```
///
/// "lower" and "higher" are determined by comparing the 32-byte keys as unsigned
/// big-endian integers. This ensures both sides compute the same order.
pub fn compute_sas(
    local_sign_pub: &[u8; ED25519_PUB_LEN],
    peer_sign_pub: &[u8; ED25519_PUB_LEN],
    local_dh_pub: &[u8; X25519_PUB_LEN],
    peer_dh_pub: &[u8; X25519_PUB_LEN],
    tls_exporter: &[u8; EXPORTER_LEN],
) -> SasCode {
    // Determine ordering: compare sign_pub as big-endian unsigned integers
    let (lower_sign, higher_sign) = order_keys(local_sign_pub, peer_sign_pub);
    let (lower_dh, higher_dh) = order_keys(local_dh_pub, peer_dh_pub);

    // Build the input for SHA-256
    let mut input = Vec::with_capacity(
        SAS_PREFIX.len() + ED25519_PUB_LEN * 2 + X25519_PUB_LEN * 2 + EXPORTER_LEN,
    );

    input.extend_from_slice(SAS_PREFIX);
    input.extend_from_slice(lower_sign);
    input.extend_from_slice(higher_sign);
    input.extend_from_slice(lower_dh);
    input.extend_from_slice(higher_dh);
    input.extend_from_slice(tls_exporter);

    // Compute SHA-256
    let digest = digest::digest(&digest::SHA256, &input);
    let digest_bytes = digest.as_ref();

    // Extract first 4 bytes as big-endian u32
    let first_four = u32::from_be_bytes([
        digest_bytes[0],
        digest_bytes[1],
        digest_bytes[2],
        digest_bytes[3],
    ]);

    // Compute mod 100_000_000
    let number = first_four % 100_000_000;

    SasCode::new(number)
}

/// Orders two keys by comparing them as unsigned big-endian integers.
///
/// Returns (lower, higher) where lower <= higher.
fn order_keys<'a>(
    a: &'a [u8; ED25519_PUB_LEN],
    b: &'a [u8; ED25519_PUB_LEN],
) -> (&'a [u8; ED25519_PUB_LEN], &'a [u8; ED25519_PUB_LEN]) {
    // Compare as big-endian: most significant byte first
    if a.as_slice() <= b.as_slice() {
        (a, b)
    } else {
        (b, a)
    }
}

/// Orders two X25519 keys by comparing them as unsigned big-endian integers.
fn order_keys_x25519<'a>(
    a: &'a [u8; X25519_PUB_LEN],
    b: &'a [u8; X25519_PUB_LEN],
) -> (&'a [u8; X25519_PUB_LEN], &'a [u8; X25519_PUB_LEN]) {
    if a.as_slice() <= b.as_slice() {
        (a, b)
    } else {
        (b, a)
    }
}

/// Computes the SAS code with explicit key ordering.
///
/// This is useful when you've already determined the ordering.
pub fn compute_sas_with_order(
    lower_sign_pub: &[u8; ED25519_PUB_LEN],
    higher_sign_pub: &[u8; ED25519_PUB_LEN],
    lower_dh_pub: &[u8; X25519_PUB_LEN],
    higher_dh_pub: &[u8; X25519_PUB_LEN],
    tls_exporter: &[u8; EXPORTER_LEN],
) -> SasCode {
    let mut input = Vec::with_capacity(
        SAS_PREFIX.len() + ED25519_PUB_LEN * 2 + X25519_PUB_LEN * 2 + EXPORTER_LEN,
    );

    input.extend_from_slice(SAS_PREFIX);
    input.extend_from_slice(lower_sign_pub);
    input.extend_from_slice(higher_sign_pub);
    input.extend_from_slice(lower_dh_pub);
    input.extend_from_slice(higher_dh_pub);
    input.extend_from_slice(tls_exporter);

    let digest = digest::digest(&digest::SHA256, &input);
    let digest_bytes = digest.as_ref();

    let first_four = u32::from_be_bytes([
        digest_bytes[0],
        digest_bytes[1],
        digest_bytes[2],
        digest_bytes[3],
    ]);

    let number = first_four % 100_000_000;

    SasCode::new(number)
}

/// Validates that a user-entered SAS code matches the computed value.
///
/// This compares the display string (with or without spaces) against the expected code.
pub fn validate_sas_display(user_input: &str, expected: SasCode) -> bool {
    // Remove all whitespace from user input
    let cleaned: String = user_input.chars().filter(|c| !c.is_whitespace()).collect();

    // Check length
    if cleaned.len() != 8 {
        return false;
    }

    // Check all digits
    if !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Parse and compare
    cleaned.parse::<u32>().map_or(false, |n| n == expected.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sas_display_format() {
        let code = SasCode::new(12345678);
        assert_eq!(code.display(), "1234 5678");

        let code = SasCode::new(1);
        assert_eq!(code.display(), "0000 0001");

        let code = SasCode::new(99999999);
        assert_eq!(code.display(), "9999 9999");
    }

    #[test]
    fn test_sas_as_str() {
        let code = SasCode::new(12345678);
        assert_eq!(code.as_str(), "12345678");

        let code = SasCode::new(0);
        assert_eq!(code.as_str(), "00000000");
    }

    #[test]
    fn test_sas_computation_ordering() {
        // Test that ordering is consistent
        let sign_pub_a = [0u8; ED25519_PUB_LEN];
        let sign_pub_b = [1u8; ED25519_PUB_LEN];
        let dh_pub_a = [0u8; X25519_PUB_LEN];
        let dh_pub_b = [1u8; X25519_PUB_LEN];
        let exporter = [0u8; EXPORTER_LEN];

        // Compute with A as local
        let sas_ab = compute_sas(&sign_pub_a, &sign_pub_b, &dh_pub_a, &dh_pub_b, &exporter);

        // Compute with B as local (should give same result)
        let sas_ba = compute_sas(&sign_pub_b, &sign_pub_a, &dh_pub_b, &dh_pub_a, &exporter);

        assert_eq!(
            sas_ab, sas_ba,
            "SAS should be the same regardless of which side computes it"
        );
    }

    #[test]
    fn test_sas_different_exporter() {
        let sign_pub_a = [0u8; ED25519_PUB_LEN];
        let sign_pub_b = [1u8; ED25519_PUB_LEN];
        let dh_pub_a = [0u8; X25519_PUB_LEN];
        let dh_pub_b = [1u8; X25519_PUB_LEN];

        let exporter1 = [0u8; EXPORTER_LEN];
        let exporter2 = [1u8; EXPORTER_LEN];

        let sas1 = compute_sas(&sign_pub_a, &sign_pub_b, &dh_pub_a, &dh_pub_b, &exporter1);
        let sas2 = compute_sas(&sign_pub_a, &sign_pub_b, &dh_pub_a, &dh_pub_b, &exporter2);

        // Different exporters should produce different SAS codes
        assert_ne!(
            sas1, sas2,
            "Different exporters should produce different SAS codes"
        );
    }

    #[test]
    fn test_validate_sas_display() {
        let code = SasCode::new(12345678);

        assert!(validate_sas_display("12345678", code));
        assert!(validate_sas_display("1234 5678", code));
        assert!(!validate_sas_display("1234-5678", code)); // Hyphens not allowed
        assert!(validate_sas_display(" 12345678 ", code));

        assert!(!validate_sas_display("1234567", code)); // Too short
        assert!(!validate_sas_display("123456789", code)); // Too long
        assert!(!validate_sas_display("abcd1234", code)); // Non-digit
        assert!(!validate_sas_display("12345670", code)); // Wrong value
    }

    #[test]
    #[should_panic]
    fn test_sas_code_too_large() {
        // This should panic
        SasCode::new(100_000_000);
    }

    #[test]
    fn test_sas_with_realistic_keys() {
        // Use some realistic-looking keys (not all zeros)
        let mut sign_pub_a = [0u8; ED25519_PUB_LEN];
        let mut sign_pub_b = [0u8; ED25519_PUB_LEN];
        let mut dh_pub_a = [0u8; X25519_PUB_LEN];
        let mut dh_pub_b = [0u8; X25519_PUB_LEN];
        let exporter = [0u8; EXPORTER_LEN];

        // Fill with some data
        for i in 0..ED25519_PUB_LEN {
            sign_pub_a[i] = (i * 7) as u8;
            sign_pub_b[i] = (i * 13) as u8;
        }
        for i in 0..X25519_PUB_LEN {
            dh_pub_a[i] = (i * 3) as u8;
            dh_pub_b[i] = (i * 5) as u8;
        }

        let sas_ab = compute_sas(&sign_pub_a, &sign_pub_b, &dh_pub_a, &dh_pub_b, &exporter);
        let sas_ba = compute_sas(&sign_pub_b, &sign_pub_a, &dh_pub_b, &dh_pub_a, &exporter);

        assert_eq!(sas_ab, sas_ba);

        // Also verify with explicit ordering
        let (lower_s, higher_s) = order_keys(&sign_pub_a, &sign_pub_b);
        let (lower_d, higher_d) = order_keys_x25519(&dh_pub_a, &dh_pub_b);
        let sas_ordered = compute_sas_with_order(lower_s, higher_s, lower_d, higher_d, &exporter);

        assert_eq!(sas_ab, sas_ordered);
    }
}
