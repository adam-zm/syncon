//! File-backed key store: our identity and the pins of paired peers.
//!
//! Layout under the store directory (mode 0700):
//! ```text
//! identity.key          secret material, mode 0600
//! peers/<fp>.pin        sign_pub || dh_pub || u8 name_len || name
//! ```
//! A pin is written only by [`Keystore::save_pin`], which the caller invokes after the
//! human confirmed the SAS. Nothing is written for a provisional peer, so a cancelled or
//! mismatched pairing leaves no state behind. Writes are atomic (temp file + rename).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::identity::{compute_fingerprint_hex, Identity, PublicIdentity, ED25519_PUB_LEN, PUBLIC_IDENTITY_LEN};

const IDENTITY_FILE: &str = "identity.key";
const PEERS_DIR: &str = "peers";
/// Display names are capped at 32 bytes by the protocol.
pub const MAX_NAME_LEN: usize = 32;

/// A paired peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub identity: PublicIdentity,
    pub name: String,
}

impl Pin {
    pub fn fingerprint_hex(&self) -> String {
        self.identity.fingerprint_hex()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let name = self.name.as_bytes();
        let mut out = self.identity.to_bytes().to_vec();
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        let id: &[u8; PUBLIC_IDENTITY_LEN] = b.get(..PUBLIC_IDENTITY_LEN)?.try_into().ok()?;
        let n = *b.get(PUBLIC_IDENTITY_LEN)? as usize;
        if n > MAX_NAME_LEN || b.len() != PUBLIC_IDENTITY_LEN + 1 + n {
            return None;
        }
        let name = String::from_utf8(b[PUBLIC_IDENTITY_LEN + 1..].to_vec()).ok()?;
        Some(Self { identity: PublicIdentity::from_bytes(id), name })
    }
}

/// Failure to read or write the store.
#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    /// A file exists but cannot be parsed. It is never overwritten automatically.
    Corrupt(PathBuf),
    /// The pin is invalid (e.g. name too long).
    Rejected(&'static str),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "key store io: {e}"),
            Self::Corrupt(p) => write!(f, "corrupt key store file: {}", p.display()),
            Self::Rejected(why) => write!(f, "rejected: {why}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Handle to a store directory.
#[derive(Debug, Clone)]
pub struct Keystore {
    dir: PathBuf,
}

impl Keystore {
    /// Opens (creating, mode 0700) the store directory.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        for d in [dir.clone(), dir.join(PEERS_DIR)] {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(d)?;
        }
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Loads the identity, or generates and persists one on first run.
    /// A file that exists but cannot be parsed is an error, never silently replaced:
    /// a new sign key would be a different device.
    pub fn load_or_create_identity(&self) -> Result<Identity, StoreError> {
        let path = self.dir.join(IDENTITY_FILE);
        match fs::read(&path) {
            Ok(bytes) => Identity::from_secret_bytes(&bytes).ok_or(StoreError::Corrupt(path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let id = Identity::generate()
                    .ok_or_else(|| io::Error::other("random number generator failed"))?;
                write_atomic(&path, &id.to_secret_bytes())?;
                Ok(id)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn pin_path(&self, fingerprint_hex: &str) -> PathBuf {
        self.dir.join(PEERS_DIR).join(format!("{fingerprint_hex}.pin"))
    }

    /// Persists a pin after SAS confirmation. The file name is the key's fingerprint, so a
    /// different sign key can never overwrite an existing pin. Re-saving updates the name.
    pub fn save_pin(&self, pin: &Pin) -> Result<(), StoreError> {
        if pin.name.len() > MAX_NAME_LEN {
            return Err(StoreError::Rejected("display name longer than 32 bytes"));
        }
        write_atomic(&self.pin_path(&pin.fingerprint_hex()), &pin.to_bytes())?;
        Ok(())
    }

    pub fn load_pin(&self, fingerprint_hex: &str) -> Result<Option<Pin>, StoreError> {
        if fingerprint_hex.len() != 32 || !fingerprint_hex.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Ok(None);
        }
        let path = self.pin_path(&fingerprint_hex.to_ascii_lowercase());
        match fs::read(&path) {
            Ok(b) => Pin::from_bytes(&b).map(Some).ok_or(StoreError::Corrupt(path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Looks a pin up by Ed25519 key.
    pub fn find_pin(&self, sign_pub: &[u8; ED25519_PUB_LEN]) -> Result<Option<Pin>, StoreError> {
        self.load_pin(&compute_fingerprint_hex(sign_pub))
    }

    pub fn list_pins(&self) -> Result<Vec<Pin>, StoreError> {
        let mut pins = Vec::new();
        for entry in fs::read_dir(self.dir.join(PEERS_DIR))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "pin") {
                let bytes = fs::read(&path)?;
                pins.push(Pin::from_bytes(&bytes).ok_or(StoreError::Corrupt(path))?);
            }
        }
        pins.sort_by_key(|p| p.fingerprint_hex());
        Ok(pins)
    }

    /// Deletes a pin (unpair). Returns whether one existed.
    pub fn remove_pin(&self, fingerprint_hex: &str) -> Result<bool, StoreError> {
        if self.load_pin(fingerprint_hex)?.is_none() {
            return Ok(false);
        }
        fs::remove_file(self.pin_path(&fingerprint_hex.to_ascii_lowercase()))?;
        Ok(true)
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f: File = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp() -> PathBuf {
        let mut r = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut r);
        std::env::temp_dir().join(format!("syncon-store-test-{}", hex::encode(r)))
    }

    fn pin_for(name: &str) -> Pin {
        let id = Identity::generate().unwrap();
        Pin { identity: PublicIdentity::new(id.sign_pub, id.dh_pub), name: name.into() }
    }

    #[test]
    fn identity_persists_with_private_modes() {
        let dir = tmp();
        let ks = Keystore::open(&dir).unwrap();
        let a = ks.load_or_create_identity().unwrap();
        let b = Keystore::open(&dir).unwrap().load_or_create_identity().unwrap();
        assert_eq!(a.sign_pub, b.sign_pub);
        assert_eq!(a.dh_pub, b.dh_pub);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join(IDENTITY_FILE)), 0o600);
        assert_eq!(mode(&dir), 0o700);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupt_identity_is_not_replaced() {
        let dir = tmp();
        let ks = Keystore::open(&dir).unwrap();
        fs::write(dir.join(IDENTITY_FILE), b"junk").unwrap();
        assert!(matches!(ks.load_or_create_identity(), Err(StoreError::Corrupt(_))));
        assert_eq!(fs::read(dir.join(IDENTITY_FILE)).unwrap(), b"junk");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pin_roundtrip_list_remove() {
        let dir = tmp();
        let ks = Keystore::open(&dir).unwrap();
        let p = pin_for("Pixel");
        assert!(ks.find_pin(&p.identity.sign_pub).unwrap().is_none());
        ks.save_pin(&p).unwrap();
        ks.save_pin(&p).unwrap();
        assert_eq!(ks.find_pin(&p.identity.sign_pub).unwrap(), Some(p.clone()));
        assert_eq!(ks.list_pins().unwrap(), vec![p.clone()]);
        assert!(ks.remove_pin(&p.fingerprint_hex()).unwrap());
        assert!(!ks.remove_pin(&p.fingerprint_hex()).unwrap());
        assert!(ks.list_pins().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn name_is_capped_and_bad_fingerprint_ignored() {
        let dir = tmp();
        let ks = Keystore::open(&dir).unwrap();
        assert!(ks.save_pin(&pin_for(&"x".repeat(33))).is_err());
        assert!(ks.load_pin("zz").unwrap().is_none());
        assert!(ks.list_pins().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn path_traversal_in_fingerprint_is_refused() {
        let dir = tmp();
        let ks = Keystore::open(&dir).unwrap();
        assert!(ks.load_pin("../../identity.key").unwrap().is_none());
        assert!(!ks.remove_pin("../../identity.key").unwrap());
        fs::remove_dir_all(dir).unwrap();
    }
}
