//! File-backed key store: our identity and the pins of paired peers.
//!
//! Layout under the store directory (mode 0700), matching platforms.md:
//! ```text
//! identity              secret material, mode 0600
//! peers/<fingerprint>   sign_pub || dh_pub || name || last address, clipboard gen, grants
//! ```
//! A pin is written only by [`Keystore::save_pin`], which the caller invokes after the
//! human confirmed the SAS. Nothing is written for a provisional peer, so a cancelled or
//! mismatched pairing leaves no state behind. Writes are atomic (temp file + rename).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::identity::{
    compute_fingerprint_hex, Identity, PublicIdentity, ED25519_PUB_LEN, PUBLIC_IDENTITY_LEN,
};

const IDENTITY_FILE: &str = "identity";
const PEERS_DIR: &str = "peers";
/// Display names are capped at 32 bytes by the protocol.
pub const MAX_NAME_LEN: usize = 32;

/// A paired peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub identity: PublicIdentity,
    pub name: String,
    pub last_rt: Option<SocketAddr>,
    pub last_bk: Option<SocketAddr>,
    pub clipboard_generation: u64,
    pub features: u32,
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
        let mut flags = 0u8;
        if self.last_rt.is_some() {
            flags |= 1;
        }
        if self.last_bk.is_some() {
            flags |= 2;
        }
        out.push(flags);
        if let Some(a) = self.last_rt {
            write_addr(&mut out, a);
        }
        if let Some(a) = self.last_bk {
            write_addr(&mut out, a);
        }
        out.extend_from_slice(&self.clipboard_generation.to_le_bytes());
        out.extend_from_slice(&self.features.to_le_bytes());
        out
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        let id: &[u8; PUBLIC_IDENTITY_LEN] = b.get(..PUBLIC_IDENTITY_LEN)?.try_into().ok()?;
        let n = *b.get(PUBLIC_IDENTITY_LEN)? as usize;
        if n > MAX_NAME_LEN {
            return None;
        }
        let name_end = PUBLIC_IDENTITY_LEN + 1 + n;
        if b.len() < name_end {
            return None;
        }
        let name = String::from_utf8(b[PUBLIC_IDENTITY_LEN + 1..name_end].to_vec()).ok()?;
        let mut rest = &b[name_end..];
        let mut last_rt = None;
        let mut last_bk = None;
        let mut clipboard_generation = 0;
        let mut features = 0;
        if !rest.is_empty() {
            let flags = *rest.first()?;
            rest = &rest[1..];
            if flags & 1 != 0 {
                let (a, n) = read_addr(rest)?;
                last_rt = Some(a);
                rest = &rest[n..];
            }
            if flags & 2 != 0 {
                let (a, n) = read_addr(rest)?;
                last_bk = Some(a);
                rest = &rest[n..];
            }
            if rest.len() >= 12 {
                clipboard_generation = u64::from_le_bytes(rest[..8].try_into().ok()?);
                features = u32::from_le_bytes(rest[8..12].try_into().ok()?);
            }
        }
        Some(Self {
            identity: PublicIdentity::from_bytes(id),
            name,
            last_rt,
            last_bk,
            clipboard_generation,
            features,
        })
    }
}

fn write_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(a) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_le_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(6);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_le_bytes());
        }
    }
}

fn read_addr(b: &[u8]) -> Option<(SocketAddr, usize)> {
    match *b.first()? {
        4 if b.len() >= 1 + 4 + 2 => {
            let ip = Ipv4Addr::new(b[1], b[2], b[3], b[4]);
            let port = u16::from_le_bytes([b[5], b[6]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), 7))
        }
        6 if b.len() >= 1 + 16 + 2 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[1..17]);
            let port = u16::from_le_bytes([b[17], b[18]]);
            Some((SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port), 19))
        }
        _ => None,
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
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(d)?;
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
        self.dir.join(PEERS_DIR).join(fingerprint_hex)
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
            Ok(b) => Pin::from_bytes(&b)
                .map(Some)
                .ok_or(StoreError::Corrupt(path)),
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
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.len() != 32 || !name.bytes().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let bytes = fs::read(&path)?;
            pins.push(Pin::from_bytes(&bytes).ok_or(StoreError::Corrupt(path))?);
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
    let mut f: File = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
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
        Pin {
            identity: PublicIdentity::new(id.sign_pub, id.dh_pub),
            name: name.into(),
            last_rt: None,
            last_bk: None,
            clipboard_generation: 0,
            features: 0,
        }
    }

    #[test]
    fn identity_persists_with_private_modes() {
        let dir = tmp();
        let ks = Keystore::open(&dir).unwrap();
        let a = ks.load_or_create_identity().unwrap();
        let b = Keystore::open(&dir)
            .unwrap()
            .load_or_create_identity()
            .unwrap();
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
        assert!(matches!(
            ks.load_or_create_identity(),
            Err(StoreError::Corrupt(_))
        ));
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
    fn pin_persists_last_address() {
        let dir = tmp();
        let ks = Keystore::open(&dir).unwrap();
        let mut p = pin_for("Pixel");
        p.last_rt = Some("127.0.0.1:47920".parse().unwrap());
        p.last_bk = Some("[::1]:47921".parse().unwrap());
        p.clipboard_generation = 9;
        p.features = 1;
        ks.save_pin(&p).unwrap();
        assert_eq!(ks.find_pin(&p.identity.sign_pub).unwrap(), Some(p));
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
        assert!(ks.load_pin("../../identity").unwrap().is_none());
        assert!(!ks.remove_pin("../../identity").unwrap());
        fs::remove_dir_all(dir).unwrap();
    }
}
