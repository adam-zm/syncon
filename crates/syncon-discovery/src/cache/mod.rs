//! Last-address cache for Syncon peers.
//!
//! This module provides caching of the last known good socket addresses for peers,
//! keyed by their fingerprint. This allows quick reconnection without waiting for mDNS.
//!
//! Cache invalidation:
//! - After 3 consecutive failed dials to a cached address
//! - On successful dial to a new address (replace the cache)
//!
//! The cache is persisted to disk and loaded at startup.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Fingerprint type (16 bytes, 32 hex chars).
pub type Fingerprint = String;

/// Maximum number of failed dial attempts before invalidating a cache entry.
pub const MAX_FAILED_DIALS: u32 = 3;

/// Default cache file name.
pub const DEFAULT_CACHE_FILE: &str = "address_cache.json";

/// Cache entry for a single peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Cached socket address.
    pub address: SocketAddr,
    /// Number of consecutive failed dial attempts.
    pub failed_dials: u32,
    /// Timestamp when this entry was last successfully used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success: Option<SystemTime>,
    /// Timestamp when this entry was created.
    pub created_at: SystemTime,
}

impl CacheEntry {
    /// Creates a new cache entry.
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            failed_dials: 0,
            last_success: None,
            created_at: SystemTime::now(),
        }
    }

    /// Records a successful dial.
    pub fn record_success(&mut self) {
        self.failed_dials = 0;
        self.last_success = Some(SystemTime::now());
    }

    /// Records a failed dial.
    pub fn record_failure(&mut self) {
        self.failed_dials += 1;
    }

    /// Returns true if this entry should be invalidated.
    pub fn is_invalid(&self) -> bool {
        self.failed_dials >= MAX_FAILED_DIALS
    }

    /// Resets the failure count.
    pub fn reset_failures(&mut self) {
        self.failed_dials = 0;
    }

    /// Updates the address and resets failures.
    pub fn update_address(&mut self, new_address: SocketAddr) {
        self.address = new_address;
        self.failed_dials = 0;
        self.last_success = Some(SystemTime::now());
    }
}

/// Last-address cache for peers.
#[derive(Debug, Default)]
pub struct AddressCache {
    entries: RwLock<HashMap<Fingerprint, CacheEntry>>,
    path: Option<PathBuf>,
    dirty: Mutex<bool>,
}

impl AddressCache {
    /// Creates a new in-memory cache.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            path: None,
            dirty: Mutex::new(false),
        }
    }

    /// Creates a new cache with persistence to the given file path.
    pub fn with_persistence(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Try to load existing cache
        let entries = if path.exists() {
            let content = fs::read_to_string(&path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Ok(Self {
            entries: RwLock::new(entries),
            path: Some(path),
            dirty: Mutex::new(false),
        })
    }

    /// Gets the cached address for a fingerprint.
    pub fn get(&self, fingerprint: &Fingerprint) -> Option<SocketAddr> {
        let entries = self.entries.read().unwrap();
        entries.get(fingerprint).map(|e| e.address)
    }

    /// Gets the full cache entry for a fingerprint.
    pub fn get_entry(&self, fingerprint: &Fingerprint) -> Option<CacheEntry> {
        let entries = self.entries.read().unwrap();
        entries.get(fingerprint).cloned()
    }

    /// Sets the address for a fingerprint.
    pub fn set(&self, fingerprint: Fingerprint, address: SocketAddr) {
        let mut entries = self.entries.write().unwrap();
        entries.insert(fingerprint, CacheEntry::new(address));
        self.mark_dirty();
    }

    /// Updates the address for a fingerprint if it exists.
    pub fn update(&self, fingerprint: &Fingerprint, address: SocketAddr) -> bool {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(fingerprint) {
            entry.update_address(address);
            self.mark_dirty();
            true
        } else {
            false
        }
    }

    /// Records a successful dial for a fingerprint.
    pub fn record_success(&self, fingerprint: &Fingerprint) -> bool {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(fingerprint) {
            entry.record_success();
            self.mark_dirty();
            true
        } else {
            false
        }
    }

    /// Records a failed dial for a fingerprint.
    /// Returns true if the entry was invalidated.
    pub fn record_failure(&self, fingerprint: &Fingerprint) -> bool {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(fingerprint) {
            entry.record_failure();
            let invalid = entry.is_invalid();
            if invalid {
                entries.remove(fingerprint);
            }
            self.mark_dirty();
            invalid
        } else {
            false
        }
    }

    /// Removes a fingerprint from the cache.
    pub fn remove(&self, fingerprint: &Fingerprint) -> bool {
        let mut entries = self.entries.write().unwrap();
        let removed = entries.remove(fingerprint).is_some();
        if removed {
            self.mark_dirty();
        }
        removed
    }

    /// Returns all cached fingerprints.
    pub fn fingerprints(&self) -> Vec<Fingerprint> {
        let entries = self.entries.read().unwrap();
        entries.keys().cloned().collect()
    }

    /// Returns all cache entries.
    pub fn entries(&self) -> Vec<(Fingerprint, CacheEntry)> {
        let entries = self.entries.read().unwrap();
        entries.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();
        self.mark_dirty();
    }

    /// Returns the number of entries in the cache.
    pub fn len(&self) -> usize {
        let entries = self.entries.read().unwrap();
        entries.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Persists the cache to disk if it has been modified.
    pub fn save(&self) -> io::Result<()> {
        let path = self.path.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "No persistence path configured")
        })?;
        let entries = self.entries.read().unwrap();
        
        // Serialize to JSON with pretty printing
        let content = serde_json::to_string_pretty(&*entries)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        // Write atomically by writing to a temp file first
        let temp_path = path.with_extension("tmp");
        let mut file = File::create(&temp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        
        // Rename temp file to final path (atomic on POSIX)
        fs::rename(&temp_path, path)?;
        
        // Clear dirty flag
        let mut dirty = self.dirty.lock().unwrap();
        *dirty = false;
        
        Ok(())
    }

    /// Loads the cache from disk (replaces current entries).
    pub fn reload(&self) -> io::Result<()> {
        let path = self.path.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "No persistence path configured")
        })?;
        
        if !path.exists() {
            return Ok(());
        }
        
        let content = fs::read_to_string(path)?;
        let entries: HashMap<Fingerprint, CacheEntry> = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        let mut current = self.entries.write().unwrap();
        *current = entries;
        
        let mut dirty = self.dirty.lock().unwrap();
        *dirty = false;
        
        Ok(())
    }

    /// Marks the cache as dirty (needs to be saved).
    fn mark_dirty(&self) {
        if self.path.is_some() {
            let mut dirty = self.dirty.lock().unwrap();
            *dirty = true;
        }
    }

    /// Returns true if the cache has been modified since the last save.
    pub fn is_dirty(&self) -> bool {
        if self.path.is_none() {
            return false;
        }
        let dirty = self.dirty.lock().unwrap();
        *dirty
    }
}

/// In-memory address resolver that combines cache and mDNS results.
#[derive(Debug)]
pub struct AddressResolver {
    cache: AddressCache,
    mdns_peers: Arc<RwLock<HashMap<Fingerprint, SocketAddr>>>,
}

impl AddressResolver {
    /// Creates a new address resolver.
    pub fn new(cache: AddressCache) -> Self {
        Self {
            cache,
            mdns_peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Updates mDNS-discovered peers.
    pub fn update_mdns_peers(&self, peers: HashMap<Fingerprint, SocketAddr>) {
        let mut mdns_peers = self.mdns_peers.write().unwrap();
        *mdns_peers = peers;
    }

    /// Resolves the addresses for a fingerprint in dial order.
    ///
    /// Returns addresses in the order they should be dialed:
    /// 1. Last known socket address from cache (if not invalidated)
    /// 2. mDNS-discovered addresses
    ///
    /// The caller should race these addresses.
    pub fn resolve(&self, fingerprint: &Fingerprint) -> Vec<SocketAddr> {
        let mut addresses = Vec::new();
        
        // 1. Try cache first
        if let Some(cached_addr) = self.cache.get(fingerprint) {
            // Check if cache entry is still valid
            if let Some(entry) = self.cache.get_entry(fingerprint) {
                if !entry.is_invalid() {
                    addresses.push(cached_addr);
                }
            }
        }
        
        // 2. Add mDNS-discovered addresses (skip duplicates)
        let mdns_peers = self.mdns_peers.read().unwrap();
        if let Some(mdns_addr) = mdns_peers.get(fingerprint) {
            if !addresses.contains(mdns_addr) {
                addresses.push(*mdns_addr);
            }
        }
        
        addresses
    }

    /// Returns the cache reference.
    pub fn cache(&self) -> &AddressCache {
        &self.cache
    }

    /// Returns the cache reference (mutable).
    pub fn cache_mut(&mut self) -> &mut AddressCache {
        &mut self.cache
    }
}

/// Races multiple addresses for a fingerprint and returns the first successful one.
///
/// This implements dial racing: try all addresses concurrently and return the first
/// that successfully responds to a probe or connects.
///
/// For simplicity, this uses a sequential approach with timeouts.
/// A production implementation would use async/await with proper timeouts.
pub fn race_addresses(
    fingerprint: &Fingerprint,
    addresses: Vec<SocketAddr>,
    probe_timeout: Duration,
) -> Option<SocketAddr> {
    use crate::mdns::send_probe;

    // Convert fingerprint string to bytes
    let fp_bytes: [u8; 16] = hex::decode(fingerprint).ok()?.try_into().ok()?;

    for addr in addresses {
        // Try to probe the address
        // Note: This is a blocking call. In production, you'd want to do this
        // asynchronously and race them properly.
        if let Ok(true) = send_probe(addr, &fp_bytes, probe_timeout) {
            return Some(addr);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_cache_entry_new() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 47920);
        let entry = CacheEntry::new(addr);
        
        assert_eq!(entry.address, addr);
        assert_eq!(entry.failed_dials, 0);
        assert!(entry.last_success.is_none());
    }

    #[test]
    fn test_cache_entry_record_success() {
        let mut entry = CacheEntry::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            47920,
        ));
        
        entry.record_success();
        assert_eq!(entry.failed_dials, 0);
        assert!(entry.last_success.is_some());
    }

    #[test]
    fn test_cache_entry_invalidation() {
        let mut entry = CacheEntry::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            47920,
        ));
        
        // Record failures up to the limit
        for _ in 0..MAX_FAILED_DIALS {
            entry.record_failure();
        }
        
        assert!(entry.is_invalid());
    }

    #[test]
    fn test_address_cache_basic() {
        let cache = AddressCache::new();
        let fingerprint = "aabbccdd11223344aabbccdd11223344".to_string();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 47920);
        
        cache.set(fingerprint.clone(), addr);
        
        assert_eq!(cache.get(&fingerprint), Some(addr));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_address_cache_remove() {
        let cache = AddressCache::new();
        let fingerprint = "aabbccdd11223344aabbccdd11223344".to_string();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 47920);
        
        cache.set(fingerprint.clone(), addr);
        assert!(cache.remove(&fingerprint));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_address_resolver_basic() {
        let cache = AddressCache::new();
        let resolver = AddressResolver::new(cache);
        let fingerprint = "aabbccdd11223344aabbccdd11223344".to_string();
        
        // Add to cache
        let cached_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 47920);
        resolver.cache().set(fingerprint.clone(), cached_addr);
        
        // Add to mDNS
        let mdns_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), 47920);
        resolver.update_mdns_peers(HashMap::from([(fingerprint.clone(), mdns_addr)]));
        
        let addresses = resolver.resolve(&fingerprint);
        
        // Cache address should come first, then mDNS
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0], cached_addr);
        assert_eq!(addresses[1], mdns_addr);
    }

    #[test]
    fn test_race_addresses_empty() {
        let addresses = vec![];
        let fingerprint = "aabbccdd11223344aabbccdd11223344".to_string();
        let result = race_addresses(&fingerprint, addresses, Duration::from_millis(10));
        assert!(result.is_none());
    }
}
