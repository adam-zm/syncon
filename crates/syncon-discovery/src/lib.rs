//! Syncon discovery: mDNS, last-address cache, UDP probe, dial racing.
//!
//! This crate must not depend on crypto beyond comparing fingerprints.

pub mod cache;
pub mod mdns;

// Re-export key types for convenience.
pub use cache::{AddressCache, AddressResolver, CacheEntry, Fingerprint};
pub use mdns::{
    AdvertisementConfig, BrowseEvent, DEFAULT_BULK_PORT, DEFAULT_REALTIME_PORT, DiscoveredPeer,
    MdnsBrowser, MdnsDaemon, PROBE_MAGIC, PROBE_SIZE, SERVICE_TYPE,
};
