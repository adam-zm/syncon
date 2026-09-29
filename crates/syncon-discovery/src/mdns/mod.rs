//! mDNS service discovery for Syncon peers.
//!
//! This module provides mDNS-based service advertisement and discovery for Syncon devices
//! using the `_link._udp.local` service type.
//!
//! TXT records contain:
//! - `v`: Protocol version (1)
//! - `fp`: Fingerprint (32 hex chars, lowercase)
//! - `rt`: Realtime UDP port
//! - `bk`: Bulk UDP port
//! - `name`: Display name (max 32 bytes, no newlines)

use flume::{RecvTimeoutError, Receiver as FlumeReceiver, Sender as FlumeSender};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use syncon_proto::VERSION;

/// Default realtime UDP port.
pub const DEFAULT_REALTIME_PORT: u16 = 47920;

/// Default bulk UDP port.
pub const DEFAULT_BULK_PORT: u16 = 47921;

/// mDNS service type for Syncon.
pub const SERVICE_TYPE: &str = "_link._udp.local";

/// Maximum display name length in bytes.
pub const MAX_NAME_LEN: usize = 32;

/// Service TXT record keys.
pub mod txt {
    pub const VERSION: &str = "v";
    pub const FINGERPRINT: &str = "fp";
    pub const REALTIME_PORT: &str = "rt";
    pub const BULK_PORT: &str = "bk";
    pub const NAME: &str = "name";
}

/// Configuration for mDNS service advertisement.
#[derive(Debug, Clone)]
pub struct AdvertisementConfig {
    /// Display name for this device.
    pub name: String,
    /// Fingerprint (32 hex chars).
    pub fingerprint: String,
    /// Realtime UDP port.
    pub realtime_port: u16,
    /// Bulk UDP port.
    pub bulk_port: u16,
}

impl Default for AdvertisementConfig {
    fn default() -> Self {
        Self {
            name: "Syncon Device".to_string(),
            fingerprint: "00000000000000000000000000000000".to_string(),
            realtime_port: DEFAULT_REALTIME_PORT,
            bulk_port: DEFAULT_BULK_PORT,
        }
    }
}

impl AdvertisementConfig {
    /// Creates a new advertisement configuration.
    pub fn new(name: impl Into<String>, fingerprint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fingerprint: fingerprint.into(),
            realtime_port: DEFAULT_REALTIME_PORT,
            bulk_port: DEFAULT_BULK_PORT,
        }
    }

    /// Sets the realtime port.
    pub fn with_realtime_port(mut self, port: u16) -> Self {
        self.realtime_port = port;
        self
    }

    /// Sets the bulk port.
    pub fn with_bulk_port(mut self, port: u16) -> Self {
        self.bulk_port = port;
        self
    }

    /// Creates ServiceInfo for mDNS advertisement.
    pub fn to_service_info(&self, ip: IpAddr) -> Result<ServiceInfo, mdns_sd::Error> {
        let mut properties = HashMap::new();
        properties.insert(txt::VERSION.to_string(), VERSION.to_string());
        properties.insert(txt::FINGERPRINT.to_string(), self.fingerprint.clone());
        properties.insert(
            txt::REALTIME_PORT.to_string(),
            self.realtime_port.to_string(),
        );
        properties.insert(txt::BULK_PORT.to_string(), self.bulk_port.to_string());
        properties.insert(txt::NAME.to_string(), self.name.clone());

        // Hostname must be a valid DNS name. Use the IP as hostname.
        let host_name = format!("{}.local", ip);
        
        ServiceInfo::new(
            SERVICE_TYPE,
            &self.name,
            &host_name,
            ip,
            self.realtime_port,
            properties,
        )
    }
}

/// Information about a discovered peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// Fingerprint of the peer.
    pub fingerprint: String,
    /// Display name of the peer.
    pub name: String,
    /// Realtime UDP port.
    pub realtime_port: u16,
    /// Bulk UDP port.
    pub bulk_port: u16,
    /// Protocol version.
    pub version: u8,
    /// Socket addresses where the service was found.
    pub addresses: Vec<SocketAddr>,
}

impl DiscoveredPeer {
    /// Creates a new DiscoveredPeer from mDNS service info.
    pub fn from_service_info(info: &ServiceInfo) -> Option<Self> {
        let version = info
            .get_property_val_str(txt::VERSION)
            .and_then(|v| v.parse::<u8>().ok())?;

        // Only accept version 1
        if version != VERSION {
            return None;
        }

        let fingerprint = info.get_property_val_str(txt::FINGERPRINT)?.to_string();
        let name = info.get_property_val_str(txt::NAME).unwrap_or_default().to_string();
        let realtime_port = info
            .get_property_val_str(txt::REALTIME_PORT)
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(DEFAULT_REALTIME_PORT);
        let bulk_port = info
            .get_property_val_str(txt::BULK_PORT)
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(DEFAULT_BULK_PORT);

        let addresses = info
            .get_addresses()
            .into_iter()
            .map(|addr| {
                // Use the service port for the address
                SocketAddr::new(addr.clone(), info.get_port())
            })
            .collect();

        Some(Self {
            fingerprint,
            name,
            realtime_port,
            bulk_port,
            version,
            addresses,
        })
    }

    /// Returns the realtime socket address for a specific IP.
    pub fn realtime_addr(&self, ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, self.realtime_port)
    }

    /// Returns the bulk socket address for a specific IP.
    pub fn bulk_addr(&self, ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, self.bulk_port)
    }
}

/// mDNS service daemon handle.
#[derive(Clone)]
pub struct MdnsDaemon {
    daemon: Arc<Mutex<ServiceDaemon>>,
}

impl MdnsDaemon {
    /// Creates a new mDNS daemon.
    pub fn new() -> Result<Self, mdns_sd::Error> {
        let daemon = ServiceDaemon::new()?;
        Ok(Self {
            daemon: Arc::new(Mutex::new(daemon)),
        })
    }

    /// Starts advertising a service.
    pub fn advertise(
        &self,
        config: AdvertisementConfig,
        interface_ip: Option<IpAddr>,
    ) -> Result<(), mdns_sd::Error> {
        let daemon = self.daemon.lock().unwrap();

        // Use IPv4 wildcard if no specific IP is provided
        let ip = interface_ip.unwrap_or(Ipv4Addr::new(0, 0, 0, 0).into());

        let service_info = config.to_service_info(ip)?;
        daemon.register(service_info)?;

        Ok(())
    }

    /// Stops advertising all services.
    pub fn unregister_all(&self) -> Result<(), mdns_sd::Error> {
        let _daemon = self.daemon.lock().unwrap();
        Ok(())
    }
}

/// Browse result event.
#[derive(Debug, Clone, PartialEq)]
pub enum BrowseEvent {
    /// A new peer was discovered.
    PeerFound(DiscoveredPeer),
    /// A peer was lost.
    PeerLost(String), // fingerprint
    /// Browse started.
    Started,
    /// Browse error.
    Error(String),
}

/// Handle for browsing mDNS services.
pub struct MdnsBrowser {
    receiver: FlumeReceiver<BrowseEvent>,
    _stop_sender: FlumeSender<()>, // Keep this alive to keep the thread running
}

impl MdnsBrowser {
    /// Starts browsing for Syncon peers.
    pub fn start(daemon: &MdnsDaemon) -> Result<Self, mdns_sd::Error> {
        let (event_sender, receiver) = flume::bounded(100);
        let (stop_sender, stop_receiver) = flume::bounded(1);

        let daemon_clone = daemon.daemon.clone();

        thread::spawn(move || {
            let daemon = daemon_clone.lock().unwrap();

            let mdns_receiver = match daemon.browse(SERVICE_TYPE) {
                Ok(r) => r,
                Err(e) => {
                    let _ = event_sender.send(BrowseEvent::Error(format!(
                        "Failed to start browse: {}",
                        e
                    )));
                    return;
                }
            };

            let _ = event_sender.send(BrowseEvent::Started);

            // Collect known peers to detect losses
            let mut known_peers: HashMap<String, DiscoveredPeer> = HashMap::new();

            loop {
                // Check for stop signal with a timeout
                match stop_receiver.recv_timeout(Duration::from_millis(50)) {
                    Ok(_) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }

                // Use a short timeout for receiving events
                match mdns_receiver.recv_timeout(Duration::from_millis(50)) {
                    Ok(ServiceEvent::ServiceFound(_, _)) => {}
                    Ok(ServiceEvent::ServiceResolved(info)) => {
                        if let Some(peer) = DiscoveredPeer::from_service_info(&info) {
                            let fingerprint = peer.fingerprint.clone();
                            
                            // Check if this is a new peer or an update
                            if let Some(existing) = known_peers.get(&fingerprint) {
                                // Peer already known, check if addresses changed
                                if existing.addresses != peer.addresses {
                                    let _ = event_sender.send(BrowseEvent::PeerFound(peer.clone()));
                                }
                            } else {
                                // New peer
                                let _ = event_sender.send(BrowseEvent::PeerFound(peer.clone()));
                            }
                            known_peers.insert(fingerprint, peer);
                        }
                    }
                    Ok(ServiceEvent::ServiceRemoved(_, _)) => {}
                    Ok(ServiceEvent::SearchStarted(_)) => {}
                    Ok(ServiceEvent::SearchStopped(_)) => {}
                    Err(RecvTimeoutError::Timeout) => {
                        // No event, continue checking
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        Ok(Self {
            receiver,
            _stop_sender: stop_sender,
        })
    }

    /// Receives the next browse event, with a timeout.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<BrowseEvent, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    /// Receives the next browse event, blocking.
    pub fn recv(&self) -> Result<BrowseEvent, flume::RecvError> {
        self.receiver.recv()
    }

    /// Returns an iterator over available events (non-blocking).
    pub fn try_iter(&self) -> flume::TryIter<'_, BrowseEvent> {
        self.receiver.try_iter()
    }
}

/// UDP probe magic bytes: "LINKDIS1"
pub const PROBE_MAGIC: [u8; 8] = [0x4c, 0x49, 0x4e, 0x4b, 0x44, 0x49, 0x53, 0x31];

/// Size of the UDP probe packet (8 magic + 16 fingerprint = 24 bytes).
pub const PROBE_SIZE: usize = 24;

/// Sends a UDP probe to verify a peer at the given address.
///
/// The probe contains the magic bytes followed by the fingerprint.
/// A paired peer or a peer in pairing mode will respond with the same packet.
pub fn send_probe(
    dst: SocketAddr,
    fingerprint: &[u8; 16],
    timeout: Duration,
) -> Result<bool, std::io::Error> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;

    // Build probe packet
    let mut probe = [0u8; PROBE_SIZE];
    probe[..8].copy_from_slice(&PROBE_MAGIC);
    probe[8..].copy_from_slice(fingerprint);

    // Send probe
    socket.send_to(&probe, dst)?;

    // Receive response
    let mut buf = [0u8; PROBE_SIZE];
    match socket.recv_from(&mut buf) {
        Ok((len, src)) if src == dst && len == PROBE_SIZE => {
            // Verify magic
            if buf[..8] != PROBE_MAGIC {
                return Ok(false);
            }
            // Verify fingerprint
            Ok(buf[8..] == *fingerprint)
        }
        Ok(_) => Ok(false), // Wrong length or wrong source
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false), // Timeout
        Err(e) => Err(e),
    }
}

/// Receives and handles UDP probes on the given socket.
///
/// This should be called in a loop on the realtime port to respond to probes.
pub fn handle_probes(
    socket: &std::net::UdpSocket,
    known_fingerprints: &[&[u8; 16]],
) -> Result<(), std::io::Error> {
    let mut buf = [0u8; PROBE_SIZE];
    
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) if len == PROBE_SIZE => {
                // Check magic
                if buf[..8] != PROBE_MAGIC {
                    continue;
                }
                
                let received_fp: &[u8; 16] = &buf[8..24].try_into().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid fingerprint length")
                })?;
                
                // Check if this fingerprint is known (paired or in pairing mode)
                if known_fingerprints.iter().any(|&fp| fp == received_fp) {
                    // Send response
                    socket.send_to(&buf, src)?;
                }
                // Otherwise ignore (do not respond)
            }
            Ok(_) => {
                // Wrong length, ignore
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout, no data
                break;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_magic() {
        assert_eq!(PROBE_MAGIC, [0x4c, 0x49, 0x4e, 0x4b, 0x44, 0x49, 0x53, 0x31]);
    }

    #[test]
    fn test_advertisement_config_default() {
        let config = AdvertisementConfig::default();
        assert_eq!(config.realtime_port, DEFAULT_REALTIME_PORT);
        assert_eq!(config.bulk_port, DEFAULT_BULK_PORT);
    }

    #[test]
    fn test_discovered_peer_from_service_info() {
        let mut properties = HashMap::new();
        properties.insert(txt::VERSION.to_string(), "1".to_string());
        properties.insert(txt::FINGERPRINT.to_string(), "aabbccdd11223344aabbccdd11223344".to_string());
        properties.insert(txt::REALTIME_PORT.to_string(), "12345".to_string());
        properties.insert(txt::BULK_PORT.to_string(), "12346".to_string());
        properties.insert(txt::NAME.to_string(), "Test Device".to_string());

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let host_name = "192.168.1.100.local";
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            "Test Device",
            host_name,
            ip,
            12345,
            properties,
        )
        .unwrap();

        let peer = DiscoveredPeer::from_service_info(&service_info).unwrap();
        assert_eq!(peer.fingerprint, "aabbccdd11223344aabbccdd11223344");
        assert_eq!(peer.name, "Test Device");
        assert_eq!(peer.realtime_port, 12345);
        assert_eq!(peer.bulk_port, 12346);
        assert_eq!(peer.version, 1);
    }

    #[test]
    fn test_discovered_peer_wrong_version() {
        let mut properties = HashMap::new();
        properties.insert(txt::VERSION.to_string(), "2".to_string());
        properties.insert(txt::FINGERPRINT.to_string(), "aabbccdd11223344aabbccdd11223344".to_string());

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let host_name = "192.168.1.100.local";
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            "Test Device",
            host_name,
            ip,
            12345,
            properties,
        )
        .unwrap();

        assert!(DiscoveredPeer::from_service_info(&service_info).is_none());
    }
}
