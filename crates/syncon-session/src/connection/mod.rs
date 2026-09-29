//! QUIC connection management for Syncon.
//!
//! This module provides:
//! - Realtime QUIC connection (port 47920) for control, clipboard, presence, etc.
//! - Bulk QUIC connection (port 47921) for file transfers
//! - Session establishment with Hello exchange
//! - Message framing and routing
//!
//! The session is **up** when realtime is established. Bulk is opportunistic.

use std::net::SocketAddr;
use std::sync::Arc;

use syncon_proto::{Envelope, Header, HEADER_SIZE, VERSION};
use syncon_crypto::identity::Identity;

/// Default realtime UDP port.
pub const REALTIME_PORT: u16 = 47920;

/// Default bulk UDP port.
pub const BULK_PORT: u16 = 47921;

/// Connection configuration.
pub struct ConnectionConfig {
    /// Local identity.
    pub identity: Identity,
    /// Realtime bind address.
    pub realtime_addr: SocketAddr,
    /// Bulk bind address.
    pub bulk_addr: SocketAddr,
}

impl ConnectionConfig {
    /// Creates a new connection configuration.
    pub fn new(identity: Identity, realtime_addr: SocketAddr, bulk_addr: SocketAddr) -> Self {
        Self {
            identity,
            realtime_addr,
            bulk_addr,
        }
    }
}

/// Message sent from the connection to the application.
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// A new connection was established.
    Connected { peer_addr: SocketAddr },
    /// A connection was closed.
    Disconnected { peer_addr: SocketAddr },
    /// An envelope was received.
    EnvelopeReceived { envelope: Envelope },
    /// Connection error.
    Error { error: String },
}

/// Message sent from the application to the connection.
#[derive(Debug, Clone)]
pub enum ConnectionCommand {
    /// Send an envelope to the peer.
    SendEnvelope { envelope: Envelope },
    /// Close the connection.
    Close,
}

/// Realtime connection handle.
pub struct RealtimeConnection {
    config: Arc<ConnectionConfig>,
}

impl RealtimeConnection {
    /// Creates a new realtime connection.
    pub fn new(config: Arc<ConnectionConfig>) -> Self {
        Self { config }
    }
    
    /// Returns the realtime address.
    pub fn addr(&self) -> SocketAddr {
        self.config.realtime_addr
    }
}

/// Bulk connection handle.
pub struct BulkConnection {
    config: Arc<ConnectionConfig>,
}

impl BulkConnection {
    /// Creates a new bulk connection.
    pub fn new(config: Arc<ConnectionConfig>) -> Self {
        Self { config }
    }
    
    /// Returns the bulk address.
    pub fn addr(&self) -> SocketAddr {
        self.config.bulk_addr
    }
}

/// Connection manager for realtime and bulk connections.
pub struct ConnectionManager {
    realtime: RealtimeConnection,
    bulk: Option<BulkConnection>,
    config: Arc<ConnectionConfig>,
}

impl ConnectionManager {
    /// Creates a new connection manager.
    pub fn new(config: ConnectionConfig) -> Self {
        let config = Arc::new(config);
        Self {
            realtime: RealtimeConnection::new(config.clone()),
            bulk: Some(BulkConnection::new(config.clone())),
            config,
        }
    }
    
    /// Returns the realtime connection.
    pub fn realtime(&self) -> &RealtimeConnection {
        &self.realtime
    }
    
    /// Returns the bulk connection, if available.
    pub fn bulk(&self) -> Option<&BulkConnection> {
        self.bulk.as_ref()
    }
    
    /// Returns the local identity.
    pub fn identity(&self) -> &Identity {
        &self.config.identity
    }
    
    /// Parses an envelope from raw bytes.
    pub fn parse_envelope(data: &[u8]) -> Option<Envelope> {
        if data.len() < HEADER_SIZE {
            return None;
        }
        
        let header = Header::from_bytes(&data[..HEADER_SIZE]).ok()?;
        let body = data[HEADER_SIZE..].to_vec();
        
        Some(Envelope { header, body })
    }
    
    /// Serializes an envelope to bytes.
    pub fn serialize_envelope(envelope: &Envelope) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + envelope.body.len());
        buf.extend_from_slice(&envelope.header.to_bytes());
        buf.extend_from_slice(&envelope.body);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(REALTIME_PORT, 47920);
        assert_eq!(BULK_PORT, 47921);
    }

    #[test]
    fn test_connection_config() {
        let identity = Identity::generate().unwrap();
        let config = ConnectionConfig::new(
            identity,
            SocketAddr::from(([127, 0, 0, 1], 47920)),
            SocketAddr::from(([127, 0, 0, 1], 47921)),
        );
        
        assert_eq!(config.realtime_addr.port(), 47920);
        assert_eq!(config.bulk_addr.port(), 47921);
    }

    #[test]
    fn test_connection_manager() {
        let identity = Identity::generate().unwrap();
        let config = ConnectionConfig::new(
            identity,
            SocketAddr::from(([127, 0, 0, 1], 47920)),
            SocketAddr::from(([127, 0, 0, 1], 47921)),
        );
        
        let manager = ConnectionManager::new(config);
        
        assert!(manager.realtime().addr().port() == 47920);
        assert!(manager.bulk().is_some());
    }

    #[test]
    fn test_envelope_roundtrip() {
        let header = Header {
            version: VERSION,
            class: syncon_proto::Class::Control,
            flags: syncon_proto::Flags::NONE,
            seq: 1,
            body_len: 4,
        };
        
        let body = vec![1, 2, 3, 4];
        let envelope = Envelope { header, body: body.clone() };
        
        let data = ConnectionManager::serialize_envelope(&envelope);
        let parsed = ConnectionManager::parse_envelope(&data).unwrap();
        
        assert_eq!(parsed.header.version, VERSION);
        assert_eq!(parsed.header.seq, 1);
        assert_eq!(parsed.body, body);
    }
}
