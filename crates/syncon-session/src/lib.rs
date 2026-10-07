//! Syncon session: Quinn endpoints, dual connection, scheduler, supervisor state machine, latest-wins apply.
//!
//! This crate must not depend on mDNS, GTK, or JNI.

pub mod connection;
pub mod pairing;
pub mod supervisor;
pub mod tls;

// Re-export key types for convenience.
pub use connection::{
    BulkLink, Link, LinkError, Message, Transport, TransportConfig, BULK_PORT, REALTIME_PORT,
};
pub use tls::Trust;
pub use supervisor::{
    BackoffConfig, PeerSession, Supervisor, SupervisorCommand, SupervisorConfig, SupervisorEvent,
    SupervisorState,
};
