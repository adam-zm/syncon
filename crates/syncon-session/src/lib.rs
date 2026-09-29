//! Syncon session: Quinn endpoints, dual connection, scheduler, supervisor state machine, latest-wins apply.
//!
//! This crate must not depend on mDNS, GTK, or JNI.

pub mod connection;
pub mod supervisor;

// Re-export key types for convenience.
pub use connection::{ConnectionConfig, REALTIME_PORT, BULK_PORT};
pub use supervisor::{
    BackoffConfig, PeerSession, Supervisor, SupervisorCommand, SupervisorConfig, SupervisorEvent,
    SupervisorState,
};
