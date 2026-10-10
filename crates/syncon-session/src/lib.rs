//! Syncon session: Quinn endpoints, dual connection, scheduler, supervisor state machine, latest-wins apply.
//!
//! This crate must not depend on mDNS, GTK, or JNI.

pub mod connection;
pub mod established;
pub mod pairing;
pub mod supervisor;
pub mod tls;

// Re-export key types for convenience.
pub use connection::{
    BulkLink, Link, LinkError, Message, Transport, TransportConfig, BULK_PORT, REALTIME_PORT,
};
pub use established::{
    echo_p95_budget, BenchConfig, EchoHistogram, HeartbeatConfig, LiveConfig, LiveEvent,
    LiveOutcome, LiveState,
};
pub use pairing::{PairError, PairPayload};
pub use supervisor::{
    connect_pinned, maintain, Backoff, BackoffConfig, CacheSource, MaintainConfig, SessionEvent,
    SupervisorState,
};
pub use tls::Trust;
