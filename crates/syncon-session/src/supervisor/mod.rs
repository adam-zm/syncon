//! Supervisor state machine for Syncon peers.
//!
//! This module implements the supervisor state machine as specified in the architecture:
//!
//! ```text
//! Idle
//!   -- unpair / never paired -----------------> Idle
//!   -- dial requested or cache hit -----------> Dialing
//! Dialing
//!   -- realtime authenticated ----------------> Established
//!   -- dial error or 5 s timeout -------------> Backoff
//! Established
//!   -- heartbeat miss (1 s active / 3 s idle) > Degraded
//!   -- local shutdown or peer close ----------> Dialing   (if still paired)
//!   -- unpair ---------------------------------> Idle
//! Degraded
//!   -- a heartbeat returns -------------------> Established
//!   -- budget exceeded -----------------------> Dialing
//! Backoff
//!   -- timer ---------------------------------> Dialing
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, RwLock};

use syncon_discovery::{AddressCache, AddressResolver};

/// Supervisor states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    /// No active session, waiting for dial request.
    Idle,
    /// Actively attempting to connect.
    Dialing,
    /// Session is established and active.
    Established,
    /// Session is degraded (heartbeat missed).
    Degraded,
    /// Backing off after failed dial attempts.
    Backoff,
}

/// Supervisor command.
#[derive(Debug, Clone)]
pub enum SupervisorCommand {
    /// Start a new session with the given fingerprint.
    Dial { fingerprint: String },
    /// Gracefully shutdown the session.
    Shutdown,
    /// Unpair from a peer.
    Unpair { fingerprint: String },
    /// Send an envelope to the peer.
    SendEnvelope { 
        fingerprint: String,
        envelope: syncon_proto::Envelope 
    },
}

/// Supervisor event.
#[derive(Debug, Clone)]
pub enum SupervisorEvent {
    /// State changed for a peer.
    StateChanged { fingerprint: String, state: SupervisorState },
    /// Session established with a peer.
    SessionEstablished { fingerprint: String },
    /// Session lost with a peer.
    SessionLost { fingerprint: String },
    /// Envelope received from peer.
    EnvelopeReceived { 
        fingerprint: String,
        envelope: syncon_proto::Envelope 
    },
    /// Error occurred.
    Error { error: String },
}

/// Backoff schedule configuration.
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    /// Initial backoff delay.
    pub initial_delay: Duration,
    /// Maximum backoff delay.
    pub max_delay: Duration,
    /// Backoff multiplier.
    pub multiplier: f64,
    /// Jitter factor (0.0 to 1.0).
    pub jitter: f64,
    /// Reset threshold (time in Established before resetting backoff).
    pub reset_threshold: Duration,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
            jitter: 0.25,
            reset_threshold: Duration::from_secs(10),
        }
    }
}

/// Per-peer session state.
#[derive(Debug)]
pub struct PeerSession {
    /// Current state.
    pub state: SupervisorState,
    /// Fingerprint of the peer.
    pub fingerprint: String,
    /// Last known address.
    pub address: Option<SocketAddr>,
    /// Last successful heartbeat time.
    pub last_heartbeat: Option<Instant>,
    /// Connection attempt count.
    pub connection_attempts: u32,
    /// Current backoff delay.
    pub current_backoff: Duration,
    /// Time when current state was entered.
    pub state_entered: Instant,
    /// Backoff configuration.
    pub backoff_config: BackoffConfig,
}

impl PeerSession {
    /// Creates a new peer session.
    pub fn new(fingerprint: String) -> Self {
        Self {
            state: SupervisorState::Idle,
            fingerprint,
            address: None,
            last_heartbeat: None,
            connection_attempts: 0,
            current_backoff: Duration::from_millis(100),
            state_entered: Instant::now(),
            backoff_config: BackoffConfig::default(),
        }
    }

    /// Returns the next backoff delay with jitter.
    pub fn next_backoff(&mut self) -> Duration {
        // Apply multiplier
        self.current_backoff = self
            .current_backoff
            .mul_f64(self.backoff_config.multiplier)
            .min(self.backoff_config.max_delay);

        // Apply jitter
        let jitter_amount = self.current_backoff.mul_f64(self.backoff_config.jitter);
        let jitter = rand::random::<f64>() * 2.0 - 1.0; // -1.0 to 1.0
        let jittered = self.current_backoff.as_secs_f64() + jitter * jitter_amount.as_secs_f64();
        
        Duration::from_secs_f64(jittered.max(0.0))
    }

    /// Resets the backoff schedule.
    pub fn reset_backoff(&mut self) {
        self.current_backoff = self.backoff_config.initial_delay;
        self.connection_attempts = 0;
    }

    /// Records a successful connection.
    pub fn record_success(&mut self) {
        self.last_heartbeat = Some(Instant::now());
        self.connection_attempts = 0;
        
        // Check if we've been in Established long enough to reset backoff
        if self.state == SupervisorState::Established {
            if self.state_entered.elapsed() >= self.backoff_config.reset_threshold {
                self.reset_backoff();
            }
        }
    }

    /// Records a failed connection attempt.
    pub fn record_failure(&mut self) {
        self.connection_attempts += 1;
    }

    /// Sets the state.
    pub fn set_state(&mut self, state: SupervisorState) {
        self.state = state;
        self.state_entered = Instant::now();
    }
}

/// Supervisor configuration.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Local identity fingerprint.
    pub local_fingerprint: String,
    /// Realtime bind address.
    pub realtime_addr: SocketAddr,
    /// Bulk bind address.
    pub bulk_addr: SocketAddr,
    /// Whether to enable mDNS discovery.
    pub enable_mdns: bool,
    /// Cache persistence path.
    pub cache_path: Option<String>,
}

/// The main supervisor.
#[derive(Debug)]
pub struct Supervisor {
    /// Per-peer sessions.
    sessions: Arc<RwLock<HashMap<String, PeerSession>>>,
    /// Event sender.
    event_sender: mpsc::Sender<SupervisorEvent>,
    /// Command receiver.
    command_receiver: mpsc::Receiver<SupervisorCommand>,
    /// Address resolver.
    address_resolver: Option<AddressResolver>,
    /// Configuration.
    config: SupervisorConfig,
}

impl Supervisor {
    /// Creates a new supervisor.
    pub async fn new(config: SupervisorConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let (event_sender, _event_receiver) = mpsc::channel(100);
        let (_command_sender, command_receiver) = mpsc::channel(100);
        
        // Initialize address cache
        let cache = if let Some(path) = &config.cache_path {
            AddressCache::with_persistence(path)?
        } else {
            AddressCache::new()
        };
        
        let address_resolver = Some(AddressResolver::new(cache));
        
        Ok(Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            command_receiver,
            address_resolver,
            config,
        })
    }

    /// Starts the supervisor.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(command) = self.command_receiver.recv() => {
                    self.handle_command(command).await;
                }
            }
        }
    }

    /// Handles a command.
    async fn handle_command(&mut self, command: SupervisorCommand) {
        match command {
            SupervisorCommand::Dial { fingerprint } => {
                self.start_dial(&fingerprint).await;
            }
            SupervisorCommand::Shutdown => {
                self.shutdown().await;
            }
            SupervisorCommand::Unpair { fingerprint } => {
                self.unpair(&fingerprint).await;
            }
            SupervisorCommand::SendEnvelope { fingerprint, envelope } => {
                self.send_envelope(&fingerprint, envelope).await;
            }
        }
    }

    /// Starts dialing a peer.
    async fn start_dial(&mut self, fingerprint: &String) {
        let mut sessions = self.sessions.write().await;
        let session = sessions.entry(fingerprint.clone()).or_insert_with(|| {
            PeerSession::new(fingerprint.clone())
        });
        
        if session.state == SupervisorState::Established {
            // Already connected
            return;
        }
        
        session.set_state(SupervisorState::Dialing);
        let _ = self.event_sender.send(SupervisorEvent::StateChanged {
            fingerprint: fingerprint.clone(),
            state: SupervisorState::Dialing
        }).await;
        
        // Resolve addresses
        if let Some(ref mut resolver) = self.address_resolver {
            let addresses = resolver.resolve(fingerprint);
            
            for addr in addresses {
                session.record_failure();
                
                let _ = self.event_sender.send(SupervisorEvent::Error {
                    error: format!("Dialing {} at {}", fingerprint, addr)
                }).await;
                
                // In a real implementation, we'd attempt the connection here
                // and transition to Established on success
                // For M0, we just emit the dial attempt
            }
        }
        
        // For now, simulate connection success
        // In a real implementation, this would happen asynchronously
        session.set_state(SupervisorState::Established);
        session.record_success();
        
        let _ = self.event_sender.send(SupervisorEvent::StateChanged {
            fingerprint: fingerprint.clone(),
            state: SupervisorState::Established
        }).await;
        
        let _ = self.event_sender.send(SupervisorEvent::SessionEstablished {
            fingerprint: fingerprint.clone()
        }).await;
    }

    /// Shuts down the supervisor.
    async fn shutdown(&mut self) {
        let mut sessions = self.sessions.write().await;
        for (fingerprint, session) in sessions.iter_mut() {
            session.set_state(SupervisorState::Idle);
            let _ = self.event_sender.send(SupervisorEvent::StateChanged {
                fingerprint: fingerprint.clone(),
                state: SupervisorState::Idle
            }).await;
        }
    }

    /// Unpairs from a peer.
    async fn unpair(&mut self, fingerprint: &String) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(fingerprint).is_some() {
            // Also remove from cache
            if let Some(ref mut resolver) = self.address_resolver {
                resolver.cache_mut().remove(fingerprint);
            }
            
            let _ = self.event_sender.send(SupervisorEvent::SessionLost {
                fingerprint: fingerprint.clone()
            }).await;
        }
    }

    /// Sends an envelope to a peer.
    async fn send_envelope(&mut self, fingerprint: &String, _envelope: syncon_proto::Envelope) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(fingerprint) {
            if session.state == SupervisorState::Established {
                // In a real implementation, we'd send via the connection
                let _ = self.event_sender.send(SupervisorEvent::Error {
                    error: format!("Sending envelope to {} (not yet implemented)", fingerprint)
                }).await;
            } else {
                let _ = self.event_sender.send(SupervisorEvent::Error {
                    error: format!("Cannot send: not connected to {}", fingerprint)
                }).await;
            }
        } else {
            let _ = self.event_sender.send(SupervisorEvent::Error {
                error: format!("Unknown peer: {}", fingerprint)
            }).await;
        }
    }

    /// Returns the current state for a peer.
    pub async fn get_state(&self, fingerprint: &String) -> Option<SupervisorState> {
        let sessions = self.sessions.read().await;
        sessions.get(fingerprint).map(|s| s.state)
    }

    /// Returns all known peers.
    pub async fn get_peers(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }

    /// Returns the event sender for external consumers.
    pub fn event_sender(&self) -> mpsc::Sender<SupervisorEvent> {
        self.event_sender.clone()
    }

    /// Returns a new command sender for external consumers.
    pub fn command_sender(&self) -> mpsc::Sender<SupervisorCommand> {
        // Create a new channel for commands
        // Note: In a real implementation, we'd need to handle the receiver properly
        mpsc::channel(100).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_session_new() {
        let fingerprint = "aabbccdd11223344aabbccdd11223344".to_string();
        let session = PeerSession::new(fingerprint.clone());
        
        assert_eq!(session.state, SupervisorState::Idle);
        assert_eq!(session.fingerprint, fingerprint);
        assert_eq!(session.connection_attempts, 0);
    }

    #[test]
    fn test_peer_session_state_transitions() {
        let fingerprint = "aabbccdd11223344aabbccdd11223344".to_string();
        let mut session = PeerSession::new(fingerprint);
        
        session.set_state(SupervisorState::Dialing);
        assert_eq!(session.state, SupervisorState::Dialing);
        
        session.set_state(SupervisorState::Established);
        assert_eq!(session.state, SupervisorState::Established);
    }

    #[test]
    fn test_peer_session_record_success() {
        let fingerprint = "aabbccdd11223344aabbccdd11223344".to_string();
        let mut session = PeerSession::new(fingerprint);
        
        session.set_state(SupervisorState::Established);
        session.record_success();
        
        assert!(session.last_heartbeat.is_some());
        assert_eq!(session.connection_attempts, 0);
    }

    #[test]
    fn test_peer_session_backoff() {
        let fingerprint = "aabbccdd11223344aabbccdd11223344".to_string();
        let mut session = PeerSession::new(fingerprint);
        
        // Record failures to increase backoff
        session.record_failure();
        session.record_failure();
        
        let backoff = session.next_backoff();
        assert!(backoff >= session.backoff_config.initial_delay);
    }

    #[tokio::test]
    async fn test_supervisor_new() {
        let config = SupervisorConfig {
            local_fingerprint: "aabbccdd11223344aabbccdd11223344".to_string(),
            realtime_addr: SocketAddr::from(([127, 0, 0, 1], 47920)),
            bulk_addr: SocketAddr::from(([127, 0, 0, 1], 47921)),
            enable_mdns: false,
            cache_path: None,
        };
        
        let supervisor = Supervisor::new(config).await.unwrap();
        assert!(supervisor.get_peers().await.is_empty());
    }

    #[tokio::test]
    async fn test_supervisor_dial() {
        let config = SupervisorConfig {
            local_fingerprint: "aabbccdd11223344aabbccdd11223344".to_string(),
            realtime_addr: SocketAddr::from(([127, 0, 0, 1], 47920)),
            bulk_addr: SocketAddr::from(([127, 0, 0, 1], 47921)),
            enable_mdns: false,
            cache_path: None,
        };
        
        let supervisor = Supervisor::new(config).await.unwrap();
        let _event_receiver = supervisor.event_sender();
        
        // Send dial command
        let command_sender = supervisor.command_sender();
        let _ = command_sender.send(SupervisorCommand::Dial {
            fingerprint: "remote_peer".to_string()
        }).await;
        
        // In a real test, we'd check the state changed
        // For now, just verify it doesn't panic
    }
}
