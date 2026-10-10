//! Supervisor: dial/accept race, backoff, reconnect. Does not speak mDNS.
//!
//! ```text
//! Idle
//!   -- dial requested or cache hit -----------> Dialing
//! Dialing
//!   -- realtime authenticated ----------------> Established
//!   -- dial error or timeout -----------------> Backoff
//! Established
//!   -- peer close / AEAD failure -------------> Dialing   (pin is kept)
//!   -- unpair ---------------------------------> Idle
//! Backoff
//!   -- timer ---------------------------------> Dialing
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use rand::Rng;
use syncon_crypto::PublicIdentity;

use crate::connection::{Link, LinkError, Transport};
use crate::established::{self, LiveConfig, LiveEvent, LiveOutcome};
use crate::tls::Trust;

/// Supervisor states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    Idle,
    Dialing,
    Established,
    Degraded,
    Backoff,
}

/// Backoff schedule from link.md: 100 ms, 200, 400, 800, cap 5 s, full jitter.
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Backoff {
    delay: Duration,
    cfg: BackoffConfig,
}

impl Backoff {
    pub fn new(cfg: BackoffConfig) -> Self {
        Self {
            delay: cfg.initial_delay,
            cfg,
        }
    }

    /// Full jitter: sleep a random time in `[0, delay]`, then double (capped).
    pub fn next(&mut self) -> Duration {
        let cap = self.delay;
        self.delay = self
            .delay
            .mul_f64(self.cfg.multiplier)
            .min(self.cfg.max_delay);
        let f: f64 = rand::thread_rng().gen();
        cap.mul_f64(f)
    }

    pub fn reset(&mut self) {
        self.delay = self.cfg.initial_delay;
    }
}

/// How we learned the peer's realtime address.
#[derive(Debug, Clone, Copy)]
pub enum CacheSource {
    /// We dialed this listen address; keep it across reconnects.
    Advertised,
    /// We accepted; remote_addr is the peer's bound UDP port.
    Accepted,
}

#[derive(Debug, Clone)]
pub struct MaintainConfig {
    pub peer: PublicIdentity,
    pub cached_rt: Option<SocketAddr>,
    pub cache_source: CacheSource,
    pub live: LiveConfig,
    /// Keep redialing after the link drops. False for `--bench-echo` (exit after histogram).
    pub reconnect: bool,
    /// Handshake timeout for reconnect dials. Short so a down peer does not block 5 s.
    pub dial_timeout: Duration,
}

impl Default for MaintainConfig {
    fn default() -> Self {
        Self {
            peer: PublicIdentity::new([0; 32], [0; 32]),
            cached_rt: None,
            cache_source: CacheSource::Advertised,
            live: LiveConfig::default(),
            reconnect: true,
            dial_timeout: Duration::from_millis(250),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    State(SupervisorState),
    PresenceRtt(Duration),
    Clipboard { generation: u64, text: String },
    CachedAddress(SocketAddr),
}

/// Race accept against a cached dial. First authenticated handshake wins.
pub async fn connect_pinned(
    transport: &Transport,
    peer: [u8; 32],
    cached_rt: Option<SocketAddr>,
    dial_timeout: Duration,
    backoff: &mut Backoff,
    mut on_state: impl FnMut(SupervisorState),
) -> Result<Link, LinkError> {
    on_state(SupervisorState::Dialing);
    let trust = Trust::only(peer);

    let accept = async {
        loop {
            match transport.accept().await {
                Ok(link) if link.peer().sign_pub == peer => return Ok(link),
                Ok(link) => link.close(),
                Err(LinkError::Closed) => return Err(LinkError::Closed),
                Err(_) => continue,
            }
        }
    };

    let dial = async {
        let addr = match cached_rt {
            Some(a) => a,
            None => {
                std::future::pending::<()>().await;
                unreachable!()
            }
        };
        loop {
            match transport.dial_timeout(addr, trust.clone(), dial_timeout).await {
                Ok(link) if link.peer().sign_pub == peer => return Ok(link),
                Ok(link) => link.close(),
                Err(LinkError::Closed) => return Err(LinkError::Closed),
                Err(_) => {
                    on_state(SupervisorState::Backoff);
                    tokio::time::sleep(backoff.next()).await;
                    on_state(SupervisorState::Dialing);
                }
            }
        }
    };

    tokio::select! {
        r = accept => r,
        r = dial => r,
    }
}

/// Run the live session, and if `reconnect` is set, redial forever. AEAD failure
/// closes the connection and returns to Dialing; the caller must not delete the pin.
pub async fn maintain(
    transport: &Transport,
    mut cfg: MaintainConfig,
    initial: Option<Link>,
    mut on_event: impl FnMut(SessionEvent),
) -> Result<LiveOutcome, LinkError> {
    let mut backoff = Backoff::new(BackoffConfig::default());
    let mut first = initial;
    loop {
        let link = if let Some(link) = first.take() {
            link
        } else {
            connect_pinned(
                transport,
                cfg.peer.sign_pub,
                cfg.cached_rt,
                cfg.dial_timeout,
                &mut backoff,
                |s| on_event(SessionEvent::State(s)),
            )
            .await?
        };
        backoff.reset();
        if matches!(cfg.cache_source, CacheSource::Accepted) {
            cfg.cached_rt = Some(link.remote_addr());
            on_event(SessionEvent::CachedAddress(link.remote_addr()));
        }
        on_event(SessionEvent::State(SupervisorState::Established));

        let live = cfg.live.clone();
        let result = established::run(&link, live, |ev| match ev {
            LiveEvent::State(_) => {}
            LiveEvent::PresenceRtt(d) => on_event(SessionEvent::PresenceRtt(d)),
            LiveEvent::Clipboard { generation, text } => {
                on_event(SessionEvent::Clipboard { generation, text });
            }
        })
        .await;

        link.close();

        match result {
            Ok(outcome) if !cfg.reconnect || outcome.echo.is_some() => return Ok(outcome),
            Ok(_) | Err(LinkError::Closed) | Err(LinkError::Aead) => {
                // Pin stays. Reconnect from the cache.
                on_event(SessionEvent::State(SupervisorState::Dialing));
                if !cfg.reconnect {
                    return result;
                }
            }
            Err(e) => {
                if !cfg.reconnect {
                    return Err(e);
                }
                on_event(SessionEvent::State(SupervisorState::Dialing));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_stays_within_cap() {
        let mut b = Backoff::new(BackoffConfig::default());
        for _ in 0..16 {
            let d = b.next();
            assert!(d <= Duration::from_secs(5));
        }
        b.reset();
        let d = b.next();
        assert!(d <= Duration::from_millis(100));
    }
}
