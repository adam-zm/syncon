//! Live session after SAS confirm: presence heartbeats, latest-wins clipboard, input echo.
//!
//! The supervisor owns dial/backoff. This loop is what keeps a connected peer in
//! `Established` and is what `--bench-echo` measures.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use syncon_proto::{Class, Clipboard, Flags, Presence};
use tokio::time::sleep_until;

use crate::connection::{Link, LinkError, Message};

/// Application-level liveness of an already authenticated link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveState {
    Established,
    Degraded,
    /// Miss budget exceeded while degraded. Reconnect is a later slice.
    Dialing,
}

/// Events the host logs or applies.
#[derive(Debug, Clone)]
pub enum LiveEvent {
    State(LiveState),
    /// RTT inferred from presence counters (send_counter echoed as last_rx_counter).
    PresenceRtt(Duration),
    Clipboard {
        generation: u64,
        text: String,
    },
}

/// Heartbeat schedule from link.md.
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    pub idle_interval: Duration,
    pub active_interval: Duration,
    pub active_window: Duration,
    pub idle_miss: Duration,
    pub active_miss: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            idle_interval: Duration::from_secs(10),
            active_interval: Duration::from_secs(1),
            active_window: Duration::from_secs(5),
            idle_miss: Duration::from_secs(3),
            active_miss: Duration::from_secs(1),
        }
    }
}

/// Datagram echo histogram: class `input`, 64-byte bodies, 1000 samples.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    pub count: usize,
    pub body_len: usize,
    pub warmup: usize,
    pub reply_timeout: Duration,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            count: 1000,
            body_len: 64,
            warmup: 20,
            reply_timeout: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EchoHistogram {
    pub n: usize,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
}

impl EchoHistogram {
    pub fn p50_ms(&self) -> f64 {
        ms(self.p50)
    }
    pub fn p95_ms(&self) -> f64 {
        ms(self.p95)
    }
    pub fn p99_ms(&self) -> f64 {
        ms(self.p99)
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

pub fn percentile(sorted: &[Duration], p: u8) -> Duration {
    assert!(!sorted.is_empty());
    let i = ((sorted.len() - 1) * p as usize) / 100;
    sorted[i]
}

/// Loopback M0 bar: datagram-echo p95 under 2 ms. LAN bar is 15 ms.
pub fn echo_p95_budget(loopback: bool) -> Duration {
    if loopback {
        Duration::from_millis(2)
    } else {
        Duration::from_millis(15)
    }
}

#[derive(Debug, Clone)]
pub struct LiveConfig {
    pub heartbeat: HeartbeatConfig,
    /// Echo class `input` probes (kind 0) so a `--bench-echo` peer can measure RTT.
    pub echo_input: bool,
    pub bench: Option<BenchConfig>,
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            heartbeat: HeartbeatConfig::default(),
            echo_input: true,
            bench: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LiveOutcome {
    pub state: LiveState,
    pub echo: Option<EchoHistogram>,
}

const PROBE: u8 = 0;
const REPLY: u8 = 1;

/// Runs until the link dies, or until `--bench-echo` has its 1000 samples.
pub async fn run(
    link: &Link,
    cfg: LiveConfig,
    mut on_event: impl FnMut(LiveEvent),
) -> Result<LiveOutcome, LinkError> {
    let mut state = LiveState::Established;
    on_event(LiveEvent::State(state));

    let mut send_counter = 0u64;
    let mut last_rx_counter = 0u64;
    let mut sent_at: VecDeque<(u64, Instant)> = VecDeque::new();
    let mut last_presence_rx = Instant::now();
    let mut last_activity = Instant::now();
    let mut next_presence = Instant::now();
    let mut clipboard_generation = 0u64;

    let mut bench_seq = 0u64;
    let mut bench_inflight: Option<(u64, Instant)> = None;
    let mut bench_deadline = None;
    let mut samples: Vec<Duration> = Vec::new();

    loop {
        let now = Instant::now();
        let active = now.saturating_duration_since(last_activity) <= cfg.heartbeat.active_window;
        let miss = if active {
            cfg.heartbeat.active_miss
        } else {
            cfg.heartbeat.idle_miss
        };
        let next_miss = last_presence_rx + miss;

        tokio::select! {
            msg = link.recv() => {
                let msg = match msg {
                    Err(LinkError::Closed) => {
                        return Ok(LiveOutcome { state, echo: None });
                    }
                    Err(e) => return Err(e),
                    Ok(m) => m,
                };
                handle_message(
                    link,
                    &cfg,
                    msg,
                    &mut last_rx_counter,
                    &mut last_presence_rx,
                    &mut last_activity,
                    &mut sent_at,
                    &mut clipboard_generation,
                    &mut bench_inflight,
                    &mut bench_deadline,
                    &mut samples,
                    &mut state,
                    &mut on_event,
                )?;
                if let Some(b) = &cfg.bench {
                    // Wait for a presence so the peer drain is running; datagrams are unreliable.
                    if last_rx_counter > 0
                        && bench_inflight.is_none()
                        && samples.len() < b.warmup + b.count
                    {
                        last_activity = Instant::now();
                        send_probe(
                            link,
                            &cfg,
                            &mut bench_seq,
                            &mut bench_inflight,
                            &mut bench_deadline,
                        )?;
                    } else if samples.len() >= b.warmup + b.count {
                        return Ok(LiveOutcome {
                            state,
                            echo: Some(histogram(&samples[b.warmup..])?),
                        });
                    }
                }
            }
            _ = sleep_until(next_presence.into()) => {
                send_counter += 1;
                let body = Presence::new(send_counter, last_rx_counter, active).to_bytes();
                link.send(Class::Presence, Flags::NONE, &body).await?;
                sent_at.push_back((send_counter, Instant::now()));
                while sent_at.len() > 16 {
                    sent_at.pop_front();
                }
                let interval = if active {
                    cfg.heartbeat.active_interval
                } else {
                    cfg.heartbeat.idle_interval
                };
                next_presence = Instant::now() + interval;
            }
            _ = sleep_until(next_miss.into()) => {
                if state == LiveState::Established {
                    state = LiveState::Degraded;
                    on_event(LiveEvent::State(state));
                } else if state == LiveState::Degraded {
                    state = LiveState::Dialing;
                    on_event(LiveEvent::State(state));
                }
                last_presence_rx = Instant::now();
            }
            _ = sleep_until(bench_deadline.unwrap_or(far_future()).into()), if bench_deadline.is_some() => {
                return Err(LinkError::Handshake("bench-echo reply timeout".into()));
            }
        }
    }
}

fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(365 * 24 * 3600)
}

fn histogram(samples: &[Duration]) -> Result<EchoHistogram, LinkError> {
    if samples.is_empty() {
        return Err(LinkError::Handshake(
            "bench-echo produced no samples".into(),
        ));
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    Ok(EchoHistogram {
        n: sorted.len(),
        p50: percentile(&sorted, 50),
        p95: percentile(&sorted, 95),
        p99: percentile(&sorted, 99),
    })
}

fn send_probe(
    link: &Link,
    cfg: &LiveConfig,
    seq: &mut u64,
    inflight: &mut Option<(u64, Instant)>,
    deadline: &mut Option<Instant>,
) -> Result<(), LinkError> {
    let Some(bench) = &cfg.bench else {
        return Ok(());
    };
    if bench.body_len < 9 {
        return Err(LinkError::Protocol(
            "bench-echo body must be at least 9 bytes".into(),
        ));
    }
    *seq += 1;
    let mut body = vec![0u8; bench.body_len];
    body[0] = PROBE;
    body[1..9].copy_from_slice(&seq.to_le_bytes());
    link.send_datagram(&body)?;
    let now = Instant::now();
    *inflight = Some((*seq, now));
    *deadline = Some(now + bench.reply_timeout);
    Ok(())
}

fn handle_message(
    link: &Link,
    cfg: &LiveConfig,
    msg: Message,
    last_rx_counter: &mut u64,
    last_presence_rx: &mut Instant,
    last_activity: &mut Instant,
    sent_at: &mut VecDeque<(u64, Instant)>,
    clipboard_generation: &mut u64,
    bench_inflight: &mut Option<(u64, Instant)>,
    bench_deadline: &mut Option<Instant>,
    samples: &mut Vec<Duration>,
    state: &mut LiveState,
    on_event: &mut impl FnMut(LiveEvent),
) -> Result<(), LinkError> {
    match msg.class {
        Class::Presence => {
            let Some(p) = Presence::from_bytes(&msg.body) else {
                return Ok(());
            };
            *last_rx_counter = p.send_counter;
            *last_presence_rx = Instant::now();
            if *state != LiveState::Established {
                *state = LiveState::Established;
                on_event(LiveEvent::State(*state));
            }
            if let Some((_, t0)) = sent_at.iter().find(|(c, _)| *c == p.last_rx_counter) {
                on_event(LiveEvent::PresenceRtt(t0.elapsed()));
            }
        }
        Class::Clipboard => {
            *last_activity = Instant::now();
            let Some(clip) = Clipboard::from_bytes(&msg.body) else {
                return Ok(());
            };
            if !clip.should_apply(*clipboard_generation) {
                return Ok(());
            }
            *clipboard_generation = clip.generation;
            if let Some(text) = clip.text_str() {
                on_event(LiveEvent::Clipboard {
                    generation: clip.generation,
                    text: text.to_string(),
                });
            }
        }
        Class::Input => {
            *last_activity = Instant::now();
            if msg.body.first() == Some(&PROBE) && cfg.echo_input {
                let mut reply = msg.body;
                reply[0] = REPLY;
                link.send_datagram(&reply)?;
            } else if msg.body.first() == Some(&REPLY) {
                if let Some((seq, t0)) = *bench_inflight {
                    let got = msg
                        .body
                        .get(1..9)
                        .and_then(|b| b.try_into().ok())
                        .map(u64::from_le_bytes);
                    if got == Some(seq) {
                        samples.push(t0.elapsed());
                        *bench_inflight = None;
                        *bench_deadline = None;
                    }
                }
            }
        }
        Class::Control | Class::Notify | Class::Handoff | Class::BlobMeta | Class::Hello => {}
    }
    Ok(())
}
