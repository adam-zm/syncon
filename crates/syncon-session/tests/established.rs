use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use syncon_crypto::Identity;
use syncon_proto::{Class, Clipboard, FeatureBits, Flags};
use syncon_session::established::{
    self, BenchConfig, HeartbeatConfig, LiveConfig, LiveEvent, LiveState,
};
use syncon_session::{Link, Transport, TransportConfig, Trust};
use tokio::sync::Notify;

fn lo() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn node(features: FeatureBits) -> Transport {
    let mut cfg = TransportConfig::new(lo(), lo(), Trust::any());
    cfg.features = features;
    Transport::bind(Arc::new(Identity::generate().unwrap()), cfg).unwrap()
}

async fn pair(features: FeatureBits) -> (Transport, Transport, Link, Link) {
    let a = node(features);
    let b = node(features);
    let a_key = a.identity().sign_pub;
    let (la, lb) = tokio::join!(a.accept(), b.dial(a.realtime_addr(), Trust::only(a_key)));
    (a, b, la.unwrap(), lb.unwrap())
}

fn fast_hb() -> HeartbeatConfig {
    HeartbeatConfig {
        idle_interval: Duration::from_millis(20),
        active_interval: Duration::from_millis(10),
        active_window: Duration::from_millis(50),
        idle_miss: Duration::from_millis(80),
        active_miss: Duration::from_millis(40),
    }
}

fn echo_cfg() -> LiveConfig {
    LiveConfig {
        heartbeat: fast_hb(),
        echo_input: true,
        bench: None,
    }
}

#[tokio::test]
async fn presence_keeps_established_and_reports_rtt() {
    let (_a, _b, la, lb) = pair(FeatureBits::NONE).await;
    let rtts = Arc::new(Mutex::new(Vec::new()));
    let rtts_b = rtts.clone();
    let done = Arc::new(Notify::new());
    let done_b = done.clone();

    let ta = tokio::spawn(async move { established::run(&la, echo_cfg(), |_| {}).await });
    let tb = tokio::spawn(async move {
        let r = established::run(&lb, echo_cfg(), |ev| {
            if let LiveEvent::PresenceRtt(d) = ev {
                rtts_b.lock().unwrap().push(d);
                if rtts_b.lock().unwrap().len() >= 2 {
                    done_b.notify_waiters();
                }
            }
        })
        .await;
        r
    });

    tokio::time::timeout(Duration::from_secs(2), done.notified())
        .await
        .expect("presence RTT");
    ta.abort();
    tb.abort();
    let n = rtts.lock().unwrap().len();
    assert!(n >= 1, "expected presence RTT samples, got {n}");
}

#[tokio::test]
async fn missed_heartbeat_degrades() {
    let (_a, _b, la, _lb) = pair(FeatureBits::NONE).await;
    let states = Arc::new(Mutex::new(Vec::new()));
    let states_t = states.clone();
    let degraded = Arc::new(Notify::new());
    let degraded_t = degraded.clone();

    let t = tokio::spawn(async move {
        established::run(&la, echo_cfg(), |ev| {
            if let LiveEvent::State(s) = ev {
                states_t.lock().unwrap().push(s);
                if s == LiveState::Degraded {
                    degraded_t.notify_waiters();
                }
            }
        })
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), degraded.notified())
        .await
        .expect("degraded");
    t.abort();
    let seen = states.lock().unwrap().clone();
    assert!(seen.contains(&LiveState::Established));
    assert!(seen.contains(&LiveState::Degraded));
}

#[tokio::test]
async fn clipboard_lower_generation_is_ignored() {
    let features = FeatureBits::new(FeatureBits::CLIPBOARD_TEXT);
    let (_a, _b, la, lb) = pair(features).await;
    let la = Arc::new(la);
    let applied = Arc::new(Mutex::new(Vec::new()));
    let applied_t = applied.clone();
    let got = Arc::new(Notify::new());
    let got_t = got.clone();

    let sender = la.clone();
    let ta = tokio::spawn(async move { established::run(&la, echo_cfg(), |_| {}).await });
    let tb = tokio::spawn(async move {
        established::run(&lb, echo_cfg(), |ev| {
            if let LiveEvent::Clipboard { generation, text } = ev {
                applied_t.lock().unwrap().push((generation, text));
                if applied_t.lock().unwrap().len() >= 2 {
                    got_t.notify_waiters();
                }
            }
        })
        .await
    });

    // Give the drain loops a moment to start.
    tokio::time::sleep(Duration::from_millis(20)).await;
    sender
        .send(
            Class::Clipboard,
            Flags::NONE,
            &Clipboard::new(10, b"ten".to_vec()).to_bytes(),
        )
        .await
        .unwrap();
    sender
        .send(
            Class::Clipboard,
            Flags::NONE,
            &Clipboard::new(5, b"five".to_vec()).to_bytes(),
        )
        .await
        .unwrap();
    sender
        .send(
            Class::Clipboard,
            Flags::NONE,
            &Clipboard::new_sensitive(11, b"secret".to_vec()).to_bytes(),
        )
        .await
        .unwrap();
    sender
        .send(
            Class::Clipboard,
            Flags::NONE,
            &Clipboard::new(12, b"twelve".to_vec()).to_bytes(),
        )
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), got.notified())
        .await
        .expect("clipboard apply");
    ta.abort();
    tb.abort();
    let got = applied.lock().unwrap().clone();
    assert_eq!(got, vec![(10, "ten".into()), (12, "twelve".into()),]);
}

#[tokio::test]
async fn bench_echo_p95_under_2ms_on_loopback() {
    let features = FeatureBits::new(FeatureBits::INPUT_DATAGRAMS);
    let (_a, _b, la, lb) = pair(features).await;
    let echo = echo_cfg();
    let mut bench = echo.clone();
    bench.bench = Some(BenchConfig {
        count: 1000,
        body_len: 64,
        warmup: 20,
        reply_timeout: Duration::from_secs(1),
    });

    let responder = tokio::spawn(async move { established::run(&la, echo, |_| {}).await });
    let histogram = established::run(&lb, bench, |_| {})
        .await
        .unwrap()
        .echo
        .expect("histogram");
    responder.abort();

    assert_eq!(histogram.n, 1000);
    assert!(
        histogram.p95 <= Duration::from_millis(2),
        "p50={:.3}ms p95={:.3}ms p99={:.3}ms",
        histogram.p50_ms(),
        histogram.p95_ms(),
        histogram.p99_ms()
    );
}
