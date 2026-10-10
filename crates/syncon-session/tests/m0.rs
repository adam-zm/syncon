use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use syncon_crypto::{Identity, Keystore, Pin, PublicIdentity};
use syncon_proto::{Class, Envelope, FeatureBits, Flags, Header};
use syncon_session::established::{BenchConfig, LiveConfig};
use syncon_session::supervisor::{
    maintain, CacheSource, MaintainConfig, SessionEvent, SupervisorState,
};
use syncon_session::{Link, LinkError, Transport, TransportConfig, Trust};

fn lo() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn bind(
    id: Arc<Identity>,
    rt: SocketAddr,
    bk: SocketAddr,
    trust: Trust,
    features: FeatureBits,
) -> Transport {
    let mut cfg = TransportConfig::new(rt, bk, trust);
    cfg.features = features;
    Transport::bind(id, cfg).unwrap()
}

async fn handshake(features: FeatureBits) -> (Transport, Transport, Link, Link) {
    let a = bind(
        Arc::new(Identity::generate().unwrap()),
        lo(),
        lo(),
        Trust::any(),
        features,
    );
    let b = bind(
        Arc::new(Identity::generate().unwrap()),
        lo(),
        lo(),
        Trust::any(),
        features,
    );
    let a_key = a.identity().sign_pub;
    let (la, lb) = tokio::join!(a.accept(), b.dial(a.realtime_addr(), Trust::only(a_key)));
    (a, b, la.unwrap(), lb.unwrap())
}

fn echo_live() -> LiveConfig {
    LiveConfig {
        echo_input: true,
        bench: None,
        heartbeat: syncon_session::HeartbeatConfig {
            idle_interval: Duration::from_millis(20),
            active_interval: Duration::from_millis(10),
            active_window: Duration::from_millis(50),
            idle_miss: Duration::from_millis(80),
            active_miss: Duration::from_millis(40),
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_from_cached_address_under_1s() {
    let features = FeatureBits::NONE;
    let id_a = Arc::new(Identity::generate().unwrap());
    let id_b = Arc::new(Identity::generate().unwrap());
    let a = bind(
        id_a.clone(),
        lo(),
        lo(),
        Trust::only(id_b.sign_pub),
        features,
    );
    let b = bind(
        id_b.clone(),
        lo(),
        lo(),
        Trust::only(id_a.sign_pub),
        features,
    );
    let a_rt = a.realtime_addr();
    let b_rt = b.realtime_addr();

    let a_cfg = MaintainConfig {
        peer: PublicIdentity::new(id_b.sign_pub, id_b.dh_pub),
        cached_rt: Some(b_rt),
        cache_source: CacheSource::Advertised,
        live: echo_live(),
        reconnect: true,
        dial_timeout: Duration::from_millis(250),
    };
    let b_cfg = MaintainConfig {
        peer: PublicIdentity::new(id_a.sign_pub, id_a.dh_pub),
        cached_rt: Some(a_rt),
        cache_source: CacheSource::Advertised,
        live: echo_live(),
        reconnect: true,
        dial_timeout: Duration::from_millis(250),
    };

    let a_states = Arc::new(Mutex::new(Vec::new()));
    let a_states_t = a_states.clone();
    let ta = tokio::spawn(async move {
        maintain(&a, a_cfg, None, move |ev| {
            if let SessionEvent::State(s) = ev {
                a_states_t.lock().unwrap().push(s);
            }
        })
        .await
    });

    let tb = tokio::spawn(async move { maintain(&b, b_cfg, None, |_| {}).await });

    async fn wait_for(states: &Mutex<Vec<SupervisorState>>, pred: impl Fn(&[SupervisorState]) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if pred(&states.lock().unwrap()) {
                return;
            }
            if Instant::now() > deadline {
                panic!("timeout waiting for state, saw {:?}", states.lock().unwrap());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    wait_for(&a_states, |s| s.contains(&SupervisorState::Established)).await;

    tb.abort();
    let _ = tb.await;
    wait_for(&a_states, |s| {
        s.iter().any(|x| *x == SupervisorState::Established)
            && s.iter().any(|x| *x == SupervisorState::Dialing)
    })
    .await;

    let listening = Instant::now();
    // Restarted peer binds fresh ports and dials the survivor's cached listen address.
    let b2 = bind(
        id_b.clone(),
        lo(),
        lo(),
        Trust::only(id_a.sign_pub),
        features,
    );
    let b2_cfg = MaintainConfig {
        peer: PublicIdentity::new(id_a.sign_pub, id_a.dh_pub),
        cached_rt: Some(a_rt),
        cache_source: CacheSource::Advertised,
        live: echo_live(),
        reconnect: true,
        dial_timeout: Duration::from_millis(250),
    };
    let tb2 = tokio::spawn(async move { maintain(&b2, b2_cfg, None, |_| {}).await });

    wait_for(&a_states, |s| {
        s.iter()
            .filter(|x| **x == SupervisorState::Established)
            .count()
            >= 2
    })
    .await;
    let elapsed = listening.elapsed();
    ta.abort();
    tb2.abort();
    assert!(
        elapsed < Duration::from_secs(1),
        "reconnect took {elapsed:?}, want < 1s; states={:?}",
        a_states.lock().unwrap()
    );
}

#[tokio::test]
async fn aead_failure_closes_and_keeps_pin() {
    let dir = std::env::temp_dir().join(format!(
        "syncon-aead-pin-{}",
        std::process::id()
    ));
    let ks = Keystore::open(&dir).unwrap();
    let (_a, _b, la, lb) = handshake(FeatureBits::NONE).await;
    let pin = Pin {
        identity: *lb.peer(),
        name: "peer".into(),
        last_rt: Some(la.remote_addr()),
        last_bk: None,
        clipboard_generation: 0,
        features: 0,
    };
    ks.save_pin(&pin).unwrap();
    let env = Envelope::new(Header::new(Class::Clipboard, Flags::NONE, 1, 32), vec![0u8; 32])
        .unwrap();
    lb.send_raw_for_test(&env.to_bytes()).await.unwrap();
    assert!(matches!(la.recv().await, Err(LinkError::Aead)));
    assert!(ks.find_pin(&pin.identity.sign_pub).unwrap().is_some());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_50mib_does_not_push_echo_p95_above_5ms() {
    let features = FeatureBits::new(FeatureBits::INPUT_DATAGRAMS);
    let (a, b, la, lb) = handshake(features).await;
    let a_pub = a.identity().sign_pub;
    let b_pub = b.identity().sign_pub;
    let a_bk = a.bulk_addr();

    const N: usize = 50 * 1024 * 1024;
    let bulk = tokio::spawn(async move {
        let (ba, bb) = tokio::join!(a.accept_bulk(b_pub), b.dial_bulk(a_bk, a_pub));
        let (ba, bb) = (ba.unwrap(), bb.unwrap());
        tokio::join!(ba.recv_zeros(N), bb.send_zeros(N))
    });

    let echoer = {
        let live = LiveConfig {
            echo_input: true,
            bench: None,
            ..echo_live()
        };
        tokio::spawn(async move { syncon_session::established::run(&la, live, |_| {}).await })
    };
    let mut bench = echo_live();
    bench.bench = Some(BenchConfig {
        count: 1000,
        body_len: 64,
        warmup: 20,
        reply_timeout: Duration::from_secs(2),
    });
    let histogram = syncon_session::established::run(&lb, bench, |_| {})
        .await
        .unwrap()
        .echo
        .expect("histogram");
    let (recv, send) = bulk.await.unwrap();
    recv.unwrap();
    send.unwrap();
    echoer.abort();

    assert_eq!(histogram.n, 1000);
    assert!(
        histogram.p95 <= Duration::from_millis(5),
        "p50={:.3}ms p95={:.3}ms p99={:.3}ms",
        histogram.p50_ms(),
        histogram.p95_ms(),
        histogram.p99_ms()
    );
}
