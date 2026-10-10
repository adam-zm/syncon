//! `pair`, `pair-with`, and the post-pair session (heartbeats, echo, reconnect).

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use syncon_crypto::{Keystore, Pin};
use syncon_proto::{FeatureBits, Role};
use syncon_session::established::{echo_p95_budget, BenchConfig, LiveConfig};
use syncon_session::pairing::{self, PairPayload};
use syncon_session::supervisor::{maintain, CacheSource, MaintainConfig, SessionEvent};
use syncon_session::{Link, Transport, TransportConfig, Trust};

use crate::Cli;

type Res = Result<(), Box<dyn std::error::Error>>;

async fn confirm_sas(cli: &Cli, link: &Link) -> Result<bool, Box<dyn std::error::Error>> {
    println!("SAS: {}", link.sas().display());
    if cli.accept_sas {
        println!("--accept-sas: confirming without a human (dev only)");
        return Ok(true);
    }
    println!("Does the other device show the same code? [y/N] ");
    let answer = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map(|_| line)
    })
    .await??;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

fn pin_from_link(link: &Link, name: String, last_rt: SocketAddr, last_bk: Option<SocketAddr>) -> Pin {
    Pin {
        identity: *link.peer(),
        name,
        last_rt: Some(last_rt),
        last_bk,
        clipboard_generation: 0,
        features: 0,
    }
}

async fn conclude(
    cli: &Cli,
    store: &Keystore,
    link: &Link,
    timeout: Duration,
    last_rt: SocketAddr,
    last_bk: Option<SocketAddr>,
) -> Result<Pin, Box<dyn std::error::Error>> {
    let confirmed = confirm_sas(cli, link).await?;
    let role = match link.peer_hello().role {
        Role::Desktop => "desktop",
        Role::Phone => "phone",
        Role::Unknown => "device",
    };
    match pairing::finish(link, confirmed, timeout).await {
        Ok(_) => {
            let pin = pin_from_link(link, role.to_string(), last_rt, last_bk);
            store.save_pin(&pin)?;
            println!("Paired with {} ({})", pin.fingerprint_hex(), pin.name);
            Ok(pin)
        }
        Err(e) => Err(format!("pairing failed, nothing was stored: {e}").into()),
    }
}

fn transport_config(
    realtime: SocketAddr,
    bulk: SocketAddr,
    trust: Trust,
    cli: &Cli,
    role: Role,
) -> TransportConfig {
    let mut cfg = TransportConfig::new(realtime, bulk, trust);
    cfg.role = role;
    let mut bits = 0u32;
    if cli.bench_echo {
        bits |= FeatureBits::INPUT_DATAGRAMS;
    }
    if cli.bench_bulk {
        bits |= FeatureBits::BLOB_TRANSFER;
    }
    cfg.features = FeatureBits::new(bits);
    cfg
}

fn live_config(cli: &Cli) -> LiveConfig {
    let mut cfg = LiveConfig::default();
    if cli.bench_echo {
        cfg.bench = Some(BenchConfig::default());
    }
    cfg
}

async fn serve_session(
    cli: &Cli,
    store: &Keystore,
    transport: &Transport,
    pin: Pin,
    cache_source: CacheSource,
    trust_slot: Option<Arc<Mutex<Trust>>>,
    initial: Option<Link>,
) -> Res {
    if let Some(slot) = trust_slot {
        *slot.lock().unwrap() = Trust::only(pin.identity.sign_pub);
    }
    eprintln!("Established with {}", pin.fingerprint_hex());

    let maintain_cfg = MaintainConfig {
        peer: pin.identity,
        cached_rt: pin.last_rt,
        cache_source,
        live: live_config(cli),
        reconnect: !cli.bench_echo && !cli.bench_bulk,
        dial_timeout: Duration::from_millis(250),
    };

    let events = |ev: SessionEvent| match ev {
        SessionEvent::State(s) => {
            eprintln!("state {s:?}");
        }
        SessionEvent::PresenceRtt(d) => eprintln!("presence rtt={d:?}"),
        SessionEvent::Clipboard { generation, text } => {
            eprintln!("clipboard gen={generation} len={}", text.len());
        }
        SessionEvent::CachedAddress(addr) => {
            let mut p = pin.clone();
            p.last_rt = Some(addr);
            let _ = store.save_pin(&p);
            eprintln!("cached {addr}");
        }
    };

    let session = maintain(transport, maintain_cfg, initial, events);
    let outcome = if cli.bench_bulk {
        let bulk = run_bulk(transport, pin.identity.sign_pub, pin.last_bk);
        let (outcome, bulk) = tokio::join!(session, bulk);
        bulk?;
        outcome?
    } else {
        session.await?
    };

    if let Some(h) = outcome.echo {
        println!(
            "echo n={} p50={:.3}ms p95={:.3}ms p99={:.3}ms",
            h.n,
            h.p50_ms(),
            h.p95_ms(),
            h.p99_ms()
        );
        let budget = if cli.bench_bulk {
            Duration::from_millis(5)
        } else {
            echo_p95_budget(
                pin.last_rt
                    .map(|a| a.ip().is_loopback())
                    .unwrap_or(true),
            )
        };
        if h.p95 > budget {
            return Err(format!(
                "echo p95 {:.3}ms exceeds budget {:.3}ms",
                h.p95_ms(),
                budget.as_secs_f64() * 1000.0
            )
            .into());
        }
    }
    Ok(())
}

async fn run_bulk(
    transport: &Transport,
    peer: [u8; 32],
    cached_bk: Option<SocketAddr>,
) -> Result<(), syncon_session::LinkError> {
    const N: usize = 50 * 1024 * 1024;
    eprintln!("bulk transfer 50 MiB zeros...");
    if let Some(addr) = cached_bk {
        let bulk = transport.dial_bulk(addr, peer).await?;
        bulk.send_zeros(N).await?;
    } else {
        let bulk = transport.accept_bulk(peer).await?;
        bulk.recv_zeros(N).await?;
    }
    eprintln!("bulk transfer done");
    Ok(())
}

pub async fn pair(
    cli: &Cli,
    store: &Keystore,
    out: Option<&Path>,
    host: Option<IpAddr>,
    timeout_secs: u64,
) -> Res {
    let realtime: SocketAddr = cli.realtime_addr.parse()?;
    let bulk: SocketAddr = cli.bulk_addr.parse()?;
    let host = match host {
        Some(h) => h,
        None if !realtime.ip().is_unspecified() => realtime.ip(),
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    let identity = Arc::new(store.load_or_create_identity()?);
    let (trust, slot) = Trust::cell(Trust::any());
    let cfg = transport_config(realtime, bulk, trust, cli, Role::Desktop);
    let transport = Transport::bind(identity.clone(), cfg)?;

    let payload = PairPayload {
        sign_pub: identity.sign_pub,
        dh_pub: identity.dh_pub,
        host,
        realtime_port: transport.realtime_addr().port(),
        bulk_port: transport.bulk_addr().port(),
        name: cli.name.clone(),
    };
    let url = payload.to_url();
    if let Some(path) = out {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        writeln!(f, "{url}")?;
    }
    println!("{url}");
    println!("Pairing mode for {timeout_secs} s...");

    let window = Duration::from_secs(timeout_secs);
    let link = pairing::accept(&transport, window).await?;
    let last_rt = link.remote_addr();
    let result = conclude(cli, store, &link, window, last_rt, None).await;
    if let Some(path) = out {
        let _ = std::fs::remove_file(path);
    }
    let pin = result?;
    serve_session(
        cli,
        store,
        &transport,
        pin,
        CacheSource::Accepted,
        Some(slot),
        Some(link),
    )
    .await
}

pub async fn pair_with(cli: &Cli, store: &Keystore, file: &Path, timeout_secs: u64) -> Res {
    let payload = PairPayload::parse(&std::fs::read_to_string(file)?)?;
    let identity = Arc::new(store.load_or_create_identity()?);
    let any = match payload.host {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let realtime: SocketAddr = cli
        .realtime_addr
        .parse()
        .unwrap_or_else(|_| (any, 0).into());
    let bulk_bind: SocketAddr = cli.bulk_addr.parse().unwrap_or_else(|_| (any, 0).into());
    // pair-with defaults are the daemon listen ports; use ephemeral unless the user overrode them.
    let (rt, bk) = if cli.realtime_addr == "0.0.0.0:47920" {
        ((any, 0).into(), (any, 0).into())
    } else {
        (realtime, bulk_bind)
    };
    let cfg = transport_config(
        rt,
        bk,
        Trust::only(payload.sign_pub),
        cli,
        Role::Phone,
    );
    let transport = Transport::bind(identity, cfg)?;
    println!("Dialing {} ({})", payload.name, payload.host);
    let link = pairing::dial(&transport, &payload).await?;
    let last_rt = SocketAddr::new(payload.host, payload.realtime_port);
    let last_bk = Some(SocketAddr::new(payload.host, payload.bulk_port));
    let pin = conclude(
        cli,
        store,
        &link,
        Duration::from_secs(timeout_secs),
        last_rt,
        last_bk,
    )
    .await?;
    serve_session(
        cli,
        store,
        &transport,
        pin,
        CacheSource::Advertised,
        None,
        Some(link),
    )
    .await
}

pub async fn run_paired(cli: &Cli, store: &Keystore) -> Res {
    let pins = store.list_pins()?;
    let pin = pins
        .into_iter()
        .next()
        .ok_or("not paired; run `pair` / `pair-with` first")?;
    let identity = Arc::new(store.load_or_create_identity()?);
    let realtime: SocketAddr = cli.realtime_addr.parse()?;
    let bulk: SocketAddr = cli.bulk_addr.parse()?;
    let cfg = transport_config(
        realtime,
        bulk,
        Trust::only(pin.identity.sign_pub),
        cli,
        Role::Unknown,
    );
    let transport = Transport::bind(identity, cfg)?;
    eprintln!(
        "run: fingerprint {} peer {} cached {:?}",
        transport.identity().fingerprint_hex(),
        pin.fingerprint_hex(),
        pin.last_rt
    );
    let source = if pin.last_rt.is_some() {
        CacheSource::Advertised
    } else {
        CacheSource::Accepted
    };
    serve_session(cli, store, &transport, pin, source, None, None).await
}
