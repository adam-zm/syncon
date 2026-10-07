//! `pair` and `pair-with`: the human-facing side of pairing.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use syncon_crypto::{Keystore, Pin};
use syncon_proto::Role;
use syncon_session::pairing::{self, PairPayload};
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

async fn conclude(cli: &Cli, store: &Keystore, link: &Link, timeout: Duration) -> Res {
    let confirmed = confirm_sas(cli, link).await?;
    let role = match link.peer_hello().role {
        Role::Desktop => "desktop",
        Role::Phone => "phone",
        Role::Unknown => "device",
    };
    match pairing::finish(link, confirmed, timeout).await {
        Ok(peer) => {
            let pin = Pin { identity: peer, name: role.to_string() };
            store.save_pin(&pin)?;
            println!("Paired with {} ({})", pin.fingerprint_hex(), pin.name);
            Ok(())
        }
        Err(e) => Err(format!("pairing failed, nothing was stored: {e}").into()),
    }
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
        None => return Err("bound to an unspecified address; pass --host with the address to advertise".into()),
    };
    let identity = Arc::new(store.load_or_create_identity()?);
    let mut cfg = TransportConfig::new(realtime, bulk, Trust::any());
    cfg.role = Role::Desktop;
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
    let result = conclude(cli, store, &link, window).await;
    if let Some(path) = out {
        let _ = std::fs::remove_file(path);
    }
    result
}

pub async fn pair_with(cli: &Cli, store: &Keystore, file: &Path, timeout_secs: u64) -> Res {
    let payload = PairPayload::parse(&std::fs::read_to_string(file)?)?;
    let identity = Arc::new(store.load_or_create_identity()?);
    let any = match payload.host {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let mut cfg = TransportConfig::new((any, 0).into(), (any, 0).into(), Trust::only(payload.sign_pub));
    cfg.role = Role::Phone;
    let transport = Transport::bind(identity, cfg)?;
    println!("Dialing {} ({})", payload.name, payload.host);
    let link = pairing::dial(&transport, &payload).await?;
    conclude(cli, store, &link, Duration::from_secs(timeout_secs)).await
}
