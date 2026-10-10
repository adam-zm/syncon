//! Syncon daemon for Linux: config, key store files, wires discovery to session, stdout metrics in M0.
//!
//! This binary must not depend on UI toolkits.

mod pair_cli;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use syncon_crypto::Keystore;

/// Syncon daemon for Linux.
#[derive(Debug, Parser)]
#[command(name = "syncon-linkd")]
#[command(about = "Syncon daemon for Linux", long_about = None)]
struct Cli {
    /// Enable verbose output.
    #[arg(short, long)]
    verbose: bool,

    /// Bind address for realtime connection.
    #[arg(long, default_value = "0.0.0.0:47920")]
    realtime_addr: String,

    /// Bind address for bulk connection.
    #[arg(long, default_value = "0.0.0.0:47921")]
    bulk_addr: String,

    /// Display name for this device.
    #[arg(short, long, default_value = "Syncon Device")]
    name: String,

    /// Key store directory (default: $XDG_DATA_HOME/link, else ~/.local/share/link).
    #[arg(long)]
    dir: Option<PathBuf>,

    /// Development mode: key store in a temp dir (deleted on exit) unless --dir is given.
    #[arg(long)]
    dev: bool,

    /// Confirm the pairing SAS without asking a human. Refused without `--dev`.
    #[arg(long)]
    accept_sas: bool,

    /// After pairing, send 1000 class-input datagrams and print p50/p95/p99.
    #[arg(long)]
    bench_echo: bool,

    /// Concurrent 50 MiB bulk transfer of zeros (with `--bench-echo`, p95 bar is 5 ms).
    #[arg(long)]
    bench_bulk: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the daemon for an already-paired peer (reconnect from cached address).
    Run,
    /// Create the identity if missing and show it.
    GenIdentity,
    /// Show the identity and paired peers.
    ShowIdentity,
    /// Enter pairing mode: write the link://pair payload and wait for one peer.
    Pair {
        /// File to write the payload to (it is also printed).
        #[arg(long)]
        out: Option<PathBuf>,
        /// IP address the peer should dial (default: the realtime bind address).
        #[arg(long)]
        host: Option<std::net::IpAddr>,
        /// Pairing window in seconds.
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
    },
    /// Pair with a device that is in pairing mode, using its payload file.
    PairWith {
        /// File containing the link://pair URL.
        file: PathBuf,
        /// Pairing window in seconds.
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.accept_sas && !cli.dev {
        return Err("--accept-sas is only allowed together with --dev".into());
    }

    // Held for the process lifetime so a --dev store is removed on exit.
    let (store, _dev_dir) = open_store(&cli)?;
    if cli.dev {
        eprintln!("dev key store: {}", store.dir().display());
    }
    let _ = cli.verbose;

    match cli.command {
        Commands::GenIdentity | Commands::ShowIdentity => {
            let identity = store.load_or_create_identity()?;
            println!("Key store: {}", store.dir().display());
            println!("  Fingerprint: {}", identity.fingerprint_hex());
            println!("  Sign Public: {}", hex::encode(identity.sign_pub));
            println!("  DH Public: {}", hex::encode(identity.dh_pub));
            for pin in store.list_pins()? {
                println!("  Paired: {} ({})", pin.fingerprint_hex(), pin.name);
            }
            Ok(())
        }
        Commands::Pair {
            ref out,
            host,
            timeout_secs,
        } => pair_cli::pair(&cli, &store, out.as_deref(), host, timeout_secs).await,
        Commands::PairWith {
            ref file,
            timeout_secs,
        } => pair_cli::pair_with(&cli, &store, file, timeout_secs).await,
        Commands::Run => pair_cli::run_paired(&cli, &store).await,
    }
}

fn open_store(
    cli: &Cli,
) -> Result<(Keystore, Option<tempfile::TempDir>), Box<dyn std::error::Error>> {
    if cli.dev && cli.dir.is_none() {
        let tmp = tempfile::Builder::new().prefix("syncon-dev-").tempdir()?;
        return Ok((Keystore::open(tmp.path())?, Some(tmp)));
    }
    let dir = match &cli.dir {
        Some(d) => d.clone(),
        None => match std::env::var_os("XDG_DATA_HOME") {
            Some(x) if !x.is_empty() => PathBuf::from(x).join("link"),
            _ => PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set; pass --dir")?)
                .join(".local/share/link"),
        },
    };
    Ok((Keystore::open(dir)?, None))
}
