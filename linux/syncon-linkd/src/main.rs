//! Syncon daemon for Linux: config, key store files, wires discovery to session, stdout metrics in M0.
//!
//! This binary must not depend on UI toolkits.
//!
//! M0 version: Basic daemon that listens on QUIC ports and accepts connections.

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use syncon_crypto::identity::Identity;
use syncon_discovery::{AddressCache, AddressResolver, AdvertisementConfig, MdnsDaemon};
use syncon_session::supervisor::{Supervisor, SupervisorConfig, SupervisorEvent};
use tokio::sync::mpsc;

/// Default cache file path.
const DEFAULT_CACHE_FILE: &str = ".syncon_cache.json";

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
    
    /// Path to cache file.
    #[arg(long, default_value = DEFAULT_CACHE_FILE)]
    cache_file: String,
    
    /// Enable mDNS discovery.
    #[arg(long, default_value = "true")]
    enable_mdns: bool,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the daemon.
    Run,
    /// Generate a new identity.
    GenIdentity,
    /// Show the current identity.
    ShowIdentity,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::GenIdentity => {
            let identity = Identity::generate().ok_or("Failed to generate identity")?;
            println!("Generated new identity:");
            println!("  Fingerprint: {}", identity.fingerprint_hex());
            println!("  Sign Public: {}", hex::encode(identity.sign_pub));
            println!("  DH Public: {}", hex::encode(identity.dh_pub));
            Ok(())
        }
        Commands::ShowIdentity => {
            // Would load from keystore file
            println!("Identity display not yet implemented - need keystore file path");
            Ok(())
        }
        Commands::Run => {
            run_daemon(cli).await?;
            Ok(())
        }
    }
}

/// Runs the syncon daemon.
async fn run_daemon(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Parse addresses
    let realtime_addr: SocketAddr = cli.realtime_addr.parse()?;
    let bulk_addr: SocketAddr = cli.bulk_addr.parse()?;
    
    // Generate or load identity
    let identity = Identity::generate().ok_or("Failed to generate identity")?;
    let fingerprint = identity.fingerprint_hex();
    
    if cli.verbose {
        println!("Starting syncon-linkd");
        println!("  Fingerprint: {}", fingerprint);
        println!("  Realtime: {}", realtime_addr);
        println!("  Bulk: {}", bulk_addr);
        println!("  Name: {}", cli.name);
    }
    
    // Initialize address cache
    let cache = AddressCache::with_persistence(&cli.cache_file).unwrap_or_else(|e| {
        if cli.verbose {
            println!("Warning: Could not load cache: {}", e);
        }
        AddressCache::new()
    });
    
    let _address_resolver = AddressResolver::new(cache);
    
    // Initialize mDNS if enabled
    let _mdns_daemon = if cli.enable_mdns {
        let daemon = MdnsDaemon::new()?;
        
        // Advertise our service
        let config = AdvertisementConfig::new(&cli.name, &fingerprint)
            .with_realtime_port(realtime_addr.port())
            .with_bulk_port(bulk_addr.port());
        
        // Use the IP from the bind address
        let advertise_ip = Some(realtime_addr.ip());
        
        daemon.advertise(config, advertise_ip)?;
        
        if cli.verbose {
            println!("  mDNS advertisement started");
        }
        
        Some(daemon)
    } else {
        None
    };
    
    // Create supervisor
    let config = SupervisorConfig {
        local_fingerprint: fingerprint,
        realtime_addr,
        bulk_addr,
        enable_mdns: cli.enable_mdns,
        cache_path: Some(cli.cache_file.clone()),
    };
    
    let (_event_sender, mut event_receiver): (mpsc::Sender<SupervisorEvent>, mpsc::Receiver<SupervisorEvent>) = mpsc::channel(100);
    
    let _supervisor = Supervisor::new(config).await?;
    
    if cli.verbose {
        println!("  Supervisor started");
        println!("\nWaiting for connections... (Ctrl+C to exit)");
    }
    
    // Main event loop - simplified for M0
    // In a real implementation, we'd run the supervisor properly
    loop {
        tokio::select! {
            Some(event) = event_receiver.recv() => {
                handle_event(event, cli.verbose);
            }
        }
    }
}

/// Handles supervisor events.
fn handle_event(event: SupervisorEvent, verbose: bool) {
    match event {
        SupervisorEvent::StateChanged { fingerprint, state } => {
            if verbose {
                println!("[EVENT] State changed for {}: {:?}", fingerprint, state);
            }
        }
        SupervisorEvent::SessionEstablished { fingerprint } => {
            if verbose {
                println!("[EVENT] Session established with {}", fingerprint);
            }
        }
        SupervisorEvent::SessionLost { fingerprint } => {
            if verbose {
                println!("[EVENT] Session lost with {}", fingerprint);
            }
        }
        SupervisorEvent::EnvelopeReceived { fingerprint, envelope } => {
            if verbose {
                println!("[EVENT] Envelope received from {}: class={:?}, seq={}, body_len={}", 
                    fingerprint, envelope.header.class, envelope.header.seq, envelope.body.len());
            }
        }
        SupervisorEvent::Error { error } => {
            eprintln!("[ERROR] {}", error);
        }
    }
}
