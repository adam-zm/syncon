//! QUIC transport for Syncon.
//!
//! Two independent QUIC connections per peer, on two UDP ports:
//! - **realtime** (47920): Hello, inner AEAD, control/clipboard/presence on one
//!   reliable stream, `input` as datagrams. The session is up when this is up.
//! - **bulk** (47921): opportunistic, raw streams for file transfer. It shares
//!   nothing with realtime so bulk congestion cannot delay realtime packets.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use syncon_crypto::{compute_sas, x25519_shared, Identity, InnerAeadKey, PublicIdentity, SasCode};
use syncon_proto::hello::HELLO_SIZE;
use syncon_proto::{Class, Envelope, FeatureBits, Flags, Header, Hello, Role, HEADER_SIZE, VERSION};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::tls::{self, Trust};

/// Default realtime UDP port.
pub const REALTIME_PORT: u16 = 47920;

/// Default bulk UDP port.
pub const BULK_PORT: u16 = 47921;

const TLS_NAME: &str = "syncon";
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const SAS_LABEL: &[u8] = b"link-sas-v1";
const INNER_LABEL: &[u8] = b"link-inner-v1";
const MAX_SKIP_BODY: u32 = 64 * 1024;

const CLOSE_NORMAL: u32 = 0;
const CLOSE_PROTOCOL: u32 = 1;
const CLOSE_AEAD: u32 = 2;

/// Transport failure.
#[derive(Debug, Clone, Error)]
pub enum LinkError {
    #[error("io/tls: {0}")]
    Transport(String),
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// AEAD failure or nonce/sequence reuse. The pin must be kept.
    #[error("AEAD failure")]
    Aead,
    #[error("connection closed")]
    Closed,
}

/// Transport configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub realtime_addr: SocketAddr,
    pub bulk_addr: SocketAddr,
    pub role: Role,
    pub features: FeatureBits,
    /// Peer who may connect to our listeners.
    pub trust: Trust,
    pub keep_alive: Duration,
    pub idle_timeout: Duration,
}

impl TransportConfig {
    pub fn new(realtime_addr: SocketAddr, bulk_addr: SocketAddr, trust: Trust) -> Self {
        Self {
            realtime_addr,
            bulk_addr,
            role: Role::Desktop,
            features: FeatureBits::NONE,
            trust,
            keep_alive: Duration::from_millis(500),
            idle_timeout: Duration::from_secs(3),
        }
    }
}

fn transport_err(e: impl std::fmt::Display) -> LinkError {
    LinkError::Transport(e.to_string())
}

fn quinn_transport(cfg: &TransportConfig, datagrams: bool) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(cfg.keep_alive));
    t.max_idle_timeout(Some(cfg.idle_timeout.try_into().expect("idle timeout fits")));
    if datagrams {
        t.datagram_receive_buffer_size(Some(256 * 1024));
    } else {
        t.datagram_receive_buffer_size(None);
    }
    Arc::new(t)
}

fn server_endpoint(
    identity: &Identity,
    cfg: &TransportConfig,
    addr: SocketAddr,
    datagrams: bool,
) -> Result<Endpoint, LinkError> {
    let tls = tls::server_config(identity, cfg.trust.clone()).map_err(transport_err)?;
    let quic = QuicServerConfig::try_from(tls).map_err(transport_err)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server.transport_config(quinn_transport(cfg, datagrams));
    Endpoint::server(server, addr).map_err(transport_err)
}

/// Both endpoints of the local device.
pub struct Transport {
    identity: Arc<Identity>,
    cfg: TransportConfig,
    realtime: Endpoint,
    bulk: Endpoint,
}

impl Transport {
    /// Binds the realtime and bulk UDP sockets. Must be called inside a Tokio runtime.
    pub fn bind(identity: Arc<Identity>, cfg: TransportConfig) -> Result<Self, LinkError> {
        let realtime = server_endpoint(&identity, &cfg, cfg.realtime_addr, true)?;
        let bulk = server_endpoint(&identity, &cfg, cfg.bulk_addr, false)?;
        Ok(Self { identity, cfg, realtime, bulk })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn realtime_addr(&self) -> SocketAddr {
        self.realtime.local_addr().expect("bound socket")
    }

    pub fn bulk_addr(&self) -> SocketAddr {
        self.bulk.local_addr().expect("bound socket")
    }

    fn client(&self, trust: Trust, datagrams: bool) -> Result<quinn::ClientConfig, LinkError> {
        let tls = tls::client_config(&self.identity, trust).map_err(transport_err)?;
        let quic = QuicClientConfig::try_from(tls).map_err(transport_err)?;
        let mut client = quinn::ClientConfig::new(Arc::new(quic));
        client.transport_config(quinn_transport(&self.cfg, datagrams));
        Ok(client)
    }

    /// Accepts one inbound realtime connection and completes Hello.
    /// A failed handshake (untrusted key, bad Hello) is an `Err`; call again for the next peer.
    pub async fn accept(&self) -> Result<Link, LinkError> {
        let incoming = self.realtime.accept().await.ok_or(LinkError::Closed)?;
        let conn = tokio::time::timeout(HELLO_TIMEOUT, async {
            incoming.await.map_err(transport_err)
        })
        .await
        .map_err(|_| LinkError::Handshake("timeout".into()))??;
        self.establish(conn, false).await
    }

    /// Dials the realtime port of a peer. `trust` constrains the key the peer may present.
    pub async fn dial(&self, addr: SocketAddr, trust: Trust) -> Result<Link, LinkError> {
        let conn = self
            .realtime
            .connect_with(self.client(trust, true)?, addr, TLS_NAME)
            .map_err(transport_err)?;
        let conn = tokio::time::timeout(HELLO_TIMEOUT, conn)
            .await
            .map_err(|_| LinkError::Handshake("timeout".into()))?
            .map_err(transport_err)?;
        self.establish(conn, true).await
    }

    /// Accepts the bulk connection of an already authenticated peer; others are refused.
    pub async fn accept_bulk(&self, peer_sign_pub: [u8; 32]) -> Result<BulkLink, LinkError> {
        loop {
            let incoming = self.bulk.accept().await.ok_or(LinkError::Closed)?;
            let Ok(conn) = incoming.await else { continue };
            if peer_key(&conn) == Some(peer_sign_pub) {
                return Ok(BulkLink { conn });
            }
            conn.close(VarInt::from_u32(CLOSE_PROTOCOL), b"unexpected peer");
        }
    }

    /// Dials the bulk port of an authenticated peer.
    pub async fn dial_bulk(&self, addr: SocketAddr, peer_sign_pub: [u8; 32]) -> Result<BulkLink, LinkError> {
        let conn = self
            .bulk
            .connect_with(self.client(Trust::only(peer_sign_pub), false)?, addr, TLS_NAME)
            .map_err(transport_err)?;
        let conn = tokio::time::timeout(HELLO_TIMEOUT, conn)
            .await
            .map_err(|_| LinkError::Handshake("timeout".into()))?
            .map_err(transport_err)?;
        Ok(BulkLink { conn })
    }

    async fn establish(&self, conn: Connection, initiator: bool) -> Result<Link, LinkError> {
        match tokio::time::timeout(HELLO_TIMEOUT, self.hello_exchange(&conn, initiator)).await {
            Ok(Ok(link)) => Ok(link),
            Ok(Err(e)) => {
                conn.close(VarInt::from_u32(CLOSE_PROTOCOL), b"handshake failed");
                Err(e)
            }
            Err(_) => {
                conn.close(VarInt::from_u32(CLOSE_PROTOCOL), b"hello timeout");
                Err(LinkError::Handshake("hello timeout".into()))
            }
        }
    }

    async fn hello_exchange(&self, conn: &Connection, initiator: bool) -> Result<Link, LinkError> {
        let id = &self.identity;
        let tls_peer = peer_key(conn).ok_or_else(|| LinkError::Handshake("no peer certificate".into()))?;

        let eph = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let eph_pub = x25519_dalek::PublicKey::from(&eph).to_bytes();
        let local = Hello::new(
            self.cfg.role,
            eph_pub,
            id.sign_pub,
            id.dh_pub,
            self.cfg.features,
            Class::Clipboard.max_body() as u16,
            id.fingerprint,
        );
        let local_bytes = local.to_bytes();
        let hello_env = Envelope::new(
            Header::new(Class::Hello, Flags::NONE, 1, HELLO_SIZE as u32),
            local_bytes.to_vec(),
        )
        .map_err(|e| LinkError::Protocol(format!("{e:?}")))?;

        let (send, recv, peer_bytes) = if initiator {
            let (mut s, mut r) = conn.open_bi().await.map_err(transport_err)?;
            s.write_all(&hello_env.to_bytes()).await.map_err(transport_err)?;
            let p = read_hello(&mut r).await?;
            (s, r, p)
        } else {
            let (mut s, mut r) = conn.accept_bi().await.map_err(transport_err)?;
            let p = read_hello(&mut r).await?;
            s.write_all(&hello_env.to_bytes()).await.map_err(transport_err)?;
            (s, r, p)
        };

        let peer = Hello::from_bytes(&peer_bytes).ok_or_else(|| LinkError::Handshake("bad hello".into()))?;
        if peer.version != VERSION {
            return Err(LinkError::Handshake(format!("unsupported version {}", peer.version)));
        }
        if peer.sign_pub != tls_peer {
            return Err(LinkError::Handshake("Hello key does not match certificate".into()));
        }
        if peer.fingerprint != syncon_crypto::compute_fingerprint(&peer.sign_pub) {
            return Err(LinkError::Handshake("Hello fingerprint mismatch".into()));
        }

        let static_shared = id
            .dh_static_shared_secret(&peer.dh_pub)
            .ok_or_else(|| LinkError::Handshake("bad peer DH key".into()))?;
        let eph_shared = x25519_shared(eph, &peer.eph_x25519_pub)
            .ok_or_else(|| LinkError::Handshake("bad peer ephemeral".into()))?;
        let mut inner = [0u8; 32];
        conn.export_keying_material(&mut inner, INNER_LABEL, &[])
            .map_err(|_| LinkError::Handshake("exporter failed".into()))?;
        let mut sas_exporter = [0u8; 32];
        conn.export_keying_material(&mut sas_exporter, SAS_LABEL, &[])
            .map_err(|_| LinkError::Handshake("exporter failed".into()))?;

        let aead = Arc::new(InnerAeadKey::derive(
            &static_shared,
            &eph_shared,
            &inner,
            &local_bytes,
            &peer_bytes,
            &id.sign_pub,
            &peer.sign_pub,
        ));
        let sas = compute_sas(&id.sign_pub, &peer.sign_pub, &id.dh_pub, &peer.dh_pub, &sas_exporter);

        // The Hello was the only plaintext frame; everything after is AEAD.
        let (tx, rx) = mpsc::channel(1024);
        let shared = Arc::new(Shared {
            fatal: Mutex::new(None),
            unknown_class: AtomicU64::new(0),
        });
        tokio::spawn(stream_reader(recv, aead.clone(), tx.clone(), conn.clone(), shared.clone()));
        tokio::spawn(datagram_reader(aead.clone(), tx, conn.clone(), shared.clone()));

        Ok(Link {
            conn: conn.clone(),
            peer: PublicIdentity::new(peer.sign_pub, peer.dh_pub),
            peer_hello: peer,
            sas,
            aead,
            send: AsyncMutex::new(send),
            seqs: Default::default(),
            rx: AsyncMutex::new(rx),
            shared,
        })
    }
}

fn peer_key(conn: &Connection) -> Option<[u8; 32]> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>().ok()?;
    tls::cert_sign_pub(certs.first()?)
}

async fn read_header(recv: &mut RecvStream) -> Result<Option<[u8; HEADER_SIZE]>, LinkError> {
    let mut hdr = [0u8; HEADER_SIZE];
    match recv.read_exact(&mut hdr).await {
        Ok(()) => Ok(Some(hdr)),
        Err(quinn::ReadExactError::FinishedEarly(0)) => Ok(None),
        Err(e) => Err(transport_err(e)),
    }
}

async fn read_hello(recv: &mut RecvStream) -> Result<Vec<u8>, LinkError> {
    let hdr = read_header(recv).await?.ok_or(LinkError::Closed)?;
    if hdr[0] != VERSION || hdr[1] != Class::Hello.as_u8() {
        return Err(LinkError::Handshake("expected Hello".into()));
    }
    let len = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
    if len != HELLO_SIZE {
        return Err(LinkError::Handshake("bad Hello length".into()));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.map_err(transport_err)?;
    Ok(body)
}

/// A decrypted message from the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub class: Class,
    pub flags: Flags,
    pub seq: u64,
    pub body: Vec<u8>,
}

struct Shared {
    fatal: Mutex<Option<LinkError>>,
    unknown_class: AtomicU64,
}

impl Shared {
    fn fail(&self, conn: &Connection, err: LinkError) {
        let code = match err {
            LinkError::Aead => CLOSE_AEAD,
            LinkError::Protocol(_) => CLOSE_PROTOCOL,
            _ => CLOSE_NORMAL,
        };
        self.fatal.lock().unwrap().get_or_insert(err);
        conn.close(VarInt::from_u32(code), b"fatal");
    }
}

async fn stream_reader(
    mut recv: RecvStream,
    aead: Arc<InnerAeadKey>,
    tx: mpsc::Sender<Message>,
    conn: Connection,
    shared: Arc<Shared>,
) {
    let mut last = [0u64; 9];
    loop {
        let hdr = match read_header(&mut recv).await {
            Ok(Some(h)) => h,
            _ => return,
        };
        if hdr[0] != VERSION {
            return shared.fail(&conn, LinkError::Protocol("bad version".into()));
        }
        let body_len = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        let Some(class) = Class::from_u8(hdr[1]) else {
            // Unknown class: count, skip, keep the connection.
            if body_len > MAX_SKIP_BODY {
                return shared.fail(&conn, LinkError::Protocol("oversized unknown frame".into()));
            }
            let mut skip = vec![0u8; body_len as usize];
            if recv.read_exact(&mut skip).await.is_err() {
                return;
            }
            shared.unknown_class.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let header = match Header::from_bytes(&hdr) {
            Ok(h) => h,
            Err(e) => return shared.fail(&conn, LinkError::Protocol(format!("{e:?}"))),
        };
        if class == Class::Hello || !class.is_reliable() {
            return shared.fail(&conn, LinkError::Protocol(format!("{class:?} on stream")));
        }
        let mut body = vec![0u8; body_len as usize];
        if recv.read_exact(&mut body).await.is_err() {
            return;
        }
        let slot = class.as_u8() as usize;
        if header.seq <= last[slot] {
            return shared.fail(&conn, LinkError::Aead);
        }
        last[slot] = header.seq;
        let Some(body) = aead.decrypt(class.as_u8(), header.seq, &body) else {
            return shared.fail(&conn, LinkError::Aead);
        };
        let msg = Message { class, flags: header.flags, seq: header.seq, body };
        if tx.send(msg).await.is_err() {
            return;
        }
    }
}

async fn datagram_reader(
    aead: Arc<InnerAeadKey>,
    tx: mpsc::Sender<Message>,
    conn: Connection,
    shared: Arc<Shared>,
) {
    let mut last = 0u64;
    while let Ok(data) = conn.read_datagram().await {
        let env = match Envelope::from_bytes(&data) {
            Ok(e) if e.header.class == Class::Input => e,
            Ok(_) => continue,
            Err(_) => {
                shared.unknown_class.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        let Some(body) = aead.decrypt(env.header.class.as_u8(), env.header.seq, &env.body) else {
            return shared.fail(&conn, LinkError::Aead);
        };
        // Latest seq wins: reordered or replayed datagrams are dropped, not fatal.
        if env.header.seq <= last {
            continue;
        }
        last = env.header.seq;
        let msg = Message { class: Class::Input, flags: env.header.flags, seq: env.header.seq, body };
        if tx.send(msg).await.is_err() {
            return;
        }
    }
}

/// An authenticated realtime link with a peer.
pub struct Link {
    conn: Connection,
    peer: PublicIdentity,
    peer_hello: Hello,
    sas: SasCode,
    aead: Arc<InnerAeadKey>,
    send: AsyncMutex<SendStream>,
    seqs: [AtomicU64; 9],
    rx: AsyncMutex<mpsc::Receiver<Message>>,
    shared: Arc<Shared>,
}

impl Link {
    pub fn peer(&self) -> &PublicIdentity {
        &self.peer
    }

    pub fn peer_hello(&self) -> &Hello {
        &self.peer_hello
    }

    pub fn sas(&self) -> SasCode {
        self.sas
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// Smoothed QUIC round-trip time.
    pub fn rtt(&self) -> Duration {
        self.conn.rtt()
    }

    /// Number of frames with an unknown class that were skipped.
    pub fn unknown_class_count(&self) -> u64 {
        self.shared.unknown_class.load(Ordering::Relaxed)
    }

    fn next_seq(&self, class: Class) -> u64 {
        self.seqs[class.as_u8() as usize].fetch_add(1, Ordering::SeqCst) + 1
    }

    fn seal(&self, class: Class, flags: Flags, seq: u64, plaintext: &[u8]) -> Result<Envelope, LinkError> {
        let body = self.aead.encrypt(class.as_u8(), seq, plaintext);
        Envelope::new(Header::new(class, flags, seq, body.len() as u32), body)
            .map_err(|e| LinkError::Protocol(format!("{e:?}")))
    }

    /// Sends a message of a reliable class on the realtime stream.
    /// The ciphertext (plaintext + 16 byte tag) must fit the class limit.
    pub async fn send(&self, class: Class, flags: Flags, plaintext: &[u8]) -> Result<(), LinkError> {
        if !class.is_reliable() || class == Class::Hello {
            return Err(LinkError::Protocol(format!("{class:?} is not a stream class")));
        }
        let mut stream = self.send.lock().await;
        let seq = self.next_seq(class);
        let env = self.seal(class, flags, seq, plaintext)?;
        stream.write_all(&env.to_bytes()).await.map_err(transport_err)
    }

    /// Sends an `input` datagram (no retransmission, latest seq wins).
    pub fn send_datagram(&self, plaintext: &[u8]) -> Result<(), LinkError> {
        let seq = self.next_seq(Class::Input);
        let env = self.seal(Class::Input, Flags::NONE, seq, plaintext)?;
        self.conn
            .send_datagram(env.to_bytes().into())
            .map_err(transport_err)
    }

    /// Receives the next message. `Err` means the link is down; the error says why.
    pub async fn recv(&self) -> Result<Message, LinkError> {
        match self.rx.lock().await.recv().await {
            Some(m) => Ok(m),
            None => Err(self.down_reason()),
        }
    }

    fn down_reason(&self) -> LinkError {
        self.shared.fatal.lock().unwrap().clone().unwrap_or(LinkError::Closed)
    }

    /// Resolves when the connection is gone.
    pub async fn closed(&self) -> LinkError {
        let e = self.conn.closed().await;
        self.shared
            .fatal
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| transport_err(e))
    }

    pub fn close(&self) {
        self.conn.close(VarInt::from_u32(CLOSE_NORMAL), b"bye");
    }

    /// Finishes our send side and waits (bounded) until the peer has acknowledged everything
    /// written, then closes. Use instead of `close` when the last message must arrive.
    pub async fn close_graceful(&self, wait: Duration) {
        {
            let mut stream = self.send.lock().await;
            if stream.finish().is_ok() {
                let _ = tokio::time::timeout(wait, stream.stopped()).await;
            }
        }
        self.close();
    }

    /// Test hook: write a raw frame to the stream, bypassing the AEAD layer.
    #[doc(hidden)]
    pub async fn send_raw_for_test(&self, bytes: &[u8]) -> Result<(), LinkError> {
        self.send.lock().await.write_all(bytes).await.map_err(transport_err)
    }
}

/// Opportunistic bulk connection.
pub struct BulkLink {
    conn: Connection,
}

impl BulkLink {
    pub async fn open_send(&self) -> Result<SendStream, LinkError> {
        self.conn.open_uni().await.map_err(transport_err)
    }

    pub async fn accept_recv(&self) -> Result<RecvStream, LinkError> {
        self.conn.accept_uni().await.map_err(transport_err)
    }

    pub fn close(&self) {
        self.conn.close(VarInt::from_u32(CLOSE_NORMAL), b"bye");
    }
}

