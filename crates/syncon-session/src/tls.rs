//! TLS 1.3 configuration with pin-based trust (no WebPKI, no CA).
//!
//! A certificate is accepted only when its subject public key is an Ed25519 key
//! that the supplied [`Trust`] allows.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::crypto::{ring as ring_provider, CryptoProvider};
use rustls::server::danger::{ClientCertVerifier, ClientCertVerified};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use syncon_crypto::Identity;

const ED25519_OID: &str = "1.3.101.112";

/// Decides which peer sign keys may complete a TLS handshake.
#[derive(Clone)]
pub struct Trust(Arc<dyn Fn(&[u8; 32]) -> bool + Send + Sync>);

impl Trust {
    /// Accepts any key. Only for the pairing window.
    pub fn any() -> Self {
        Self(Arc::new(|_| true))
    }

    /// Accepts exactly one key.
    pub fn only(key: [u8; 32]) -> Self {
        Self(Arc::new(move |k| *k == key))
    }

    /// Accepts keys for which the predicate returns true.
    pub fn from_fn(f: impl Fn(&[u8; 32]) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Updatable policy. Pairing starts as [`Trust::any`]; after SAS confirm, store
    /// [`Trust::only`] so a later handshake cannot present a different key.
    pub fn cell(initial: Self) -> (Self, Arc<Mutex<Self>>) {
        let slot = Arc::new(Mutex::new(initial));
        let reader = slot.clone();
        (
            Self(Arc::new(move |k| reader.lock().unwrap().allows(k))),
            slot,
        )
    }

    fn allows(&self, key: &[u8; 32]) -> bool {
        (self.0)(key)
    }
}

impl std::fmt::Debug for Trust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Trust(..)")
    }
}

/// Extracts the Ed25519 subject public key from a DER certificate.
pub fn cert_sign_pub(der: &[u8]) -> Option<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let spki = cert.public_key();
    if spki.algorithm.algorithm.to_id_string() != ED25519_OID {
        return None;
    }
    spki.subject_public_key.data.as_ref().try_into().ok()
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring_provider::default_provider())
}

#[derive(Debug)]
struct PinVerifier {
    trust: Trust,
    provider: Arc<CryptoProvider>,
}

impl PinVerifier {
    fn check(&self, cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let key = cert_sign_pub(cert).ok_or_else(|| {
            rustls::Error::General("peer certificate is not an Ed25519 certificate".into())
        })?;
        if self.trust.allows(&key) {
            Ok(())
        } else {
            Err(rustls::Error::General("peer key is not trusted".into()))
        }
    }

    fn verify_sig(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for PinVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_sig(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn cert_and_key(identity: &Identity) -> (Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>) {
    (
        vec![CertificateDer::from(identity.certificate().to_vec())],
        PrivatePkcs8KeyDer::from(identity.sign_pkcs8().to_vec()),
    )
}

/// Server-side TLS config: requires a client certificate allowed by `trust`.
pub fn server_config(identity: &Identity, trust: Trust) -> Result<rustls::ServerConfig, rustls::Error> {
    let provider = provider();
    let verifier = Arc::new(PinVerifier { trust, provider: provider.clone() });
    let (certs, key) = cert_and_key(identity);
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key.into())?;
    cfg.max_early_data_size = 0;
    Ok(cfg)
}

/// Client-side TLS config: presents our certificate, accepts servers allowed by `trust`.
pub fn client_config(identity: &Identity, trust: Trust) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = provider();
    let verifier = Arc::new(PinVerifier { trust, provider: provider.clone() });
    let (certs, key) = cert_and_key(identity);
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key.into())
}
