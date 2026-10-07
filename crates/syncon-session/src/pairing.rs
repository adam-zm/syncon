//! Pairing: the `link://pair` payload, the unpinned handshake and the SAS confirmation exchange.
//!
//! Nothing is persisted here. [`finish`] returns the peer identity only when both humans
//! confirmed the SAS; the caller then writes the pin. Every other outcome leaves no state.

use std::net::IpAddr;
use std::time::Duration;

use data_encoding::BASE32_NOPAD;
use syncon_crypto::PublicIdentity;
use syncon_proto::{Class, Control, Flags};
use thiserror::Error;
use tokio::time::Instant;

use crate::connection::{Link, LinkError, Transport};
use crate::tls::Trust;

/// Pairing window on the displaying side.
pub const PAIRING_WINDOW: Duration = Duration::from_secs(120);
const MAX_NAME_LEN: usize = 32;
const SCHEME: &str = "link://pair?";

/// The contents of the QR code / pair file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairPayload {
    pub sign_pub: [u8; 32],
    pub dh_pub: [u8; 32],
    pub host: IpAddr,
    pub realtime_port: u16,
    pub bulk_port: u16,
    pub name: String,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("invalid pair payload: {0}")]
pub struct PayloadError(&'static str);

fn b32(bytes: &[u8]) -> String {
    BASE32_NOPAD.encode(bytes).to_ascii_lowercase()
}

fn unb32(s: &str) -> Option<[u8; 32]> {
    BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes()).ok()?.try_into().ok()
}

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl PairPayload {
    pub fn to_url(&self) -> String {
        format!(
            "{SCHEME}v=1&sign={}&dh={}&host={}&rt={}&bk={}&name={}",
            b32(&self.sign_pub),
            b32(&self.dh_pub),
            self.host,
            self.realtime_port,
            self.bulk_port,
            pct_encode(&self.name)
        )
    }

    pub fn parse(url: &str) -> Result<Self, PayloadError> {
        let query = url.trim().strip_prefix(SCHEME).ok_or(PayloadError("not a link://pair URL"))?;
        let (mut v, mut sign, mut dh, mut host, mut rt, mut bk, mut name) =
            (None, None, None, None, None, None, None);
        for pair in query.split('&') {
            let (k, val) = pair.split_once('=').ok_or(PayloadError("malformed parameter"))?;
            let slot = match k {
                "v" => &mut v,
                "sign" => &mut sign,
                "dh" => &mut dh,
                "host" => &mut host,
                "rt" => &mut rt,
                "bk" => &mut bk,
                "name" => &mut name,
                _ => continue,
            };
            if slot.replace(val).is_some() {
                return Err(PayloadError("duplicate parameter"));
            }
        }
        if v != Some("1") {
            return Err(PayloadError("unsupported version"));
        }
        let name = pct_decode(name.ok_or(PayloadError("missing name"))?).ok_or(PayloadError("bad name"))?;
        if name.len() > MAX_NAME_LEN {
            return Err(PayloadError("name longer than 32 bytes"));
        }
        let port = |v: Option<&str>| v.and_then(|p| p.parse::<u16>().ok()).filter(|p| *p != 0);
        Ok(Self {
            sign_pub: unb32(sign.ok_or(PayloadError("missing sign"))?).ok_or(PayloadError("bad sign"))?,
            dh_pub: unb32(dh.ok_or(PayloadError("missing dh"))?).ok_or(PayloadError("bad dh"))?,
            host: host.and_then(|h| h.parse().ok()).ok_or(PayloadError("host must be a literal IP"))?,
            realtime_port: port(rt).ok_or(PayloadError("bad rt"))?,
            bulk_port: port(bk).ok_or(PayloadError("bad bk"))?,
            name,
        })
    }
}

#[derive(Debug, Clone, Error)]
pub enum PairError {
    #[error(transparent)]
    Link(#[from] LinkError),
    #[error("pairing timed out")]
    Timeout,
    #[error("the peer presented different keys than the pair payload")]
    PayloadMismatch,
    #[error("cancelled or SAS mismatch on this side")]
    LocalReject,
    #[error("the other device rejected the pairing")]
    PeerReject,
    #[error("unexpected traffic during pairing")]
    Unexpected,
}

/// Desktop side: waits for one unpinned handshake inside the pairing window.
/// Failed handshakes do not consume the window.
pub async fn accept(transport: &Transport, window: Duration) -> Result<Link, PairError> {
    let deadline = Instant::now() + window;
    loop {
        match tokio::time::timeout_at(deadline, transport.accept()).await {
            Err(_) => return Err(PairError::Timeout),
            Ok(Ok(link)) => return Ok(link),
            Ok(Err(LinkError::Closed)) => return Err(LinkError::Closed.into()),
            Ok(Err(_)) => continue,
        }
    }
}

/// Phone side: dials the host in the payload and requires exactly the keys it carries.
pub async fn dial(transport: &Transport, payload: &PairPayload) -> Result<Link, PairError> {
    let addr = (payload.host, payload.realtime_port).into();
    let link = transport.dial(addr, Trust::only(payload.sign_pub)).await?;
    if link.peer().sign_pub != payload.sign_pub || link.peer().dh_pub != payload.dh_pub {
        link.close();
        return Err(PairError::PayloadMismatch);
    }
    Ok(link)
}

/// Exchanges the confirmation. `local_confirmed` is the human's verdict on the SAS.
/// Returns the peer identity only if both sides confirmed; the caller persists the pin.
/// No class other than control is accepted in this state.
pub async fn finish(
    link: &Link,
    local_confirmed: bool,
    timeout: Duration,
) -> Result<PublicIdentity, PairError> {
    let msg = if local_confirmed { Control::PairConfirm } else { Control::PairReject };
    link.send(Class::Control, Flags::NONE, &msg.to_bytes()).await?;

    let verdict = tokio::time::timeout(timeout, link.recv()).await;
    let outcome = match verdict {
        Err(_) => Err(PairError::Timeout),
        Ok(Err(e)) => Err(e.into()),
        Ok(Ok(m)) if m.class == Class::Control => match Control::from_bytes(&m.body) {
            Some(Control::PairConfirm) if local_confirmed => Ok(link.peer().clone()),
            Some(Control::PairConfirm) => Err(PairError::LocalReject),
            Some(Control::PairReject) => Err(PairError::PeerReject),
            _ => Err(PairError::Unexpected),
        },
        Ok(Ok(_)) => Err(PairError::Unexpected),
    };
    link.close_graceful(Duration::from_secs(2)).await;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PairPayload {
        PairPayload {
            sign_pub: [0xAB; 32],
            dh_pub: [0x12; 32],
            host: "192.168.1.20".parse().unwrap(),
            realtime_port: 47920,
            bulk_port: 47921,
            name: "Adam's Laptop & co".into(),
        }
    }

    #[test]
    fn url_roundtrip() {
        let p = sample();
        let url = p.to_url();
        assert!(url.starts_with("link://pair?v=1&sign="));
        assert!(!url.contains(' '));
        assert_eq!(PairPayload::parse(&url).unwrap(), p);
        let v6 = PairPayload { host: "::1".parse().unwrap(), ..p };
        assert_eq!(PairPayload::parse(&v6.to_url()).unwrap(), v6);
    }

    #[test]
    fn rejects_bad_payloads() {
        let url = sample().to_url();
        for bad in [
            url.replace("v=1", "v=2"),
            url.replace("host=192.168.1.20", "host=example.com"),
            url.replace("rt=47920", "rt=0"),
            url.replace("&bk=47921", ""),
            format!("{url}&rt=1"),
            url.replace("link://", "http://"),
            format!("{url}{}", "a".repeat(40)),
        ] {
            assert!(PairPayload::parse(&bad).is_err(), "{bad}");
        }
    }
}
