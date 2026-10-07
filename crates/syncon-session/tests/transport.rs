use std::sync::Arc;

use syncon_crypto::Identity;
use syncon_proto::{Class, Envelope, Flags, Header};
use syncon_session::{Link, LinkError, Transport, TransportConfig, Trust};

fn lo() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn node(trust: Trust) -> Transport {
    let id = Arc::new(Identity::generate().unwrap());
    Transport::bind(id, TransportConfig::new(lo(), lo(), trust)).unwrap()
}

/// Two transports that trust each other, with an established link on each side.
async fn pair() -> (Transport, Transport, Link, Link) {
    let a = node(Trust::any());
    let b = node(Trust::any());
    let a_key = a.identity().sign_pub;
    let (la, lb) = tokio::join!(a.accept(), b.dial(a.realtime_addr(), Trust::only(a_key)));
    (a, b, la.unwrap(), lb.unwrap())
}

#[tokio::test]
async fn handshake_sas_and_messages() {
    let (a, b, la, lb) = pair().await;
    assert_eq!(la.sas().display(), lb.sas().display());
    assert_eq!(la.peer().sign_pub, b.identity().sign_pub);
    assert_eq!(lb.peer().sign_pub, a.identity().sign_pub);

    for i in 1..=3u8 {
        lb.send(Class::Clipboard, Flags::NONE, &[i; 20]).await.unwrap();
    }
    for i in 1..=3u8 {
        let m = la.recv().await.unwrap();
        assert_eq!((m.class, m.seq, m.body), (Class::Clipboard, i as u64, vec![i; 20]));
    }
    la.send(Class::Presence, Flags::NONE, b"hb").await.unwrap();
    assert_eq!(lb.recv().await.unwrap().body, b"hb");
}

#[tokio::test]
async fn datagrams_roundtrip() {
    let (_a, _b, la, lb) = pair().await;
    lb.send_datagram(&[7u8; 64]).unwrap();
    let m = la.recv().await.unwrap();
    assert_eq!((m.class, m.body.len()), (Class::Input, 64));
}

#[tokio::test]
async fn untrusted_peer_rejected() {
    let a = node(Trust::only([9u8; 32]));
    let b = node(Trust::any());
    let (ra, rb) = tokio::join!(a.accept(), b.dial(a.realtime_addr(), Trust::any()));
    assert!(ra.is_err() || rb.is_err());
    assert!(rb.is_err() || ra.is_err());
}

#[tokio::test]
async fn dial_with_wrong_pin_fails() {
    let a = node(Trust::any());
    let b = node(Trust::any());
    let (_ra, rb) = tokio::join!(a.accept(), b.dial(a.realtime_addr(), Trust::only([1u8; 32])));
    assert!(rb.is_err());
}

#[tokio::test]
async fn aead_failure_closes_link() {
    let (_a, _b, la, lb) = pair().await;
    // A well-formed envelope whose body is not valid ciphertext.
    let env = Envelope::new(Header::new(Class::Clipboard, Flags::NONE, 1, 32), vec![0u8; 32]).unwrap();
    lb.send_raw_for_test(&env.to_bytes()).await.unwrap();
    assert!(matches!(la.recv().await, Err(LinkError::Aead)));
}

#[tokio::test]
async fn unknown_class_is_skipped() {
    let (_a, _b, la, lb) = pair().await;
    let mut frame = vec![0u8; 16 + 4];
    frame[0] = 1;
    frame[1] = 99;
    frame[4] = 1;
    frame[12] = 4;
    lb.send_raw_for_test(&frame).await.unwrap();
    lb.send(Class::Presence, Flags::NONE, b"x").await.unwrap();
    assert_eq!(la.recv().await.unwrap().class, Class::Presence);
    assert_eq!(la.unknown_class_count(), 1);
}

#[tokio::test]
async fn bulk_connection_is_separate_and_pinned() {
    let (a, b, la, lb) = pair().await;
    let a_pub = a.identity().sign_pub;
    let b_pub = b.identity().sign_pub;
    let (ba, bb) = tokio::join!(a.accept_bulk(b_pub), b.dial_bulk(a.bulk_addr(), a_pub));
    let (ba, bb) = (ba.unwrap(), bb.unwrap());
    let mut s = bb.open_send().await.unwrap();
    s.write_all(&[0u8; 1024]).await.unwrap();
    s.finish().unwrap();
    let data = ba.accept_recv().await.unwrap().read_to_end(4096).await.unwrap();
    assert_eq!(data.len(), 1024);
    // realtime still works
    lb.send(Class::Presence, Flags::NONE, b"x").await.unwrap();
    assert_eq!(la.recv().await.unwrap().class, Class::Presence);
}
