use std::sync::Arc;
use std::time::Duration;

use syncon_crypto::Identity;
use syncon_proto::{Class, Flags};
use syncon_session::pairing::{self, PairError, PairPayload};
use syncon_session::{Transport, TransportConfig, Trust};

fn lo() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn node(trust: Trust) -> Transport {
    Transport::bind(
        Arc::new(Identity::generate().unwrap()),
        TransportConfig::new(lo(), lo(), trust),
    )
    .unwrap()
}

fn payload(t: &Transport) -> PairPayload {
    PairPayload {
        sign_pub: t.identity().sign_pub,
        dh_pub: t.identity().dh_pub,
        host: "127.0.0.1".parse().unwrap(),
        realtime_port: t.realtime_addr().port(),
        bulk_port: t.bulk_addr().port(),
        name: "desktop".into(),
    }
}

const T: Duration = Duration::from_secs(5);

#[tokio::test]
async fn both_confirm_yields_peer_identities() {
    let desktop = node(Trust::any());
    let phone = node(Trust::any());
    let p = payload(&desktop);
    let (ld, lp) = tokio::join!(pairing::accept(&desktop, T), pairing::dial(&phone, &p));
    let (ld, lp) = (ld.unwrap(), lp.unwrap());
    assert_eq!(ld.sas().display(), lp.sas().display());
    assert_eq!(ld.sas().as_str().len(), 8);

    let (rd, rp) = tokio::join!(pairing::finish(&ld, true, T), pairing::finish(&lp, true, T));
    assert_eq!(rd.unwrap().sign_pub, phone.identity().sign_pub);
    assert_eq!(rp.unwrap().sign_pub, desktop.identity().sign_pub);
}

#[tokio::test]
async fn one_reject_fails_both_sides() {
    let desktop = node(Trust::any());
    let phone = node(Trust::any());
    let p = payload(&desktop);
    let (ld, lp) = tokio::join!(pairing::accept(&desktop, T), pairing::dial(&phone, &p));
    let (ld, lp) = (ld.unwrap(), lp.unwrap());
    let (rd, rp) = tokio::join!(pairing::finish(&ld, true, T), pairing::finish(&lp, false, T));
    assert!(matches!(rd, Err(PairError::PeerReject)));
    assert!(matches!(rp, Err(PairError::LocalReject) | Err(PairError::PeerReject)));
    assert!(rp.is_err());
}

#[tokio::test]
async fn non_control_traffic_aborts_pairing() {
    let desktop = node(Trust::any());
    let phone = node(Trust::any());
    let p = payload(&desktop);
    let (ld, lp) = tokio::join!(pairing::accept(&desktop, T), pairing::dial(&phone, &p));
    let (ld, lp) = (ld.unwrap(), lp.unwrap());
    lp.send(Class::Clipboard, Flags::NONE, b"stolen").await.unwrap();
    let r = pairing::finish(&ld, true, T).await;
    assert!(matches!(r, Err(PairError::Unexpected)));
}

#[tokio::test]
async fn payload_with_wrong_dh_key_is_refused() {
    let desktop = node(Trust::any());
    let phone = node(Trust::any());
    let mut p = payload(&desktop);
    p.dh_pub = [5; 32];
    let (_ld, lp) = tokio::join!(pairing::accept(&desktop, T), pairing::dial(&phone, &p));
    assert!(matches!(lp, Err(PairError::PayloadMismatch)));
}

#[tokio::test]
async fn payload_with_wrong_sign_key_is_refused() {
    let desktop = node(Trust::any());
    let phone = node(Trust::any());
    let mut p = payload(&desktop);
    p.sign_pub = [5; 32];
    let (_ld, lp) = tokio::join!(
        pairing::accept(&desktop, Duration::from_millis(500)),
        pairing::dial(&phone, &p)
    );
    assert!(lp.is_err());
}

#[tokio::test]
async fn window_expires_and_failed_handshakes_do_not_consume_it() {
    let desktop = node(Trust::any());
    let r = pairing::accept(&desktop, Duration::from_millis(300)).await;
    assert!(matches!(r, Err(PairError::Timeout)));
}
