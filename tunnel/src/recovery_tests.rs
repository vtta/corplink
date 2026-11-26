use super::*;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::time::timeout;

fn config(addr: SocketAddr) -> WgConf {
    let b64 = base64::engine::general_purpose::STANDARD;
    let server = x25519_dalek::StaticSecret::from([31; 32]);
    WgConf {
        address: "10.9.0.2/24".into(),
        peer_address: addr.to_string(),
        mtu: 1400,
        private_key: b64.encode([17; 32]),
        peer_key: b64.encode(x25519_dalek::PublicKey::from(&server).as_bytes()),
        dns: "10.9.0.1".into(),
        protocol: 1,
        allowed_ips: vec!["10.9.0.0/24".into()],
    }
}

#[tokio::test]
async fn no_ready_tunnel_without_an_authenticated_handshake() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let t = tokio::spawn(Tunnel::start(config(l.local_addr().unwrap())));
    let (mut stream, _) = l.accept().await.unwrap();
    let n = stream.read_u32_le().await.unwrap();
    assert!(n > 0);
    let mut msg = vec![0; n as usize];
    stream.read_exact(&mut msg).await.unwrap();
    assert!(!t.is_finished());
    drop(stream);
    assert!(timeout(Duration::from_secs(3), t)
        .await
        .unwrap()
        .unwrap()
        .is_err());
}
