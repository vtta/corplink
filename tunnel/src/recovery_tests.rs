use super::*;
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

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

// An authenticated loopback peer that echoes only inner IPv4 UDP packets.
async fn echo_peer(listener: &TcpListener) -> Result<()> {
    let (mut tcp, _) = listener.accept().await?;
    let server = x25519_dalek::StaticSecret::from([31; 32]);
    let client = x25519_dalek::StaticSecret::from([17; 32]);
    let mut wg = Tunn::new_with_identifier(
        server,
        x25519_dalek::PublicKey::from(&client),
        None,
        None,
        1,
        None,
        Some(CORPLINK_HANDSHAKE_IDENTIFIER),
    );
    let mut out = vec![0; 65535];
    loop {
        let n = tcp.read_u32_le().await? as usize;
        anyhow::ensure!(n <= 65535);
        let mut frame_data = vec![0; n];
        tcp.read_exact(&mut frame_data).await?;
        let mut input = &frame_data[..];
        loop {
            match wg.decapsulate(None, input, &mut out) {
                TunnResult::WriteToNetwork(bytes) => tcp.write_all(&frame(bytes)).await?,
                TunnResult::WriteToTunnelV4(ip, _) if ip.len() >= 28 && ip[9] == 17 => {
                    let mut echo = ip.to_vec();
                    for k in 0..4 {
                        echo.swap(12 + k, 16 + k);
                    }
                    let hdr = usize::from(echo[0] & 15) * 4;
                    if hdr + 8 > echo.len() {
                        break;
                    }
                    echo.swap(hdr, hdr + 2);
                    echo.swap(hdr + 1, hdr + 3);
                    if let TunnResult::WriteToNetwork(bytes) = wg.encapsulate(&echo, &mut out) {
                        tcp.write_all(&frame(bytes)).await?;
                    }
                    break;
                }
                _ => break,
            }
            input = &[];
        }
    }
}

async fn socks_request(addr: SocketAddr, cmd: u8) -> Result<(TcpStream, u8, SocketAddr)> {
    let mut client = TcpStream::connect(addr).await?;
    client.write_all(&[5, 1, 0]).await?;
    let mut greet = [0; 2];
    client.read_exact(&mut greet).await?;
    assert_eq!(greet, [5, 0]);
    client.write_all(&[5, cmd, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await?;
    Ok((
        client,
        reply[1],
        SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        )),
    ))
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

#[tokio::test]
async fn udp_echo_across_two_gateway_generations() {
    timeout(Duration::from_secs(8), async {
        let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vpn_addr = gateway.local_addr().unwrap();
        let gateway = Arc::new(gateway);
        let l = socks5::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (publish, current) = watch::channel(None);
        let proxy = tokio::spawn(socks5::serve_managed(current, l, None));
        for _ in 0..2 {
            assert_eq!(socks_request(addr, 3).await.unwrap().1, 3);
            let g = gateway.clone();
            let remote = tokio::spawn(async move { echo_peer(&g).await });
            let tun = Tunnel::start(config(vpn_addr)).await.unwrap();
            publish.send_replace(Some(tun.clone()));
            let (mut control, code, relay) = socks_request(addr, 3).await.unwrap();
            assert_eq!(code, 0);
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let query = [0, 0, 0, 1, 10, 9, 0, 1, 0, 7, 42, 55, 16];
            udp.send_to(&query, relay).await.unwrap();
            let mut reply = [0; 64];
            let (n, src) = udp.recv_from(&mut reply).await.unwrap();
            assert_eq!(src, relay);
            assert_eq!(&reply[..n], query);
            let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            other.send_to(&query, relay).await.unwrap();
            assert!(
                timeout(Duration::from_millis(100), other.recv_from(&mut reply))
                    .await
                    .is_err()
            );
            assert!(
                timeout(Duration::from_millis(100), udp.recv_from(&mut reply))
                    .await
                    .is_err()
            );
            // Closing the control channel must retire the UDP association.
            control.shutdown().await.unwrap();
            assert_eq!(control.read(&mut reply).await.unwrap(), 0);
            sleep(Duration::from_millis(20)).await;
            udp.send_to(&query, relay).await.unwrap();
            assert!(!matches!(
                timeout(Duration::from_millis(100), udp.recv_from(&mut reply)).await,
                Ok(Ok(_))
            ));
            remote.abort();
            let _ = remote.await;
            assert!(tun.end_reason().await.contains("gateway TCP"));
            publish.send_replace(None);
        }
        proxy.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_associate_uses_the_same_password_authentication_as_connect() {
    let listener = socks5::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_publish, current) = watch::channel(None);
    let server = tokio::spawn(socks5::serve_managed(
        current,
        listener,
        Some(("user".to_owned(), "pass".to_owned())),
    ));
    let mut cli = TcpStream::connect(addr).await.unwrap();
    cli.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    cli.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 255]);

    for (password, expected) in [(b"fail", 1), (b"pass", 0)] {
        let mut cli = TcpStream::connect(addr).await.unwrap();
        cli.write_all(&[5, 1, 2]).await.unwrap();
        cli.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 2]);
        cli.write_all(b"\x01\x04user\x04").await.unwrap();
        cli.write_all(password).await.unwrap();
        cli.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, expected]);
        if expected == 0 {
            cli.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut response = [0; 10];
            cli.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 3); // authenticated, but no tunnel has been published
        }
    }
    server.abort();
}
