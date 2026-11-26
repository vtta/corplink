//! SOCKS5 CONNECT and UDP ASSOCIATE over the current authenticated tunnel.
use crate::{DatagramSocket, Tunnel};
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

pub async fn serve(tun: Tunnel, listen: &str) -> Result<()> {
    serve_auth(tun, listen, None).await
}

pub async fn serve_auth(tun: Tunnel, listen: &str, auth: Option<(String, String)>) -> Result<()> {
    serve_on(tun, bind(listen).await?, auth).await
}

pub async fn bind(listen: &str) -> Result<TcpListener> {
    Ok(TcpListener::bind(listen).await?)
}

pub async fn serve_on(
    tun: Tunnel,
    listener: TcpListener,
    auth: Option<(String, String)>,
) -> Result<()> {
    let (_keep, current) = watch::channel(Some(tun));
    serve_managed(current, listener, auth).await
}

/// The listener survives tunnel replacement. New requests made during recovery fail promptly.
pub async fn serve_managed(
    current: watch::Receiver<Option<Tunnel>>,
    listener: TcpListener,
    auth: Option<(String, String)>,
) -> Result<()> {
    loop {
        let (cli, _) = listener.accept().await?;
        let current = current.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(cli, current, auth).await {
                tracing::debug!("SOCKS connection: {e}");
            }
        });
    }
}

async fn reply(cli: &mut TcpStream, code: u8, bound: Option<SocketAddr>) -> Result<()> {
    let addr = bound.unwrap_or_else(|| SocketAddr::from(([0; 4], 0)));
    let mut bytes = vec![5, code, 0];
    match addr.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend(ip.octets());
        }
    }
    bytes.extend(addr.port().to_be_bytes());
    cli.write_all(&bytes).await?;
    Ok(())
}

async fn field(cli: &mut TcpStream) -> Result<Vec<u8>> {
    let len = cli.read_u8().await?;
    let mut data = vec![0; len as usize];
    cli.read_exact(&mut data).await?;
    Ok(data)
}

async fn handle(
    mut cli: TcpStream,
    current: watch::Receiver<Option<Tunnel>>,
    auth: Option<(String, String)>,
) -> Result<()> {
    if cli.read_u8().await? != 5 {
        bail!("expected SOCKS5");
    }
    let methods = field(&mut cli).await?;
    let method = if auth.is_some() { 2 } else { 0 };
    if !methods.contains(&method) {
        cli.write_all(&[5, 0xff]).await?;
        bail!("no supported auth method");
    }
    cli.write_all(&[5, method]).await?;
    if let Some((user, password)) = auth {
        let version = cli.read_u8().await?;
        let u = field(&mut cli).await?;
        let p = field(&mut cli).await?;
        let ok = version == 1 && u == user.as_bytes() && p == password.as_bytes();
        cli.write_all(&[1, u8::from(!ok)]).await?;
        if !ok {
            bail!("SOCKS authentication failed");
        }
    }
    let mut h = [0; 4];
    cli.read_exact(&mut h).await?;
    if h[0] != 5 || h[2] != 0 {
        bail!("invalid SOCKS request");
    }
    if !matches!(h[1], 1 | 3) {
        return reply(&mut cli, 7, None).await;
    }
    let host = match h[3] {
        1 => Ipv4Addr::from(cli.read_u32().await?).to_string(),
        3 => String::from_utf8(field(&mut cli).await?)?,
        4 if h[1] == 3 => {
            let mut a = [0; 16];
            cli.read_exact(&mut a).await?;
            String::new()
        }
        _ => return reply(&mut cli, 8, None).await,
    };
    let port = cli.read_u16().await?;
    let tun = current.borrow().clone();
    let Some(tun) = tun.filter(|t| !t.is_closed()) else {
        return reply(&mut cli, 3, None).await;
    };
    if h[1] == 3 {
        return associate(cli, tun, port).await;
    }
    let mut stream = match tun.connect_host(&host, port).await {
        Ok(s) => s,
        Err(_) => return reply(&mut cli, 4, None).await,
    };
    reply(&mut cli, 0, None).await?;
    tokio::select! {
        _ = tun.closed() => {},
        result = tokio::io::copy_bidirectional(&mut cli, &mut stream) => { result?; },
    }
    Ok(())
}

enum Target<'a> {
    Ip(Ipv4Addr),
    Name(&'a str),
}

fn parse_datagram(pkt: &[u8]) -> Option<(Target<'_>, u16, &[u8])> {
    // RFC 1928: drop unsupported fragments, invalid reserved bytes and bad addresses.
    if pkt.get(..3)? != [0, 0, 0] {
        return None;
    }
    let (host, end) = match *pkt.get(3)? {
        1 => (
            Target::Ip(Ipv4Addr::from(<[u8; 4]>::try_from(pkt.get(4..8)?).ok()?)),
            8,
        ),
        3 => {
            let len = *pkt.get(4)? as usize;
            if len == 0 {
                return None;
            }
            (
                Target::Name(std::str::from_utf8(pkt.get(5..5 + len)?).ok()?),
                5 + len,
            )
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(pkt.get(end..end + 2)?.try_into().ok()?);
    if port == 0 {
        return None;
    }
    Some((host, port, &pkt[end + 2..]))
}

async fn associate(mut cli: TcpStream, tun: Tunnel, requested_port: u16) -> Result<()> {
    let peer = cli.peer_addr()?;
    let relay = UdpSocket::bind(SocketAddr::new(cli.local_addr()?.ip(), 0)).await?;
    let DatagramSocket {
        outbound,
        mut inbound,
    } = match tun.bind_udp().await {
        Ok(s) => s,
        Err(_) => return reply(&mut cli, 1, None).await,
    };
    reply(&mut cli, 0, Some(relay.local_addr()?)).await?;
    let client = OnceLock::new();
    let outgoing = async {
        let mut buf = vec![0; 65535];
        while !outbound.is_closed() {
            let (n, from) = relay.recv_from(&mut buf).await?;
            if from.ip() != peer.ip() || (requested_port != 0 && requested_port != from.port()) {
                continue;
            }
            let Some((host, port, payload)) = parse_datagram(&buf[..n]) else {
                continue;
            };
            if *client.get_or_init(|| from) != from {
                continue;
            }
            let ip = match host {
                Target::Ip(ip) => ip,
                Target::Name(name) => match tun.resolve(name).await {
                    Ok(ip) => ip,
                    Err(_) => continue,
                },
            };
            outbound
                .send((SocketAddrV4::new(ip, port), payload.to_vec()))
                .await
                .context("tunnel closed")?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let incoming = async {
        while let Some((src, payload)) = inbound.recv().await {
            let Some(client) = client.get() else { continue };
            let mut pkt = Vec::with_capacity(10 + payload.len());
            pkt.extend([0, 0, 0, 1]);
            pkt.extend(src.ip().octets());
            pkt.extend(src.port().to_be_bytes());
            pkt.extend(payload);
            // An oversized encapsulated datagram cannot be sent on this socket.
            if pkt.len() <= 65507 {
                relay.send_to(&pkt, client).await?;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let mut byte = [0];
    tokio::select! {
        result = cli.read(&mut byte) => { result?; Ok(()) },
        _ = tun.closed() => Ok(()),
        result = outgoing => result,
        result = incoming => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn datagram_headers() {
        assert!(matches!(
            parse_datagram(&[0, 0, 0, 1, 10, 0, 0, 1, 0, 53, 42]),
            Some((Target::Ip(_), 53, [42]))
        ));
        assert!(matches!(
            parse_datagram(&[0, 0, 0, 3, 1, b'a', 1, 0]),
            Some((Target::Name("a"), 256, []))
        ));
        for pkt in [
            &[0, 0, 1, 1, 10, 0, 0, 1, 0, 53][..],
            &[0, 0, 0, 3, 5, b'a'],
            &[0, 0, 0, 4],
            &[1, 0, 0, 1],
            &[0, 0, 0, 3, 0, 0, 53],
        ] {
            assert!(parse_datagram(pkt).is_none());
        }
    }
}
