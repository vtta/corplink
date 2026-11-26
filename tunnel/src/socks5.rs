//! SOCKS5 CONNECT over the current authenticated tunnel.
use crate::Tunnel;
use anyhow::{bail, Result};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

async fn reply(cli: &mut TcpStream, code: u8) -> Result<()> {
    cli.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
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
    if h[1] != 1 {
        return reply(&mut cli, 7).await;
    }
    let host = match h[3] {
        1 => Ipv4Addr::from(cli.read_u32().await?).to_string(),
        3 => String::from_utf8(field(&mut cli).await?)?,
        _ => return reply(&mut cli, 8).await,
    };
    let port = cli.read_u16().await?;
    let tun = current.borrow().clone();
    let Some(tun) = tun.filter(|t| !t.is_closed()) else {
        return reply(&mut cli, 3).await;
    };
    let mut stream = match tun.connect_host(&host, port).await {
        Ok(s) => s,
        Err(_) => return reply(&mut cli, 4).await,
    };
    reply(&mut cli, 0).await?;
    tokio::select! {
        _ = tun.closed() => {},
        result = tokio::io::copy_bidirectional(&mut cli, &mut stream) => { result?; },
    }
    Ok(())
}
