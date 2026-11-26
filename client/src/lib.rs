//! Self-contained pure-Rust CorpLink/feilian client, as a library.
//!
//! [`connect`] performs the login (company lookup, feilian_v1 password/2FA,
//! `connect_vpn`), brings up the userspace WireGuard-over-TCP [`Tunnel`], and
//! returns a [`Session`] that keeps the server-side session alive in the
//! background and, on [`Session::close`] / drop, disconnects and logs out.
pub mod api;
pub mod client;
pub mod config;
pub mod qrcode;
pub mod resp;
pub mod state;
pub mod template;
pub mod totp;
pub mod utils;

pub use config::{Config, WgConf};
pub use corplink_tunnel::{Tunnel, TunnelStream};

use anyhow::{Context, Result};
use std::time::Duration;
use tokio::sync::oneshot;

fn to_tunnel_conf(wg: &WgConf) -> corplink_tunnel::WgConf {
    corplink_tunnel::WgConf {
        address: wg.address.clone(),
        peer_address: wg.peer_address.clone(),
        mtu: wg.mtu,
        private_key: wg.private_key.clone(),
        peer_key: wg.peer_key.clone(),
        dns: wg.dns.clone(),
        protocol: wg.protocol,
        allowed_ips: wg.allowed_ips.clone(),
    }
}

/// A live tunnel session. Clone the [`Tunnel`] via [`Session::tunnel`] to open
/// connections; keepalive runs in the background until [`Session::close`] or drop.
pub struct Session {
    tunnel: Tunnel,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl Session {
    /// A clonable handle to the tunnel for opening connections.
    pub fn tunnel(&self) -> Tunnel {
        self.tunnel.clone()
    }
    /// Gracefully disconnect the VPN and log out the terminal.
    pub async fn close(mut self) {
        self.tunnel.stop();
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(()); // best-effort background cleanup
        }
    }
}

/// Log in with `config` and bring up the tunnel. `config` may be in-memory
/// (no file); credentials come from its fields.
async fn login_client(mut config: Config) -> Result<client::Client> {
    config.prepare()?;
    if config.server.is_none() {
        let resp = client::get_company_url(&config.company_name)
            .await
            .with_context(|| format!("company lookup failed for {}", config.company_name))?;
        config.server = Some(resp.domain);
    }
    client::Client::new(config).context("failed to init client")
}

async fn allocate(c: &mut client::Client) -> Result<WgConf> {
    if c.need_login() {
        c.login().await.context("login failed")?;
    }
    match c.connect_vpn().await {
        Ok(wg) => Ok(wg),
        // The saved session died server-side (logged out elsewhere, expired):
        // connect_vpn resets the state, so log in once more and retry.
        Err(e) if e.to_string().contains("logout") => {
            log::warn!("{e}; re-logging in");
            c.login().await.context("re-login failed")?;
            c.connect_vpn()
                .await
                .context("connect_vpn failed after re-login")
        }
        Err(e) => Err(e.context("connect_vpn failed")),
    }
}

pub async fn connect(config: Config) -> Result<Session> {
    let platform = config.platform.clone();
    let mut c = login_client(config).await?;
    let wg = allocate(&mut c).await?;
    let tunnel = match Tunnel::start(to_tunnel_conf(&wg)).await {
        Ok(t) => t,
        Err(e) => {
            let _ = c.disconnect_vpn(&wg).await;
            return Err(e.context("failed to start tunnel"));
        }
    };
    let (sd_tx, sd_rx) = oneshot::channel();
    let join = tokio::spawn(session_task(c, wg, platform, sd_rx));
    Ok(Session {
        tunnel,
        shutdown: Some(sd_tx),
        join: Some(join),
    })
}

async fn report_until_stopped(c: &mut client::Client, wg: &WgConf) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await;
    loop {
        tick.tick().await;
        if let Err(e) = c.report_vpn_status(wg).await {
            log::warn!("VPN status report failed: {e}");
        }
    }
}

async fn session_task(
    mut c: client::Client,
    wg: WgConf,
    platform: Option<String>,
    mut sd_rx: oneshot::Receiver<()>,
) {
    tokio::select! {
        _ = report_until_stopped(&mut c, &wg) => {},
        _ = &mut sd_rx => {},
    }
    let _ = c.disconnect_vpn(&wg).await;
    if platform.as_deref() == Some(config::PLATFORM_CORPLINK_V1) {
        let _ = c.logout().await;
    }
}

/// Keep one authenticated VPN allocation active and publish only handshake-ready tunnels.
/// A network handoff or transport failure never logs the user out of their portal session.
pub async fn maintain(
    config: Config,
    current: tokio::sync::watch::Sender<Option<Tunnel>>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    tokio::pin!(shutdown);
    let mut delay = Duration::from_secs(1);
    let mut client = None;
    loop {
        let attempt = async {
            if client.is_none() {
                client = Some(login_client(config.clone()).await?);
            }
            allocate(client.as_mut().expect("client initialized")).await
        };
        let allocation = tokio::select! {
            _ = &mut shutdown => break,
            result = attempt => result,
        };
        match allocation {
            Ok(wg) => {
                let c = client.as_mut().expect("client allocated VPN");
                let start = tokio::time::Instant::now();
                let result = tokio::select! {
                    _ = &mut shutdown => None,
                    result = Tunnel::start(to_tunnel_conf(&wg)) => Some(result),
                };
                let stopping = match result {
                    None => true,
                    Some(Err(e)) => {
                        log::warn!("tunnel setup failed: {e}");
                        false
                    }
                    Some(Ok(tun)) => {
                        current.send_replace(Some(tun.clone()));
                        log::info!("tunnel ready on {}", wg.peer_address);
                        let stop = tokio::select! {
                            biased;
                            _ = &mut shutdown => true,
                            reason = tun.end_reason() => {
                                log::warn!("reconnecting: {reason}");
                                false
                            }
                            _ = report_until_stopped(c, &wg) => unreachable!(),
                        };
                        current.send_replace(None);
                        tun.stop();
                        tun.closed().await;
                        if start.elapsed() >= Duration::from_secs(10) {
                            delay = Duration::from_secs(1);
                        }
                        stop
                    }
                };
                // Finish retiring this allocation before registering the same key again.
                let _ = tokio::time::timeout(Duration::from_secs(3), c.disconnect_vpn(&wg)).await;
                if stopping {
                    break;
                }
            }
            Err(e) => log::warn!("VPN connection failed: {e}"),
        }
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tokio::time::sleep(delay) => {},
        }
        delay = (delay * 2).min(Duration::from_secs(30));
    }
    if config.platform.as_deref() == Some(config::PLATFORM_CORPLINK_V1) {
        if let Some(c) = client.as_mut() {
            let _ = c.logout().await;
        }
    }
    Ok(())
}
