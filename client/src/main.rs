//! Thin CLI over the corplink-client library: login + userspace tunnel + SOCKS5.
use anyhow::{Context, Result};
use corplink_client::{maintain, Config};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let conf_file = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.json".into());
    let config = Config::from_file(&conf_file)
        .await
        .context("failed to load config")?;

    let socks5_listen = config
        .socks5_listen
        .clone()
        .context("`socks5_listen` is required (userspace SOCKS5 mode only)")?;
    let auth = match config.socks5_username.clone().unwrap_or_default() {
        u if u.is_empty() => None,
        u => Some((u, config.socks5_password.clone().unwrap_or_default())),
    };

    let listener = corplink_tunnel::socks5::bind(&socks5_listen).await?;
    let (publish, current) = tokio::sync::watch::channel(None);
    log::info!("SOCKS5 listening on {socks5_listen}");
    tokio::select! {
        result = corplink_tunnel::socks5::serve_managed(current, listener, auth) => result,
        result = maintain(config, publish, wait_for_shutdown_signal()) => result,
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
