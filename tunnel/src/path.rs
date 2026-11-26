//! Darwin route notifications wake the tunnel when the gateway's source address changes.
use std::net::{IpAddr, SocketAddr};

#[cfg(target_os = "macos")]
pub(crate) async fn changed(peer: SocketAddr, local: IpAddr) -> std::io::Result<()> {
    use socket2::{Domain, Socket, Type};
    use std::io::Read;
    use std::net::UdpSocket;
    use tokio::io::unix::AsyncFd;

    let socket = Socket::new(
        Domain::from(libc::PF_ROUTE),
        Type::from(libc::SOCK_RAW),
        None,
    )?;
    socket.set_nonblocking(true)?;
    // SAFETY: AsyncFd exclusively owns this socket, whose descriptor is stable until drop.
    let events = unsafe { AsyncFd::register_with_interest(socket, tokio::io::Interest::READABLE) }?;
    // Subscribe before checking: DHCP can change while the outer TCP dial is finishing.
    let source = || {
        let probe = UdpSocket::bind(if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        probe.connect(peer)?;
        probe.local_addr().map(|addr| addr.ip())
    };
    loop {
        if source().ok() != Some(local) {
            return Ok(());
        }
        let mut buf = [0u8; 4096];
        loop {
            let mut ready = events.readable().await?;
            if let Ok(result) = ready.try_io(|inner| inner.get_ref().read(&mut buf)) {
                let n = result?;
                if n >= 4
                    && matches!(
                        i32::from(buf[3]),
                        libc::RTM_ADD
                            | libc::RTM_DELETE
                            | libc::RTM_CHANGE
                            | libc::RTM_NEWADDR
                            | libc::RTM_DELADDR
                            | libc::RTM_IFINFO
                            | libc::RTM_IFINFO2
                    )
                {
                    break;
                }
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn changed(_: SocketAddr, _: IpAddr) -> std::io::Result<()> {
    std::future::pending().await
}
