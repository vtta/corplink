//! Pure-Rust CorpLink/feilian WireGuard-over-TCP userspace tunnel.
//! boringtun (WG crypto) + smoltcp (userspace TCP/IP) + corplink TCP transport.
//! Exposes `Tunnel::connect(host_ip, port) -> TunnelStream` (AsyncRead+AsyncWrite).
use anyhow::{bail, Context, Result};
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context as TaskCtx, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

mod device;
mod path;
use std::{sync::Arc, time::Duration};
use tokio::task::{AbortHandle, JoinSet};
pub mod socks5;
use device::VirtDevice;

/// CorpLink/feilian replaces WireGuard's stock Noise handshake identifier.
const CORPLINK_HANDSHAKE_IDENTIFIER: &[u8] = b"CorpLink v1 vpn@feilian-----------";

#[derive(serde::Deserialize, Clone)]
pub struct WgConf {
    pub address: String,      // e.g. "10.0.0.2/24"
    pub peer_address: String, // e.g. "192.0.2.1:443"
    pub mtu: u32,
    pub private_key: String, // base64
    pub peer_key: String,    // base64
    pub dns: String,
    pub protocol: i32, // 1 = tcp
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

fn b64_32(s: &str) -> Result<[u8; 32]> {
    let v = base64::engine::general_purpose::STANDARD.decode(s.trim())?;
    if v.len() != 32 {
        bail!("key not 32 bytes");
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}
fn now() -> SmolInstant {
    SmolInstant::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64,
    )
}

enum Cmd {
    Connect {
        dst: (Ipv4Addr, u16),
        resp: oneshot::Sender<Result<TunnelStream>>,
    },
    Resolve {
        name: String,
        resp: oneshot::Sender<Result<Ipv4Addr>>,
    },
}

#[derive(Clone)]
pub struct Tunnel {
    cmd: mpsc::Sender<Cmd>,
    worker: Arc<Worker>,
    ended: tokio::sync::watch::Receiver<Option<String>>,
}

struct Worker(AbortHandle);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Tunnel {
    /// Establish the tunnel from a dumped WgConf and spawn the datapath task.
    pub async fn start(conf: WgConf) -> Result<Tunnel> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (ended_tx, ended) = tokio::sync::watch::channel(None);
        let task = tokio::spawn(async move {
            let result = run_tunnel(conf, cmd_rx, ready_tx).await;
            ended_tx.send_replace(Some(match &result {
                Ok(()) => "tunnel stopped".to_owned(),
                Err(error) => format!("{error:#}"),
            }));
            result
        });
        let tunnel = Tunnel {
            cmd: cmd_tx,
            worker: Arc::new(Worker(task.abort_handle())),
            ended,
        };
        if tokio::time::timeout(Duration::from_secs(15), ready_rx)
            .await
            .context("gateway dial or WireGuard handshake timed out")?
            .is_err()
        {
            task.await.context("tunnel worker stopped")??;
            bail!("gateway closed before WireGuard handshake");
        }
        Ok(tunnel)
    }

    /// Completes when this generation can no longer carry connections.
    pub async fn closed(&self) {
        self.cmd.closed().await;
    }

    pub fn is_closed(&self) -> bool {
        self.cmd.is_closed()
    }

    pub async fn end_reason(&self) -> String {
        let mut ended = self.ended.clone();
        let reason = ended.wait_for(Option::is_some).await;
        reason
            .ok()
            .and_then(|r| r.clone())
            .unwrap_or_else(|| "tunnel stopped".into())
    }

    pub fn stop(&self) {
        self.worker.0.abort();
    }

    /// Resolve a hostname to an IPv4 address using the VPN's DNS server, through the tunnel.
    pub async fn resolve(&self, name: &str) -> Result<Ipv4Addr> {
        if let Ok(ip) = name.parse::<Ipv4Addr>() {
            return Ok(ip);
        }
        let name = name.strip_suffix('.').unwrap_or(name);
        if name.len() > 253 || name.split('.').any(|s| s.is_empty() || s.len() > 63) {
            bail!("invalid DNS name");
        }
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Resolve {
                name: name.to_string(),
                resp: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("tunnel closed"))?;
        tokio::time::timeout(Duration::from_secs(8), rx)
            .await
            .context("tunnel DNS timed out")?
            .context("resolve dropped")?
    }

    /// Convenience: resolve `host` (name or IPv4 literal) then connect to `host:port`.
    pub async fn connect_host(&self, host: &str, port: u16) -> Result<TunnelStream> {
        let ip = match host.parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(_) => self.resolve(host).await?,
        };
        self.connect(ip, port).await
    }

    /// Open a TCP connection to `ip:port` through the tunnel.
    pub async fn connect(&self, ip: Ipv4Addr, port: u16) -> Result<TunnelStream> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Connect {
                dst: (ip, port),
                resp: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("tunnel closed"))?;
        tokio::time::timeout(Duration::from_secs(15), rx)
            .await
            .context("tunnel TCP connect timed out")?
            .context("connect dropped")?
    }
}

/// Duplex stream over the tunnel: implements AsyncRead + AsyncWrite.
pub struct TunnelStream {
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    leftover: Vec<u8>,
    eof: bool,
}
impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.leftover.is_empty() {
            let n = self.leftover.len().min(buf.remaining());
            buf.put_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            return Poll::Ready(Ok(()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.leftover = data[n..].to_vec();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncWrite for TunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let tx = self
            .write_tx
            .as_ref()
            .ok_or(std::io::ErrorKind::BrokenPipe)?;
        match tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tunnel closed",
            ))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
        self.write_tx.take();
        Poll::Ready(Ok(()))
    }
}

// ---- corplink TCP transport framing: u32-le length prefix + payload ----
fn frame(buf: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + buf.len());
    v.extend_from_slice(&(buf.len() as u32).to_le_bytes());
    v.extend_from_slice(buf);
    v
}

struct Conn {
    handle: smoltcp::iface::SocketHandle,
    to_app: Option<mpsc::Sender<Vec<u8>>>, // event loop -> app (recv data)
    from_app: mpsc::UnboundedReceiver<Vec<u8>>, // app -> event loop (send data)
    pending: VecDeque<Vec<u8>>,            // app bytes not yet accepted by socket
    resp: Option<oneshot::Sender<Result<TunnelStream>>>, // completed on TCP connect
    stream: Option<TunnelStream>,          // pre-built, handed out on connect
    fin_sent: bool,
}

async fn run_tunnel(
    conf: WgConf,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    ready: oneshot::Sender<()>,
) -> Result<()> {
    let priv_k = b64_32(&conf.private_key)?;
    let peer_k = b64_32(&conf.peer_key)?;
    let our_ip: Ipv4Addr = conf.address.split('/').next().unwrap().parse()?;
    let prefix: u8 = conf
        .address
        .split('/')
        .nth(1)
        .unwrap_or("32")
        .parse()
        .unwrap_or(32);
    let mtu = conf.mtu as usize;

    let sp = x25519_dalek::StaticSecret::from(priv_k);
    let pp = x25519_dalek::PublicKey::from(peer_k);
    let mut tunn = Tunn::new_with_identifier(
        sp,
        pp,
        None,
        Some(10),
        0,
        None,
        Some(CORPLINK_HANDSHAKE_IDENTIFIER),
    );

    let tcp = TcpStream::connect(&conf.peer_address)
        .await
        .context("connect wg endpoint")?;
    let peer = tcp.peer_addr()?;
    let local = tcp.local_addr()?;
    let path_changed = path::changed(peer, local.ip());
    tokio::pin!(path_changed);
    let (mut rd, mut wr) = tcp.into_split();
    // Dropping the worker cancels both halves and releases the outer TCP socket.
    let mut io_tasks = JoinSet::new();

    // writer task
    let (net_out_tx, mut net_out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    io_tasks.spawn(async move {
        while let Some(pkt) = net_out_rx.recv().await {
            if wr.write_all(&frame(&pkt)).await.is_err() {
                break;
            }
        }
    });
    // reader task
    let (wg_in_tx, mut wg_in_rx) = mpsc::channel::<Vec<u8>>(1024);
    io_tasks.spawn(async move {
        loop {
            let mut len = [0u8; 4];
            if rd.read_exact(&mut len).await.is_err() {
                break;
            }
            let n = u32::from_le_bytes(len) as usize;
            if n == 0 || n > 65535 {
                break;
            }
            let mut b = vec![0u8; n];
            if rd.read_exact(&mut b).await.is_err() {
                break;
            }
            if wg_in_tx.send(b).await.is_err() {
                break;
            }
        }
    });

    // smoltcp iface
    let mut device = VirtDevice::new(mtu);
    let mut iface = Interface::new(
        Config::new(smoltcp::wire::HardwareAddress::Ip),
        &mut device,
        now(),
    );
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::from(our_ip)),
            prefix,
        ));
    });
    // default route so smoltcp emits packets for arbitrary destinations (gateway irrelevant for Ip medium)
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(
            our_ip.octets()[0],
            our_ip.octets()[1],
            our_ip.octets()[2],
            1,
        ))
        .ok();

    let mut sockets = SocketSet::new(Vec::new());
    let dns_ip: Ipv4Addr = conf.dns.parse().unwrap_or(Ipv4Addr::new(1, 1, 1, 1));
    let dns_handle = {
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 8 * 1024]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 8 * 1024]);
        let mut sock = udp::Socket::new(rx, tx);
        sock.bind(40000u16).ok();
        sockets.add(sock)
    };
    let mut pending_dns: Vec<(u16, oneshot::Sender<Result<Ipv4Addr>>)> = Vec::new();
    let mut dns_id: u16 = 1;
    let mut conns: Vec<Conn> = Vec::new();
    let mut buf = vec![0u8; 65535];
    let mut next_port: u16 = 0;

    // kick handshake
    if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&[], &mut buf) {
        let _ = net_out_tx.send(p.to_vec());
    }
    let mut ready = Some(ready);

    let mut tick = tokio::time::interval(std::time::Duration::from_millis(5));
    loop {
        tokio::select! {
            result = &mut path_changed => {
                result.context("gateway path monitor")?;
                bail!("gateway source address changed");
            }
            _ = io_tasks.join_next() => bail!("gateway TCP stream closed"),
            packet = wg_in_rx.recv() => {
                let pkt = packet.context("gateway TCP reader closed")?;
                decap_all(&mut tunn, &pkt, &mut device, &net_out_tx);
                if ready.is_some() && tunn.time_since_last_handshake().is_some() {
                    if let Some(done) = ready.take() { let _ = done.send(()); }
                }
            }
            _ = tick.tick() => {}
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return Ok(()); };
                match cmd {
                    Cmd::Resolve { name, resp } => {
                        dns_id = dns_id.wrapping_add(1);
                        let q = build_dns_query(&name, dns_id);
                        let sock = sockets.get_mut::<udp::Socket>(dns_handle);
                        match sock.send_slice(&q, (IpAddress::Ipv4(Ipv4Address::from(dns_ip)), 53)) {
                            Ok(()) => pending_dns.push((dns_id, resp)),
                            Err(e) => { let _ = resp.send(Err(anyhow::anyhow!("dns send: {e}"))); }
                        }
                    }
                    Cmd::Connect { dst, resp } => {
                        let sock = tcp::Socket::new(
                            tcp::SocketBuffer::new(vec![0u8; 128 * 1024]),
                            tcp::SocketBuffer::new(vec![0u8; 128 * 1024]),
                        );
                        next_port = next_port.wrapping_add(1);
                        let local_port = 20000u16.wrapping_add(next_port % 40000);
                        let handle = sockets.add(sock);
                        let remote = (IpAddress::Ipv4(Ipv4Address::from(dst.0)), dst.1);
                        let s = sockets.get_mut::<tcp::Socket>(handle);
                        match s.connect(iface.context(), remote, local_port) {
                            Ok(()) => {
                                let (to_app, read_rx) = mpsc::channel::<Vec<u8>>(256);
                                let (write_tx, from_app) = mpsc::unbounded_channel::<Vec<u8>>();
                                let stream = TunnelStream { read_rx, write_tx: Some(write_tx), leftover: Vec::new(), eof: false };
                                conns.push(Conn {
                                    handle, to_app: Some(to_app), from_app,
                                    pending: VecDeque::new(),
                                    resp: Some(resp), stream: Some(stream), fin_sent: false,
                                });
                            }
                            Err(e) => { let _ = resp.send(Err(anyhow::anyhow!("smoltcp connect: {e}"))); sockets.remove(handle); }
                        }
                    }
                }
            }
        }

        // update timers (keepalive / rehandshake)
        loop {
            match tunn.update_timers(&mut buf) {
                TunnResult::Err(boringtun::noise::errors::WireGuardError::ConnectionExpired) => {
                    bail!("WireGuard session expired")
                }
                TunnResult::WriteToNetwork(p) => {
                    let _ = net_out_tx.send(p.to_vec());
                }
                _ => break,
            }
        }
        // drive smoltcp
        let _ = iface.poll(now(), &mut device, &mut sockets);
        {
            let sock = sockets.get_mut::<udp::Socket>(dns_handle);
            while let Ok((data, meta)) = sock.recv() {
                if meta.endpoint.addr != IpAddress::Ipv4(dns_ip) || meta.endpoint.port != 53 {
                    continue;
                }
                if let Some((id, ip)) = parse_dns_a(data) {
                    if let Some(pos) = pending_dns.iter().position(|(pid, _)| *pid == id) {
                        let (_, resp) = pending_dns.remove(pos);
                        let _ = resp.send(ip.ok_or_else(|| anyhow::anyhow!("no A record")));
                    }
                }
            }
        }
        pending_dns.retain(|(_, resp)| !resp.is_closed());
        pump(&mut sockets, &mut conns);
        // encapsulate outgoing IP packets
        while let Some(ip) = device.tx.pop_front() {
            if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&ip, &mut buf) {
                let _ = net_out_tx.send(p.to_vec());
            }
        }
    }
}

fn build_dns_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}
fn parse_dns_a(resp: &[u8]) -> Option<(u16, Option<Ipv4Addr>)> {
    if resp.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([resp[0], resp[1]]);
    let qd = u16::from_be_bytes([resp[4], resp[5]]);
    let an = u16::from_be_bytes([resp[6], resp[7]]);
    if resp[2] & 0x80 == 0 {
        return None;
    }
    let mut i = 12;
    fn skip_name(packet: &[u8], i: &mut usize) -> Option<()> {
        loop {
            let len = *packet.get(*i)?;
            *i += 1;
            if len == 0 {
                return Some(());
            }
            if len & 0xc0 == 0xc0 {
                packet.get(*i)?;
                *i += 1;
                return Some(());
            }
            if len > 63 {
                return None;
            }
            packet.get(*i..*i + len as usize)?;
            *i += len as usize;
        }
    }
    for _ in 0..qd {
        skip_name(resp, &mut i)?;
        resp.get(i..i + 4)?;
        i += 4;
    }
    for _ in 0..an {
        skip_name(resp, &mut i)?;
        let header = resp.get(i..i + 10)?;
        let len = u16::from_be_bytes([header[8], header[9]]) as usize;
        i += 10;
        let data = resp.get(i..i + len)?;
        if header[..4] == [0, 1, 0, 1] && len == 4 {
            return Some((id, Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))));
        }
        i += len;
    }
    Some((id, None))
}

// boringtun decapsulate loop
fn decap_all(
    tunn: &mut Tunn,
    pkt: &[u8],
    device: &mut VirtDevice,
    net_out: &mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut scratch = vec![0u8; 65535];
    let mut input: Vec<u8> = pkt.to_vec();
    loop {
        let r = tunn.decapsulate(None, &input, &mut scratch);
        match r {
            TunnResult::WriteToNetwork(p) => {
                let _ = net_out.send(p.to_vec());
                input = Vec::new();
            }
            TunnResult::WriteToTunnelV4(ip, _) => {
                device.rx.push_back(ip.to_vec());
                input = Vec::new();
            }
            TunnResult::WriteToTunnelV6(ip, _) => {
                device.rx.push_back(ip.to_vec());
                input = Vec::new();
            }
            TunnResult::Done => break,
            TunnResult::Err(_) => break,
        }
    }
}

// move data between smoltcp sockets and app channels; complete pending connects
fn pump(sockets: &mut SocketSet, conns: &mut Vec<Conn>) {
    conns.retain_mut(|c| {
        let s = sockets.get_mut::<tcp::Socket>(c.handle);
        if c.resp.as_ref().is_some_and(|r| r.is_closed()) {
            s.abort();
        }
        // hand out the stream once the TCP connection is established
        if c.resp.is_some() && s.may_send() {
            if let (Some(resp), Some(stream)) = (c.resp.take(), c.stream.take()) {
                let _ = resp.send(Ok(stream));
            }
        }
        // app -> socket
        while let Ok(data) = c.from_app.try_recv() {
            c.pending.push_back(data);
        }
        while let Some(front) = c.pending.front_mut() {
            if !s.can_send() {
                break;
            }
            match s.send_slice(front) {
                Ok(n) if n == front.len() => {
                    c.pending.pop_front();
                }
                Ok(n) if n > 0 => {
                    front.drain(..n);
                    break;
                }
                _ => break,
            }
        }
        // if app closed its write end and everything flushed, send FIN
        if !c.fin_sent && c.pending.is_empty() && c.from_app.is_closed() && c.resp.is_none() {
            s.close();
            c.fin_sent = true;
        }
        // socket -> app
        while s.can_recv() {
            let Some(sender) = &c.to_app else { break };
            let slot = match sender.try_reserve() {
                Ok(slot) => slot,
                Err(mpsc::error::TrySendError::Full(_)) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    s.abort();
                    break;
                }
            };
            let mut tmp = vec![0u8; 32 * 1024];
            match s.recv_slice(&mut tmp) {
                Ok(n) if n > 0 => {
                    tmp.truncate(n);
                    slot.send(tmp);
                }
                _ => break,
            }
        }
        if !s.may_recv() && c.resp.is_none() {
            c.to_app.take();
        }
        if s.state() == tcp::State::Closed {
            sockets.remove(c.handle);
            false
        } else {
            true
        }
    });
}

#[cfg(test)]
mod recovery_tests;
