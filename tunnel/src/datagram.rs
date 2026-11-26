//! UDP sockets inside the tunnel. Each SOCKS control connection owns one binding.
use anyhow::{bail, Context, Result};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpCidr};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::sync::mpsc;

type Packet = (SocketAddrV4, Vec<u8>);

pub(crate) struct DatagramSocket {
    pub(crate) outbound: mpsc::Sender<Packet>,
    pub(crate) inbound: mpsc::Receiver<Packet>,
}

struct Binding {
    handle: SocketHandle,
    port: u16,
    peers: VecDeque<SocketAddrV4>,
    outbound: mpsc::Receiver<Packet>,
    inbound: mpsc::Sender<Packet>,
}

pub(super) struct Sockets {
    bindings: Vec<Binding>,
    allowed: Vec<IpCidr>,
    next_port: u16,
}

impl Sockets {
    pub fn new(routes: &[String]) -> Result<Self> {
        let mut allowed = Vec::new();
        for route in routes.iter().filter(|s| !s.contains(':')) {
            let cidr = if route.contains('/') {
                route.clone()
            } else {
                format!("{route}/32")
            };
            allowed.push(cidr.parse().ok().context("invalid IPv4 AllowedIPs entry")?);
        }
        Ok(Self {
            bindings: Vec::new(),
            allowed,
            next_port: 49152,
        })
    }

    pub fn bind(&mut self, sockets: &mut SocketSet<'static>) -> Result<DatagramSocket> {
        if self.bindings.len() >= 256 {
            bail!("UDP association limit reached");
        }
        let port = loop {
            let p = self.next_port;
            self.next_port = self.next_port.checked_add(1).unwrap_or(49152);
            if self.bindings.iter().all(|b| b.port != p) {
                break p;
            }
        };
        let buffer =
            || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65536]);
        let mut sock = udp::Socket::new(buffer(), buffer());
        sock.bind(port).context("bind tunnel UDP socket")?;
        let (send, outbound) = mpsc::channel(16);
        let (inbound, recv) = mpsc::channel(16);
        self.bindings.push(Binding {
            handle: sockets.add(sock),
            port,
            peers: VecDeque::new(),
            outbound,
            inbound,
        });
        Ok(DatagramSocket {
            outbound: send,
            inbound: recv,
        })
    }

    pub fn pump(&mut self, sockets: &mut SocketSet<'static>) {
        self.bindings.retain_mut(|b| {
            if b.inbound.is_closed() {
                sockets.remove(b.handle);
                return false;
            }
            let sock = sockets.get_mut::<udp::Socket>(b.handle);
            while sock.can_send() {
                let Ok((addr, bytes)) = b.outbound.try_recv() else {
                    break;
                };
                let ip = IpAddress::Ipv4(*addr.ip());
                if self.allowed.iter().any(|r| r.contains_addr(&ip)) {
                    if sock.send_slice(&bytes, (ip, addr.port())).is_ok()
                        && !b.peers.contains(&addr)
                    {
                        if b.peers.len() == 256 {
                            b.peers.pop_front();
                        }
                        b.peers.push_back(addr);
                    }
                }
            }
            while let Ok((data, meta)) = sock.recv() {
                let IpAddress::Ipv4(ip) = meta.endpoint.addr;
                let src = SocketAddrV4::new(Ipv4Addr::from(ip), meta.endpoint.port);
                if b.peers.contains(&src) {
                    let _ = b.inbound.try_send((src, data.to_vec()));
                }
            }
            true
        });
    }
}
