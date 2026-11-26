//! Socket construction (SO_REUSEADDR, v6-only) via socket2.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

fn parse(host: &str, port: u16) -> Result<SocketAddr> {
    let ip: IpAddr = host.parse().with_context(|| format!("invalid IP address {host:?}"))?;
    Ok(SocketAddr::new(ip, port))
}

fn socket(addr: &SocketAddr, ty: Type, proto: Protocol) -> Result<Socket> {
    let s = Socket::new(Domain::for_address(*addr), ty, Some(proto))?;
    s.set_reuse_address(true)?;
    if addr.is_ipv6() {
        // Best effort, like the Python original.
        let _ = s.set_only_v6(true);
    }
    s.set_nonblocking(true)?;
    Ok(s)
}

pub fn bind_udp(host: &str, port: u16) -> Result<UdpSocket> {
    let addr = parse(host, port)?;
    let s = socket(&addr, Type::DGRAM, Protocol::UDP)?;
    s.bind(&addr.into()).with_context(|| format!("binding UDP {addr}"))?;
    Ok(UdpSocket::from_std(s.into())?)
}

pub fn bind_tcp(host: &str, port: u16) -> Result<TcpListener> {
    let addr = parse(host, port)?;
    let s = socket(&addr, Type::STREAM, Protocol::TCP)?;
    s.bind(&addr.into()).with_context(|| format!("binding TCP {addr}"))?;
    s.listen(100)?;
    Ok(TcpListener::from_std(s.into())?)
}
