//! UDP echo loop: record the packet, then send the datagram back unchanged.

use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mtp_core::clock::now_ns;
use tokio::net::UdpSocket;

use crate::aggregator::Aggregator;
use crate::config::Out;

pub async fn reflect(sock: Arc<UdpSocket>, agg: Arc<Mutex<Aggregator>>, out: Out) {
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, addr) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            // ICMP errors from earlier sends can surface here on some platforms.
            Err(e) if matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused) => continue,
            Err(e) => {
                eprintln!("[server] udp recv error: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let now = now_ns();
        let announce = agg
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .on_packet(&buf[..n], &addr.ip().to_string(), addr.port(), now);
        if let Some(line) = announce {
            out.line(line);
        }
        // Echo even unparseable datagrams, as the Python server did.
        let _ = sock.send_to(&buf[..n], addr).await;
    }
}
