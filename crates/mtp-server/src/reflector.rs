//! UDP echo loop: record the packet, then send the datagram back unchanged.

use std::io::ErrorKind;
use std::panic::{catch_unwind, AssertUnwindSafe};
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
        // Per-datagram bookkeeping must never be able to end the echo task.
        let res = catch_unwind(AssertUnwindSafe(|| {
            let announce = agg
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .on_packet(&buf[..n], &addr.ip().to_string(), addr.port(), now);
            if let Some(line) = announce {
                out.line(line);
            }
        }));
        if res.is_err() {
            eprintln!("[server] panic while recording datagram from {addr}; continuing");
        }
        // Echo even unparseable datagrams, as the Python server did.
        let _ = sock.send_to(&buf[..n], addr).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp_core::wire::{build_packet, Mode};

    #[tokio::test]
    async fn echoes_after_hostile_datagrams() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = sock.local_addr().unwrap();
        let agg = Arc::new(Mutex::new(Aggregator::default()));
        let (out, _) = Out::captured();
        let task = tokio::spawn(reflect(sock, agg, out));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pkts = [
            build_packet(Mode::Audio, u64::MAX, 1 << 63, 64).unwrap(),
            build_packet(Mode::Audio, u64::MAX, u64::MAX, 64).unwrap(),
            build_packet(Mode::Audio, 0, 0, 64).unwrap(),
            build_packet(Mode::Audio, u64::MAX - 1, 5, 64).unwrap(),
            b"junk".to_vec(),
        ];
        for p in &pkts {
            client.send_to(p, target).await.unwrap();
            let mut buf = [0u8; 128];
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                .await
                .expect("echo timed out")
                .unwrap();
            assert_eq!(&buf[..n], &p[..]);
        }
        assert!(!task.is_finished());
        task.abort();
    }
}
