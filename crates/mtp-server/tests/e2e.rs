//! End-to-end loopback test: handshake, echo, connection line, final stats.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mtp_core::clock::now_ns;
use mtp_core::control::HelloResp;
use mtp_core::wire::{build_packet, Mode};
use mtp_server::{Config, Out, Server};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};

fn local_cfg() -> Config {
    Config {
        tcp_host_v4: "127.0.0.1".into(),
        tcp_host_v6: String::new(),
        tcp_port: 0,
        udp_host_v4: "127.0.0.1".into(),
        udp_host_v6: String::new(),
        audio_port: 0,
        video_port: 0,
        ..Config::default()
    }
}

async fn wait_for(buf: &Arc<Mutex<Vec<String>>>, needle: &str) -> Vec<String> {
    for _ in 0..100 {
        let lines = buf.lock().unwrap().clone();
        if lines.iter().any(|l| l.contains(needle)) {
            return lines;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never saw {needle:?}; got {:#?}", buf.lock().unwrap());
}

#[tokio::test]
async fn handshake_echo_and_final_stats() {
    let (out, captured) = Out::captured();
    let server = Server::start(local_cfg(), out).await.unwrap();

    // Handshake for video mode.
    let mut tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let hello = format!("{{\"mode\":\"video\",\"client_udp_port\":{}}}\n", udp.local_addr().unwrap().port());
    tcp.write_all(hello.as_bytes()).await.unwrap();
    let (rd, mut wr) = tcp.into_split();
    let mut rd = BufReader::new(rd);
    let mut line = String::new();
    rd.read_line(&mut line).await.unwrap();
    let resp: HelloResp = serde_json::from_str(&line).unwrap();
    assert!(resp.ok);
    assert_eq!(resp.server_udp_port, server.video_addrs[0].port());
    assert_ne!(resp.server_udp_port, server.audio_addrs[0].port());

    // Echo 5 packets; the reflected bytes must be identical.
    let target = server.video_addrs[0];
    for seq in 0..5u64 {
        let pkt = build_packet(Mode::Video, seq, now_ns(), 200).unwrap();
        udp.send_to(&pkt, target).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buf))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(from, target);
        assert_eq!(&buf[..n], &pkt[..]);
    }

    // Regression: the Connection line is printed (it used to raise UnboundLocalError).
    let lines = wait_for(&captured, "[server] Connection:").await;
    let conn = lines.iter().find(|l| l.contains("[server] Connection:")).unwrap();
    assert!(conn.contains("mode=video"), "{conn}");
    assert!(conn.contains(&format!("media_udp={}", resp.server_udp_port)), "{conn}");
    assert!(conn.contains(&format!("nat_udp={}", udp.local_addr().unwrap().port())), "{conn}");
    assert!(conn.contains(&format!("reported_udp={}", udp.local_addr().unwrap().port())), "{conn}");

    // Path update is acknowledged.
    wr.write_all(b"{\"path_update\":{\"client_udp_port\":4242}}\n").await.unwrap();
    wait_for(&captured, "path_update from 127.0.0.1 reported_udp=4242").await;

    // Closing the control channel prints final stats.
    drop(wr);
    drop(rd);
    let lines = wait_for(&captured, "=== Control Stats ===").await;
    assert!(lines.iter().any(|l| l.starts_with("Final stats for peer")));
    assert!(lines.iter().any(|l| l.contains("  - Packets: 5")));
    assert!(lines.iter().any(|l| l.contains("Hello->Resp (ms):") && !l.contains("n/a")));
}

#[tokio::test]
async fn audio_is_the_default_mode_and_garbage_hello_is_tolerated() {
    let (out, _captured) = Out::captured();
    let server = Server::start(local_cfg(), out).await.unwrap();
    let mut tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
    tcp.write_all(b"not json\n").await.unwrap();
    let mut rd = BufReader::new(tcp);
    let mut line = String::new();
    rd.read_line(&mut line).await.unwrap();
    let resp: HelloResp = serde_json::from_str(&line).unwrap();
    assert_eq!(resp.mode, "audio");
    assert_eq!(resp.server_udp_port, server.audio_addrs[0].port());
}

#[tokio::test]
async fn needs_at_least_one_address_family() {
    let cfg = Config { udp_host_v4: String::new(), udp_host_v6: String::new(), ..local_cfg() };
    assert!(Server::start(cfg, Out::captured().0).await.is_err());
}
