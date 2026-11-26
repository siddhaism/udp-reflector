//! B1 (overflow / clock edge cases), B2/B3 (caps, timeouts, lenient port parsing).
//! Run in debug: integer overflow panics only exist there.

mod common;

use std::time::Duration;

use common::*;
use mtp_core::clock::now_ns;
use mtp_core::control::HelloResp;
use mtp_core::wire::{build_packet, Mode};
use mtp_server::aggregator::Aggregator;
use mtp_server::{Config, Out, Server};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};

async fn sock() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

async fn echo_ok(c: &UdpSocket, target: std::net::SocketAddr, seq: u64, send_ns: u64) {
    let pkt = build_packet(Mode::Audio, seq, send_ns, 64).unwrap();
    c.send_to(&pkt, target).await.unwrap();
    assert_eq!(recv_echo(c).await, pkt, "seq={seq} send_ns={send_ns}");
}

fn flow(server: &Server, port: u16) -> Option<(u64, u64, u64)> {
    let a = server.aggregator.lock().unwrap();
    a.flows
        .get(&("127.0.0.1".to_string(), port, 1))
        .map(|f| (f.packets, f.lost, f.reordered))
}

// ---------------- B1 ----------------

#[tokio::test]
async fn extreme_seq_and_timestamps_are_echoed_and_do_not_wedge_reflector() {
    let (server, _l) = start().await;
    let t = server.audio_addrs[0];
    let bad = sock().await;
    let good = sock().await;
    let half = 1u64 << 63;
    let cases = [
        (u64::MAX, 0),
        (u64::MAX, half),
        (0, half),
        (1, half - 1),
        (2, half + 1),
        (3, u64::MAX),
        (u64::MAX - 1, u64::MAX),
    ];
    for (seq, ns) in cases {
        echo_ok(&bad, t, seq, ns).await;
        // a later normal packet from another client and from the same client still works
        echo_ok(&good, t, 0, now_ns()).await;
    }
    echo_ok(&bad, t, 12345, now_ns()).await;
    // reflector task is alive
    echo_ok(&good, t, 1, now_ns()).await;
}

#[tokio::test]
async fn seq_max_then_normal_same_flow_has_sane_stats() {
    let (server, _l) = start().await;
    let t = server.audio_addrs[0];
    let c = sock().await;
    let port = c.local_addr().unwrap().port();
    for seq in [u64::MAX, 0, 1, 2] {
        echo_ok(&c, t, seq, now_ns()).await;
    }
    let (packets, lost, _) = flow(&server, port).unwrap();
    assert_eq!(packets, 4);
    assert!(lost < 1_000_000, "absurd loss: {lost}");
    // summary generation over such a flow must not panic or yield NaN/garbage
    let now = now_ns();
    let mut a = server.aggregator.lock().unwrap();
    let j = mtp_server::summary::generate_summary_json(&a, now, 60.0, true);
    let text = j.map(|v| v.to_string()).unwrap_or_default();
    assert!(!text.contains("NaN"), "{text}");
    let _ = mtp_server::summary::generate_summary(&mut a, now, 60.0, false);
}

#[tokio::test]
async fn send_ns_at_or_above_2_63_gives_sane_flow_stats() {
    let (server, _l) = start().await;
    let t = server.audio_addrs[0];
    let c = sock().await;
    let port = c.local_addr().unwrap().port();
    for (i, ns) in [1u64 << 63, (1u64 << 63) + 1, u64::MAX, 0, 5].into_iter().enumerate() {
        echo_ok(&c, t, i as u64, ns).await;
    }
    let (packets, lost, reordered) = flow(&server, port).unwrap();
    assert_eq!((packets, lost, reordered), (5, 0, 0));
}

#[test]
fn aggregator_survives_clock_stepping_backwards_and_extremes() {
    let mut a = Aggregator::default();
    let p = |seq, ns| build_packet(Mode::Audio, seq, ns, 64).unwrap();
    a.on_packet(&p(0, 1_000), "h", 1, 10_000_000_000);
    // wall clock steps backwards
    a.on_packet(&p(1, 1_000), "h", 1, 5_000_000_000);
    a.on_packet(&p(2, 1u64 << 63), "h", 1, 0);
    a.on_packet(&p(u64::MAX, u64::MAX), "h", 1, u64::MAX);
    a.on_packet(&p(3, 0), "h", 1, 1);
    let f = a.flows.get(&("h".to_string(), 1, 1)).unwrap();
    assert_eq!(f.packets, 5);
    assert!(f.ipa_ms.iter().all(|v| v.is_finite() && *v >= 0.0), "{:?}", f.ipa_ms);
    assert!(f.jitter_samples_ms.iter().all(|v| v.is_finite() && *v >= 0.0));
    assert!(f.rfc_jitter_ms.is_finite());
    assert!(f.elapsed_s().is_finite());
    let now = 20_000_000_000;
    let _ = mtp_server::summary::generate_summary(&mut a, now, 60.0, false);
    let _ = mtp_server::summary::generate_summary_json(&a, now, 60.0, true);
    // prune with a "now" earlier than last activity must not underflow
    a.prune(0, 1);
}

// ---------------- B2 flow cap ----------------

#[tokio::test]
async fn flow_cap_evicts_and_keeps_echoing() {
    let cfg = Config { max_flows: 4, ..local_cfg() };
    let (out, _l) = Out::captured();
    let server = Server::start(cfg, out).await.unwrap();
    let t = server.audio_addrs[0];
    let mut clients = vec![];
    for i in 0..20u64 {
        let c = sock().await;
        echo_ok(&c, t, i, now_ns()).await;
        assert!(server.aggregator.lock().unwrap().flows.len() <= 4, "cap exceeded at client {i}");
        clients.push(c);
    }
    assert_eq!(server.aggregator.lock().unwrap().flows.len(), 4);
    // an evicted (oldest) client still gets echoes
    echo_ok(&clients[0], t, 99, now_ns()).await;
    // the most recent flows survived
    let last = clients[19].local_addr().unwrap().port();
    assert!(flow(&server, last).is_some());
}

// ---------------- B3 control caps / timeouts / ports ----------------

async fn hello_on(addr: std::net::SocketAddr, msg: &str) -> (HelloResp, BufReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = tcp.into_split();
    wr.write_all(msg.as_bytes()).await.unwrap();
    let mut rd = BufReader::new(rd);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), rd.read_line(&mut line))
        .await
        .expect("no response")
        .unwrap();
    (serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line:?}: {e}")), rd, wr)
}

#[tokio::test]
async fn control_connection_cap_rejects_extra_and_recovers() {
    let cfg = Config { max_control_conns: 2, ..local_cfg() };
    let (out, _l) = Out::captured();
    let server = Server::start(cfg, out).await.unwrap();
    let addr = server.tcp_addrs[0];
    let (_r1, rd1, wr1) = hello_on(addr, "{\"mode\":\"audio\"}\n").await;
    let (_r2, _rd2, _wr2) = hello_on(addr, "{\"mode\":\"audio\"}\n").await;

    // third: must not get a successful hello response; connection is closed.
    let mut third = TcpStream::connect(addr).await.unwrap();
    let _ = third.write_all(b"{\"mode\":\"audio\"}\n").await;
    let mut buf = Vec::new();
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        let mut b = [0u8; 1024];
        loop {
            match third.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&b[..n]),
            }
        }
    })
    .await;
    assert!(res.is_ok(), "over-cap connection was left open");
    assert!(
        serde_json::from_slice::<HelloResp>(&buf).map(|r| !r.ok).unwrap_or(true),
        "over-cap connection got a successful hello: {:?}",
        String::from_utf8_lossy(&buf)
    );

    // free a slot -> new clients admitted again
    drop((rd1, wr1));
    let mut admitted = false;
    for _ in 0..500 {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = tcp.into_split();
        let _ = wr.write_all(b"{\"mode\":\"video\"}\n").await;
        let mut rd = BufReader::new(rd);
        let mut line = String::new();
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), rd.read_line(&mut line)).await {
            if n > 0 && serde_json::from_str::<HelloResp>(&line).map(|r| r.ok).unwrap_or(false) {
                admitted = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(admitted, "slot never freed after disconnect");
}

#[tokio::test]
async fn control_idle_timeout_closes_silent_client() {
    let cfg = Config { control_idle_timeout: 0.3, ..local_cfg() };
    let (out, lines) = Out::captured();
    let server = Server::start(cfg, out).await.unwrap();
    let (_r, mut rd, _wr) = hello_on(server.tcp_addrs[0], "{\"mode\":\"audio\"}\n").await;
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), rd.read_to_end(&mut rest))
        .await
        .expect("idle client never closed")
        .ok();
    assert!(rest.is_empty());
    // closing still produces the usual final stats
    wait_line(&lines, "Final stats for peer").await;
}

#[tokio::test]
async fn control_idle_timeout_closes_connection_that_never_sends_hello() {
    let cfg = Config { control_idle_timeout: 0.3, ..local_cfg() };
    let (out, _l) = Out::captured();
    let server = Server::start(cfg, out).await.unwrap();
    let mut tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut rest))
        .await
        .expect("silent connection never closed")
        .ok();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn active_client_is_not_cut_by_idle_timeout() {
    let cfg = Config { control_idle_timeout: 1.0, ..local_cfg() };
    let (out, lines) = Out::captured();
    let server = Server::start(cfg, out).await.unwrap();
    let (_r, _rd, mut wr) = hello_on(server.tcp_addrs[0], "{\"mode\":\"audio\"}\n").await;
    for i in 0..5 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        wr.write_all(format!("{{\"path_update\":{{\"client_udp_port\":{}}}}}\n", 4000 + i).as_bytes())
            .await
            .unwrap();
    }
    wait_line(&lines, "reported_udp=4004").await;
}

#[tokio::test]
async fn client_udp_port_accepts_string_and_integral_float() {
    let (server, lines) = start().await;
    let addr = server.tcp_addrs[0];
    for (i, v) in ["\"5001\"", "5002.0", "5003"].iter().enumerate() {
        let (r, _rd, mut wr) = hello_on(addr, &format!("{{\"mode\":\"audio\",\"client_udp_port\":{v}}}\n")).await;
        assert!(r.ok, "{v}");
        // path_update with the same forms
        let pv = ["\"6001\"", "6002.0", "6003"][i];
        wr.write_all(format!("{{\"path_update\":{{\"client_udp_port\":{pv}}}}}\n").as_bytes()).await.unwrap();
        let want = format!("reported_udp=60{:02}", i + 1);
        wait_line(&lines, &want).await;
    }
    // hello forms are reflected in the connection line once UDP arrives
    let udp = sock().await;
    echo_ok(&udp, server.audio_addrs[0], 0, now_ns()).await;
    let out = wait_line(&lines, "[server] Connection:").await;
    let all = out.join("\n");
    assert!(all.contains("reported_udp=5003") || all.contains("reported_udp=60"), "{all}");
}

#[tokio::test]
async fn client_udp_port_junk_is_ignored_not_fatal() {
    let (server, lines) = start().await;
    let addr = server.tcp_addrs[0];
    for v in ["\"abc\"", "1.5", "70000", "-1", "null", "true", "[1]", "{}", "\"\""] {
        let (r, _rd, mut wr) = hello_on(addr, &format!("{{\"mode\":\"audio\",\"client_udp_port\":{v}}}\n")).await;
        assert!(r.ok, "{v}");
        wr.write_all(format!("{{\"path_update\":{{\"client_udp_port\":{v}}}}}\n").as_bytes()).await.unwrap();
    }
    let (_r, _rd, mut wr) = hello_on(addr, "{\"mode\":\"audio\"}\n").await;
    wr.write_all(b"{\"path_update\":{\"client_udp_port\":4321}}\n").await.unwrap();
    wait_line(&lines, "reported_udp=4321").await;
}
