//! TCP control channel behaviour through the public `Server` API.

mod common;

use std::time::Duration;

use common::*;
use mtp_core::clock::now_ns;
use mtp_core::control::HelloResp;
use mtp_core::wire::{build_packet, Mode};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};

async fn read_resp(rd: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> HelloResp {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), rd.read_line(&mut line))
        .await
        .expect("no response")
        .unwrap();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad resp {line:?}: {e}"))
}

async fn hello(server: &mtp_server::Server, msg: &str) -> (HelloResp, BufReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf) {
    let tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
    let (rd, mut wr) = tcp.into_split();
    wr.write_all(msg.as_bytes()).await.unwrap();
    let mut rd = BufReader::new(rd);
    let resp = read_resp(&mut rd).await;
    (resp, rd, wr)
}

#[tokio::test]
async fn brokers_audio_and_video_ports() {
    let (server, _l) = start().await;
    let (a, _r1, _w1) = hello(&server, "{\"mode\":\"audio\"}\n").await;
    let (v, _r2, _w2) = hello(&server, "{\"mode\":\"video\"}\n").await;
    let (ap, vp) = (server.audio_addrs[0].port(), server.video_addrs[0].port());
    assert_ne!(ap, vp);
    assert!(a.ok && v.ok);
    assert_eq!((a.mode.as_str(), a.server_udp_port), ("audio", ap));
    assert_eq!((v.mode.as_str(), v.server_udp_port), ("video", vp));
    for r in [&a, &v] {
        assert_eq!((r.audio_port, r.video_port), (ap, vp));
        assert_eq!(r.server_host_v4.as_deref(), Some("127.0.0.1"));
    }
}

#[tokio::test]
async fn unknown_or_missing_mode_defaults_to_audio_port() {
    let (server, _l) = start().await;
    let ap = server.audio_addrs[0].port();
    for msg in ["{\"mode\":\"hologram\"}\n", "{}\n", "{\"mode\":5}\n"] {
        let (r, _rd, _wr) = hello(&server, msg).await;
        assert!(r.ok, "{msg}");
        assert_eq!(r.server_udp_port, ap, "{msg}");
    }
}

#[tokio::test]
async fn garbage_handshake_does_not_kill_server() {
    let (server, _l) = start().await;
    for msg in ["this is not json\n", "\n", "[1,2,3]\n", "\u{0}\u{1}\u{2}\n"] {
        let tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
        let (rd, mut wr) = tcp.into_split();
        wr.write_all(msg.as_bytes()).await.unwrap();
        let mut rd = BufReader::new(rd);
        let _ = read_resp(&mut rd).await; // server still answers (as audio)
    }
    let (r, _rd, _wr) = hello(&server, "{\"mode\":\"video\"}\n").await;
    assert_eq!(r.server_udp_port, server.video_addrs[0].port());
}

#[tokio::test]
async fn binary_non_utf8_handshake_is_survived() {
    let (server, _l) = start().await;
    let tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
    let (rd, mut wr) = tcp.into_split();
    wr.write_all(&[0xFF, 0xFE, 0x80, b'\n']).await.unwrap();
    let mut rd = BufReader::new(rd);
    let _ = read_resp(&mut rd).await;
    let (r, _a, _b) = hello(&server, "{\"mode\":\"audio\"}\n").await;
    assert!(r.ok);
}

#[tokio::test]
async fn oversized_line_is_survived() {
    let (server, _l) = start().await;
    let tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
    let (rd, mut wr) = tcp.into_split();
    let mut big = vec![b'a'; 200_000];
    big.push(b'\n');
    // The server may stop reading mid-way; ignore a write error from that.
    let writer = tokio::spawn(async move {
        let _ = wr.write_all(&big).await;
        wr
    });
    let mut rd = BufReader::new(rd);
    let _ = read_resp(&mut rd).await;
    drop(writer);
    let (r, _a, _b) = hello(&server, "{\"mode\":\"audio\"}\n").await;
    assert!(r.ok);
}

#[tokio::test]
async fn partial_handshake_then_disconnect_does_not_crash() {
    let (server, _l) = start().await;
    {
        let mut tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
        tcp.write_all(b"{\"mode\":\"vid").await.unwrap();
        // close without newline
    }
    {
        // connect and close immediately with no bytes
        let _tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
    }
    let (r, _a, _b) = hello(&server, "{\"mode\":\"video\"}\n").await;
    assert!(r.ok);
    assert_eq!(r.server_udp_port, server.video_addrs[0].port());
}

#[tokio::test]
async fn handshake_split_across_writes_is_reassembled() {
    let (server, _l) = start().await;
    let tcp = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
    let (rd, mut wr) = tcp.into_split();
    wr.write_all(b"{\"mode\":").await.unwrap();
    wr.flush().await.unwrap();
    // yield so the server sees the first fragment before the second
    tokio::task::yield_now().await;
    wr.write_all(b"\"video\"}\n").await.unwrap();
    let mut rd = BufReader::new(rd);
    let r = read_resp(&mut rd).await;
    assert_eq!(r.mode, "video");
    assert_eq!(r.server_udp_port, server.video_addrs[0].port());
}

#[tokio::test]
async fn empty_connection_produces_no_final_stats() {
    let (server, lines) = start().await;
    {
        let _t = TcpStream::connect(server.tcp_addrs[0]).await.unwrap();
    }
    // A completed handshake afterwards is the sync point: its final stats appear
    // exactly once.
    let (_r, rd, wr) = hello(&server, "{\"mode\":\"audio\"}\n").await;
    drop((rd, wr));
    wait_line(&lines, "Final stats for peer").await;
    wait_line(&lines, "Bytes: out=").await;
    let n = lines.lock().unwrap().iter().filter(|l| l.contains("Final stats for peer")).count();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn disconnect_emits_final_stats_with_byte_counts() {
    let (server, lines) = start().await;
    let msg = "{\"mode\":\"audio\"}\n";
    let (resp, rd, wr) = hello(&server, msg).await;
    let resp_len = mtp_core::control::to_line(&resp).unwrap().len();
    drop((rd, wr));
    let out = wait_line(&lines, "Bytes: out=").await;
    let bytes = out.iter().find(|l| l.contains("Bytes: out=")).unwrap();
    assert!(bytes.contains(&format!("in={}", msg.len())), "{bytes}");
    assert!(bytes.contains("out="), "{bytes}");
    assert!(out.iter().any(|l| l.contains("(control disconnect)")));
    // response written by the server is a re-serialisation of the same struct
    assert!(bytes.contains(&format!("out={resp_len}")), "{bytes} vs {resp_len}");
}

#[tokio::test]
async fn disconnect_of_one_client_leaves_others_working() {
    let (server, lines) = start().await;
    let (_r1, rd1, wr1) = hello(&server, "{\"mode\":\"audio\"}\n").await;
    let (_r2, _rd2, mut wr2) = hello(&server, "{\"mode\":\"audio\"}\n").await;
    drop((rd1, wr1));
    wait_line(&lines, "Final stats for peer").await;

    // second connection still serviced: path_update is processed
    wr2.write_all(b"{\"path_update\":{\"client_udp_port\":4242}}\n").await.unwrap();
    wait_line(&lines, "reported_udp=4242").await;
    // new clients still accepted
    let (r3, _a, _b) = hello(&server, "{\"mode\":\"video\"}\n").await;
    assert!(r3.ok);
}

#[tokio::test]
async fn server_closes_its_side_on_client_disconnect() {
    let (server, _l) = start().await;
    let (_r, mut rd, mut wr) = hello(&server, "{\"mode\":\"audio\"}\n").await;
    wr.shutdown().await.unwrap(); // half-close: server sees EOF, then closes
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), rd.read_to_end(&mut rest))
        .await
        .expect("server never closed")
        .unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn path_update_variants_do_not_break_session() {
    let (server, lines) = start().await;
    let (_r, _rd, mut wr) = hello(&server, "{\"mode\":\"audio\"}\n").await;
    for m in ["not json\n", "{\"path_update\":5}\n", "{\"path_update\":{\"client_udp_port\":null}}\n", "{}\n"] {
        wr.write_all(m.as_bytes()).await.unwrap();
    }
    wr.write_all(b"{\"path_update\":{\"client_udp_port\":777}}\n").await.unwrap();
    let out = wait_line(&lines, "reported_udp=777").await;
    assert_eq!(out.iter().filter(|l| l.contains("path_update from")).count(), 1);
}

#[tokio::test]
async fn reported_udp_port_links_control_to_udp_flow() {
    let (server, lines) = start().await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    let msg = format!("{{\"mode\":\"audio\",\"client_udp_port\":{port}}}\n");
    let (_r, _rd, _wr) = hello(&server, &msg).await;
    udp.send_to(&build_packet(Mode::Audio, 0, now_ns(), 64).unwrap(), server.audio_addrs[0])
        .await
        .unwrap();
    recv_echo(&udp).await;
    let out = wait_line(&lines, "[server] Connection:").await;
    let conn = out.iter().find(|l| l.contains("[server] Connection:")).unwrap();
    assert!(conn.contains(&format!("nat_udp={port}")) && conn.contains(&format!("reported_udp={port}")), "{conn}");
}

#[tokio::test]
async fn many_concurrent_control_clients() {
    let (server, lines) = start().await;
    let addr = server.tcp_addrs[0];
    let mut handles = vec![];
    for i in 0..16 {
        handles.push(tokio::spawn(async move {
            let mode = if i % 2 == 0 { "audio" } else { "video" };
            let tcp = TcpStream::connect(addr).await.unwrap();
            let (rd, mut wr) = tcp.into_split();
            wr.write_all(format!("{{\"mode\":\"{mode}\"}}\n").as_bytes()).await.unwrap();
            let mut rd = BufReader::new(rd);
            let r = read_resp(&mut rd).await;
            (mode, r.mode)
        }));
    }
    for h in handles {
        let (sent, got) = h.await.unwrap();
        assert_eq!(sent, got);
    }
    wait_until("16 final stats", || {
        lines.lock().unwrap().iter().filter(|l| l.contains("Final stats for peer")).count() == 16
    })
    .await;
}
