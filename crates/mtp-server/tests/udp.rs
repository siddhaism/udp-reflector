//! UDP reflector behaviour through the public `Server` API.

mod common;

use common::*;
use mtp_core::clock::now_ns;
use mtp_core::wire::{build_packet, Mode};
use mtp_server::Server;
use tokio::net::UdpSocket;

async fn sock() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

fn flow_packets(server: &Server, port: u16, mode: u8) -> Option<(u64, u64, u64, u64)> {
    let a = server.aggregator.lock().unwrap();
    a.flows
        .get(&("127.0.0.1".to_string(), port, mode))
        .map(|f| (f.packets, f.duplicates, f.lost, f.reordered))
}

#[tokio::test]
async fn echo_is_byte_identical_and_preserves_seq_and_timestamp() {
    let (server, _l) = start().await;
    let c = sock().await;
    let target = server.audio_addrs[0];
    for (seq, size) in [(0u64, 22usize), (1, 100), (2, 1200), (u64::MAX - 1, 8000)] {
        let sent_ns = now_ns();
        let pkt = build_packet(Mode::Audio, seq, sent_ns, size).unwrap();
        c.send_to(&pkt, target).await.unwrap();
        let echo = recv_echo(&c).await;
        assert_eq!(echo, pkt);
        let h = mtp_core::wire::parse_packet(&echo).unwrap();
        assert_eq!((h.seq, h.send_ns), (seq, sent_ns));
    }
}

#[tokio::test]
async fn echo_returns_to_sender_from_server_port() {
    let (server, _l) = start().await;
    let c = sock().await;
    let pkt = build_packet(Mode::Video, 1, 1, 64).unwrap();
    c.send_to(&pkt, server.video_addrs[0]).await.unwrap();
    let mut buf = [0u8; 128];
    let (_, from) = c.recv_from(&mut buf).await.unwrap();
    assert_eq!(from, server.video_addrs[0]);
}

#[tokio::test]
async fn ordered_packets_are_counted_without_loss() {
    let (server, _l) = start().await;
    let c = sock().await;
    let port = c.local_addr().unwrap().port();
    for seq in 0..10u64 {
        c.send_to(&build_packet(Mode::Audio, seq, now_ns(), 80).unwrap(), server.audio_addrs[0])
            .await
            .unwrap();
        recv_echo(&c).await;
    }
    // echo is sent after recording, so stats are already updated
    assert_eq!(flow_packets(&server, port, 1), Some((10, 0, 0, 0)));
}

#[tokio::test]
async fn duplicates_are_detected_not_double_counted() {
    let (server, _l) = start().await;
    let c = sock().await;
    let port = c.local_addr().unwrap().port();
    let pkt = build_packet(Mode::Audio, 5, now_ns(), 80).unwrap();
    for _ in 0..3 {
        c.send_to(&pkt, server.audio_addrs[0]).await.unwrap();
        // duplicates are still echoed
        assert_eq!(recv_echo(&c).await, pkt);
    }
    assert_eq!(flow_packets(&server, port, 1), Some((1, 2, 0, 0)));
}

#[tokio::test]
async fn gap_counts_loss_and_late_packet_counts_reorder() {
    let (server, _l) = start().await;
    let c = sock().await;
    let port = c.local_addr().unwrap().port();
    for seq in [0u64, 1, 4, 2] {
        c.send_to(&build_packet(Mode::Audio, seq, now_ns(), 64).unwrap(), server.audio_addrs[0])
            .await
            .unwrap();
        recv_echo(&c).await;
    }
    let (packets, dups, lost, reordered) = flow_packets(&server, port, 1).unwrap();
    assert_eq!((packets, dups, reordered), (4, 0, 1));
    // gap of 2 (seq 2,3) then packet 2 arrives late and is given back: 1 lost
    assert_eq!(lost, 1);
}

#[tokio::test]
async fn malformed_datagrams_are_echoed_ignored_and_do_not_kill_reflector() {
    let (server, _l) = start().await;
    let c = sock().await;
    let port = c.local_addr().unwrap().port();
    let target = server.audio_addrs[0];

    let mut bad_magic = build_packet(Mode::Audio, 1, 1, 64).unwrap();
    bad_magic[0] = b'X';
    let junk: Vec<Vec<u8>> = vec![
        vec![0u8],
        b"garbage".to_vec(),
        build_packet(Mode::Audio, 1, 1, 22).unwrap()[..21].to_vec(),
        bad_magic,
        vec![0xFF; 8000],
    ];
    for j in &junk {
        c.send_to(j, target).await.unwrap();
        // reflector echoes unparseable datagrams as the Python server did
        assert_eq!(&recv_echo(&c).await, j);
    }
    // an empty datagram must not crash it either
    c.send_to(&[], target).await.unwrap();
    assert!(recv_echo(&c).await.is_empty());

    assert!(server.aggregator.lock().unwrap().flows.is_empty());

    // still alive and tracking valid packets afterwards
    let good = build_packet(Mode::Audio, 0, now_ns(), 64).unwrap();
    c.send_to(&good, target).await.unwrap();
    assert_eq!(recv_echo(&c).await, good);
    assert_eq!(flow_packets(&server, port, 1), Some((1, 0, 0, 0)));
}

#[tokio::test]
async fn unknown_mode_byte_is_tracked_as_its_own_flow() {
    let (server, _l) = start().await;
    let c = sock().await;
    let port = c.local_addr().unwrap().port();
    let mut p = build_packet(Mode::Audio, 0, 1, 64).unwrap();
    p[5] = 77;
    c.send_to(&p, server.audio_addrs[0]).await.unwrap();
    assert_eq!(recv_echo(&c).await, p);
    assert_eq!(flow_packets(&server, port, 77), Some((1, 0, 0, 0)));
}

#[tokio::test]
async fn concurrent_flows_are_isolated() {
    let (server, lines) = start().await;
    let a = sock().await;
    let b = sock().await;
    let v = sock().await;
    let (pa, pb, pv) = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
        v.local_addr().unwrap().port(),
    );
    let audio = server.audio_addrs[0];
    let video = server.video_addrs[0];

    // Interleave: a sends 0..6 in order, b sends the same seqs with a gap, v is video.
    for seq in 0..6u64 {
        let pa_pkt = build_packet(Mode::Audio, seq, now_ns(), 64).unwrap();
        a.send_to(&pa_pkt, audio).await.unwrap();
        assert_eq!(recv_echo(&a).await, pa_pkt);

        let bseq = if seq >= 3 { seq + 1 } else { seq }; // b skips seq 3
        let pb_pkt = build_packet(Mode::Audio, bseq, now_ns(), 64).unwrap();
        b.send_to(&pb_pkt, audio).await.unwrap();
        assert_eq!(recv_echo(&b).await, pb_pkt);

        let pv_pkt = build_packet(Mode::Video, 100, now_ns(), 64).unwrap(); // same seq repeatedly
        v.send_to(&pv_pkt, video).await.unwrap();
        assert_eq!(recv_echo(&v).await, pv_pkt);
    }

    assert_eq!(flow_packets(&server, pa, 1), Some((6, 0, 0, 0)));
    assert_eq!(flow_packets(&server, pb, 1), Some((6, 0, 1, 0)));
    assert_eq!(flow_packets(&server, pv, 2), Some((1, 5, 0, 0)));
    assert_eq!(server.aggregator.lock().unwrap().flows.len(), 3);

    // each new flow announced exactly once
    let observed = lines.lock().unwrap().iter().filter(|l| l.contains("Observed UDP")).count();
    assert_eq!(observed, 3);
}

#[tokio::test]
async fn same_socket_two_modes_are_two_flows() {
    let (server, _l) = start().await;
    let c = sock().await;
    let port = c.local_addr().unwrap().port();
    for (mode, target) in [(Mode::Audio, server.audio_addrs[0]), (Mode::Video, server.video_addrs[0])] {
        let p = build_packet(mode, 0, 1, 64).unwrap();
        c.send_to(&p, target).await.unwrap();
        recv_echo(&c).await;
    }
    assert_eq!(flow_packets(&server, port, 1), Some((1, 0, 0, 0)));
    assert_eq!(flow_packets(&server, port, 2), Some((1, 0, 0, 0)));
}

#[tokio::test]
async fn burst_from_many_clients_all_echoed() {
    let (server, _l) = start().await;
    let mut clients = vec![];
    for _ in 0..8 {
        clients.push(sock().await);
    }
    for (i, c) in clients.iter().enumerate() {
        let p = build_packet(Mode::Audio, i as u64, now_ns(), 100 + i).unwrap();
        c.send_to(&p, server.audio_addrs[0]).await.unwrap();
    }
    for (i, c) in clients.iter().enumerate() {
        let echo = recv_echo(c).await;
        assert_eq!(mtp_core::wire::parse_packet(&echo).unwrap().seq, i as u64);
        assert_eq!(echo.len(), 100 + i);
    }
    wait_until("8 flows", || server.aggregator.lock().unwrap().flows.len() == 8).await;
}
