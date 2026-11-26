#![allow(dead_code)]
//! Shared helpers for loopback tests.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mtp_server::{Config, Out, Server};
use tokio::net::UdpSocket;

pub type Lines = Arc<Mutex<Vec<String>>>;

pub fn local_cfg() -> Config {
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

pub async fn start() -> (Server, Lines) {
    let (out, lines) = Out::captured();
    (Server::start(local_cfg(), out).await.unwrap(), lines)
}

/// Poll `cond` until true; generous 10s bound, only used to wait for async server work.
pub async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

pub async fn wait_line(lines: &Lines, needle: &str) -> Vec<String> {
    wait_until(needle, || lines.lock().unwrap().iter().any(|l| l.contains(needle))).await;
    lines.lock().unwrap().clone()
}

pub async fn recv_echo(sock: &UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 70_000];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    buf.truncate(n);
    buf
}
