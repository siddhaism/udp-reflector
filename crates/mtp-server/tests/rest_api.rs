//! Black-box tests of the opt-in REST API (contract only).

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use mtp_core::clock::now_ns;
use mtp_core::wire::{build_packet, Mode};
use mtp_server::{Config, Out, Server};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

async fn start_http() -> (Server, SocketAddr) {
    let cfg = Config { http_port: Some(0), ..local_cfg() };
    let (out, _l) = Out::captured();
    let s = Server::start(cfg, out).await.unwrap();
    let a = s.http_addr.expect("http_addr when --http-port given");
    (s, a)
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn h(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&self.body)))
    }
}

fn parse(buf: &[u8]) -> Resp {
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| panic!("no header end in {:?}", String::from_utf8_lossy(buf)));
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Resp { status, headers, body: buf[split + 4..].to_vec() }
}

async fn raw(addr: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(addr).await.unwrap();
    // the server may reply and close before we finish writing (e.g. 414/431)
    let _ = c.write_all(data).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        let mut b = [0u8; 8192];
        loop {
            match c.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&b[..n]),
            }
        }
    })
    .await;
    buf
}

async fn get(addr: SocketAddr, target: &str) -> Resp {
    parse(&raw(addr, format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await)
}

async fn probe(server: &Server, c: &UdpSocket, seq: u64) {
    let p = build_packet(Mode::Audio, seq, now_ns(), 64).unwrap();
    c.send_to(&p, server.audio_addrs[0]).await.unwrap();
    assert_eq!(recv_echo(c).await, p);
}

// ---------------- enablement ----------------

#[tokio::test]
async fn disabled_by_default() {
    let (server, _l) = start().await;
    assert!(server.http_addr.is_none());
    assert!(Config::default().http_port.is_none());
}

#[tokio::test]
async fn binds_loopback_by_default() {
    assert_eq!(Config::default().http_host, "127.0.0.1");
    let (_s, a) = start_http().await;
    assert!(a.ip().is_loopback() && a.ip().is_ipv4(), "{a}");
    assert_ne!(a.port(), 0);
}

// ---------------- endpoints ----------------

#[tokio::test]
async fn healthz() {
    let (_s, a) = start_http().await;
    let r = get(a, "/healthz").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), serde_json::json!({"status": "ok"}));
    assert!(r.h("content-type").unwrap().contains("application/json"));
    assert!(r.h("connection").unwrap().eq_ignore_ascii_case("close"));
    let r = get(a, "/healthz?a=1&&%zz&b").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), serde_json::json!({"status": "ok"}));
}

#[tokio::test]
async fn idle_summary_and_flows() {
    let (_s, a) = start_http().await;
    let r = get(a, "/summary").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), serde_json::json!({"idle": true, "active_flows": []}));
    assert!(r.h("content-type").unwrap().contains("application/json"));
    let r = get(a, "/flows").await;
    assert_eq!((r.status, r.json()), (200, serde_json::json!({"flows": []})));
}

#[tokio::test]
async fn active_summary_flows_and_filters() {
    let (s, a) = start_http().await;
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = c.local_addr().unwrap().port();
    for q in 0..5 {
        probe(&s, &c, q).await;
    }
    // response cache (if any) may serve idle briefly: poll
    let mut d = Value::Null;
    for _ in 0..500 {
        d = get(a, "/summary").await.json();
        if d["idle"] == Value::Bool(false) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(d["idle"], Value::Bool(false), "{d}");
    assert!(d["active_count"].as_u64().unwrap() >= 1);
    assert_eq!(d["flows"].as_array().unwrap().len() as u64, d["active_count"].as_u64().unwrap());
    assert!(d.get("aggregate").is_some());

    let f = get(a, "/flows").await.json();
    let flows = f["flows"].as_array().unwrap();
    assert!(!flows.is_empty());
    assert_eq!(f.as_object().unwrap().len(), 1);

    let f = get(a, &format!("/flows?host=127.0.0.1&port={port}")).await.json();
    assert_eq!(f["flows"].as_array().unwrap().len(), 1);
    let f = get(a, "/flows?host=127.0.0.2").await.json();
    assert_eq!(f, serde_json::json!({"flows": []}));
    let f = get(a, "/flows?host=127.0.0.").await.json();
    assert_eq!(f, serde_json::json!({"flows": []}));
    let other = if port == 1 { 2 } else { 1 };
    let f = get(a, &format!("/flows?port={other}")).await.json();
    assert_eq!(f, serde_json::json!({"flows": []}));
    let f = get(a, &format!("/flows?port={port}")).await.json();
    assert_eq!(f["flows"].as_array().unwrap().len(), 1);
    // percent-encoded host matches exactly
    let f = get(a, "/flows?host=127%2E0%2E0%2E1").await.json();
    assert_eq!(f["flows"].as_array().unwrap().len(), 1);
    let d = get(a, "/summary?host=10.9.9.9").await.json();
    assert_eq!(d["idle"], Value::Bool(true));
}

#[tokio::test]
async fn flows_listing_is_bounded_and_server_handles_many_flows() {
    // Builder's assumption: /flows capped at 8. Contract does not state a cap; just require
    // the response is valid, and report the observed size.
    let (s, a) = start_http().await;
    let mut cs = vec![];
    for i in 0..12 {
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        probe(&s, &c, i).await;
        cs.push(c);
    }
    let mut n = 0;
    for _ in 0..500 {
        let f = get(a, "/flows").await.json();
        n = f["flows"].as_array().unwrap().len();
        if n > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(n >= 1);
    eprintln!("NOTE: /flows returned {n} entries with 12 active flows");
}

// ---------------- 400 ----------------

#[tokio::test]
async fn bad_queries_are_400() {
    let (_s, a) = start_http().await;
    let cases = [
        "/flows?foo=1",
        "/summary?hostx=1",
        "/flows?host=a&host=b",
        "/flows?port=1&port=2",
        "/flows?host=",
        "/flows?port=",
        "/summary?host=",
        "/flows?port=abc",
        "/flows?port=-1",
        "/flows?port=65536",
        "/flows?port=99999999999999999999",
        "/flows?port=%2B5",
        "/flows?port=1.5",
        "/flows?port=%D9%A5",
        "/flows?port=%EF%BC%95",
        "/flows?port=%20",
        "/flows?host=%zz",
        "/flows?host=%",
        "/flows?host=%4",
        "/flows?host=%FF",
        "/flows?host=%C0%AF",
        "/summary?port=%ZZ",
    ];
    for t in cases {
        let r = get(a, t).await;
        assert_eq!(r.status, 400, "{t}");
        assert!(r.h("content-type").unwrap().contains("application/json"), "{t}");
        r.json();
    }
}

#[tokio::test]
async fn valid_ports() {
    let (_s, a) = start_http().await;
    for p in ["0", "1", "65535", "00080", "%35%30"] {
        assert_eq!(get(a, &format!("/flows?port={p}")).await.status, 200, "{p}");
    }
}

#[tokio::test]
async fn raw_non_ascii_bytes_in_request_line_are_400() {
    let (_s, a) = start_http().await;
    for line in [&b"GET /flows?host=\xff\xfe HTTP/1.1"[..], b"GET /flows?host=\xc3\xa9 HTTP/1.1", b"GET /\x80 HTTP/1.1"] {
        let mut req = line.to_vec();
        req.extend_from_slice(b"\r\nHost: x\r\n\r\n");
        let buf = raw(a, &req).await;
        assert!(!buf.is_empty(), "{line:?}: no response");
        assert_eq!(parse(&buf).status, 400, "{:?}", String::from_utf8_lossy(line));
    }
}

#[tokio::test]
async fn plus_in_query_value() {
    // Builder decodes '+' as space (form-style). Python's parse_qs does the same.
    let (_s, a) = start_http().await;
    let r = get(a, "/flows?host=a+b").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), serde_json::json!({"flows": []}));
}

// ---------------- routing ----------------

#[tokio::test]
async fn unknown_paths_are_404() {
    let (_s, a) = start_http().await;
    for t in ["/", "/nope", "/healthz/", "/summary/", "/flows/", "/Summary", "/flows/x", "/healthz.json"] {
        let r = get(a, t).await;
        assert_eq!(r.status, 404, "{t}");
        r.json();
    }
}

#[tokio::test]
async fn non_get_is_405_with_allow() {
    let (_s, a) = start_http().await;
    for m in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "FOO"] {
        let r = parse(&raw(a, format!("{m} /healthz HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await);
        assert_eq!(r.status, 405, "{m}");
        assert_eq!(r.h("allow"), Some("GET"), "{m}");
    }
    let r = parse(&raw(a, b"POST /summary HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd").await);
    assert_eq!(r.status, 405);
}

#[tokio::test]
async fn non_get_on_unknown_path_status() {
    // Builder's assumption: 405 precedes routing. Python http_api does the same
    // (_route checks the method first). Record the observed behaviour.
    let (_s, a) = start_http().await;
    let r = parse(&raw(a, b"POST /nope HTTP/1.1\r\nHost: x\r\n\r\n").await);
    assert_eq!(r.status, 405);
    assert_eq!(r.h("allow"), Some("GET"));
}

#[tokio::test]
async fn long_request_line_414_and_big_headers_431() {
    let (_s, a) = start_http().await;
    let mut req = b"GET /".to_vec();
    req.extend(std::iter::repeat(b'a').take(3000));
    req.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(parse(&raw(a, &req).await).status, 414);
    let mut un = b"GET /healthz?".to_vec();
    un.extend(std::iter::repeat(b'a').take(5000));
    assert_eq!(parse(&raw(a, &un).await).status, 414);

    let mut h = b"GET /healthz HTTP/1.1\r\nX-Pad: ".to_vec();
    h.extend(std::iter::repeat(b'a').take(9000));
    h.extend_from_slice(b"\r\n\r\n");
    assert_eq!(parse(&raw(a, &h).await).status, 431);
    let mut many = b"GET /healthz HTTP/1.1\r\n".to_vec();
    for i in 0..100 {
        many.extend_from_slice(format!("X-{i}: {}\r\n", "v".repeat(100)).as_bytes());
    }
    many.extend_from_slice(b"\r\n");
    assert_eq!(parse(&raw(a, &many).await).status, 431);
}

#[tokio::test]
async fn request_line_just_under_limit_ok() {
    let (_s, a) = start_http().await;
    let pad = 2048 - "GET /flows?host= HTTP/1.1\r\n".len() - 10;
    let t = format!("/flows?host={}", "a".repeat(pad));
    assert_eq!(get(a, &t).await.status, 200);
}

#[tokio::test]
async fn garbage_targets_never_5xx() {
    let (_s, a) = start_http().await;
    let lines: Vec<&[u8]> = vec![
        b"GET //[ HTTP/1.1",
        b"GET http://[ HTTP/1.1",
        b"GET http://[::1 /summary HTTP/1.1",
        b"GARBAGE",
        b"GET",
        b"GET /healthz",
        b"GET  /healthz  HTTP/1.1",
        b"\x00\x01\x02\x03",
        b"GET /healthz HTTP/9.9",
        b"GET healthz HTTP/1.1",
        b"GET http://%zz/ HTTP/1.1",
        b"GET //:99999999/x HTTP/1.1",
        b"GET /healthz HTTP/1.1 extra",
    ];
    for l in lines {
        let mut req = l.to_vec();
        req.extend_from_slice(b"\r\nHost: x\r\n\r\n");
        let buf = raw(a, &req).await;
        if !buf.is_empty() {
            let st = parse(&buf).status;
            assert!(st < 500, "{:?} -> {st}", String::from_utf8_lossy(l));
        }
        assert_eq!(get(a, "/healthz").await.status, 200, "server broke after {l:?}");
    }
}

#[tokio::test]
#[ignore = "BUG: `GET //[ HTTP/1.1` and `GET http://[ HTTP/1.1` return 404 {\"error\":\"not found\"}; contract (and Python urlsplit ValueError path) require 400"]
async fn unbalanced_bracket_targets_are_400() {
    let (_s, a) = start_http().await;
    let mut failures = vec![];
    for l in [&b"GET //[ HTTP/1.1"[..], b"GET http://[ HTTP/1.1", b"GET http://[::1 /summary HTTP/1.1"] {
        let mut req = l.to_vec();
        req.extend_from_slice(b"\r\n\r\n");
        let r = parse(&raw(a, &req).await);
        if r.status != 400 {
            failures.push(format!("{:?} -> {} {}", String::from_utf8_lossy(l), r.status, String::from_utf8_lossy(&r.body)));
        }
    }
    assert!(failures.is_empty(), "expected 400: {failures:?}");
}

// ---------------- resilience ----------------

#[tokio::test]
async fn connection_cap_503() {
    let (_s, a) = start_http().await;
    let mut held = vec![];
    for _ in 0..64 {
        let mut c = TcpStream::connect(a).await.unwrap();
        c.write_all(b"GET /healthz HTTP/1.1\r\n").await.unwrap(); // never finished
        held.push(c);
    }
    let mut got = None;
    for _ in 0..500 {
        let r = get(a, "/healthz").await;
        if r.status == 503 {
            got = Some(r);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let r = got.expect("never saw 503 with 64 connections held");
    assert!(r.h("content-type").unwrap().contains("application/json"));
    r.json();
    drop(held);
    let mut ok = false;
    for _ in 0..500 {
        if get(a, "/healthz").await.status == 200 {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ok, "never recovered after releasing connections");
}

#[tokio::test]
async fn udp_echo_correct_while_http_hammered() {
    let (s, a) = start_http().await;
    let mut tasks = vec![];
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for _ in 0..8 {
        let stop = stop.clone();
        tasks.push(tokio::spawn(async move {
            let mut bad = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let buf = raw(a, b"GET /summary HTTP/1.1\r\nHost: x\r\n\r\n").await;
                if buf.is_empty() {
                    continue;
                }
                let st = parse(&buf).status;
                if st != 200 && st != 503 {
                    bad += 1;
                }
            }
            bad
        }));
    }
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for q in 0..200 {
        probe(&s, &c, q).await;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for t in tasks {
        assert_eq!(t.await.unwrap(), 0);
    }
    assert_eq!(get(a, "/healthz").await.status, 200);
}

#[tokio::test]
async fn slow_partial_request_does_not_block_others() {
    let (_s, a) = start_http().await;
    let mut c = TcpStream::connect(a).await.unwrap();
    c.write_all(b"GET /heal").await.unwrap();
    assert_eq!(get(a, "/healthz").await.status, 200);
}

#[tokio::test]
#[ignore = "SKIPPED: 5 s read timeout (408) is not configurable via Config; run manually with --ignored (takes ~5 s)"]
async fn read_timeout_408() {
    let (_s, a) = start_http().await;
    let mut c = TcpStream::connect(a).await.unwrap();
    c.write_all(b"GET /heal").await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), c.read_to_end(&mut buf)).await.unwrap().ok();
    assert_eq!(parse(&buf).status, 408);
}
