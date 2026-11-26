//! Optional read-only REST layer (`--http-port`).
//!
//! A small, strict front end reads and bounds the request head (so the status
//! codes for oversized/slow/malformed requests are exact), then dispatches GET
//! requests to an axum `Router`. One response per connection, `Connection: close`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use mtp_core::clock::now_ns;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tower::ServiceExt;

use crate::aggregator::Aggregator;
use crate::summary::{flow_json, snapshot_flows, summary_json_from, Filter};

/// Longest request line accepted (excluding the line terminator).
pub const MAX_REQUEST_LINE: usize = 2048;
/// Largest header block accepted (everything after the request line).
pub const MAX_HEADER_BYTES: usize = 8192;
/// Time allowed to receive the full request head.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Concurrent connections served; extras get an immediate 503.
pub const MAX_CONNECTIONS: usize = 64;
/// How long a computed summary for a given filter is reused.
pub const CACHE_TTL: Duration = Duration::from_millis(250);
const MAX_CACHE_ENTRIES: usize = 64;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

struct Computed {
    summary: Value,
    flows: Value,
}

pub struct HttpState {
    agg: Arc<Mutex<Aggregator>>,
    idle_ttl_s: f64,
    cache: Mutex<HashMap<Filter, (Instant, Arc<Computed>)>>,
}

impl HttpState {
    pub fn new(agg: Arc<Mutex<Aggregator>>, idle_ttl_s: f64) -> Arc<Self> {
        Arc::new(Self { agg, idle_ttl_s, cache: Mutex::new(HashMap::new()) })
    }

    fn computed(&self, filter: &Filter) -> Arc<Computed> {
        let now = Instant::now();
        {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, c)) = cache.get(filter) {
                if now.duration_since(*at) < CACHE_TTL {
                    return c.clone();
                }
            }
        }
        // Snapshot under the aggregator lock, compute after releasing it.
        let snap = {
            let a = self.agg.lock().unwrap_or_else(|e| e.into_inner());
            snapshot_flows(&a, now_ns(), self.idle_ttl_s, filter)
        };
        let c = Arc::new(Computed {
            summary: summary_json_from(&snap, false).unwrap_or_else(|| json!({"idle": true, "active_flows": []})),
            flows: json!({"flows": snap.iter().map(flow_json).collect::<Vec<_>>()}),
        });
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, (at, _)| now.duration_since(*at) < CACHE_TTL);
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(filter.clone(), (now, c.clone()));
        c
    }
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Strict percent-decoding (`+` is a space); `None` on a bad escape or invalid UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hi = hex(*b.get(i + 1)?)?;
                let lo = hex(*b.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Parse `?host=&port=` strictly: only those keys, each at most once, none blank.
pub fn parse_filter(query: Option<&str>) -> Result<Filter, String> {
    let mut f = Filter::default();
    let q = match query {
        None | Some("") => return Ok(f),
        Some(q) => q,
    };
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').ok_or_else(|| format!("malformed query parameter '{pair}'"))?;
        let k = percent_decode(k).ok_or("invalid percent-encoding in query")?;
        let v = percent_decode(v).ok_or("invalid percent-encoding in query")?;
        if v.is_empty() {
            return Err(format!("blank value for '{k}'"));
        }
        match k.as_str() {
            "host" => {
                if f.host.replace(v).is_some() {
                    return Err("duplicate parameter 'host'".into());
                }
            }
            "port" => {
                if f.port.is_some() {
                    return Err("duplicate parameter 'port'".into());
                }
                if !v.bytes().all(|c| c.is_ascii_digit()) {
                    return Err("port must be ASCII digits".into());
                }
                let mut n: u32 = 0;
                for c in v.bytes() {
                    n = n * 10 + u32::from(c - b'0');
                    if n > 65535 {
                        return Err("port out of range 0..65535".into());
                    }
                }
                f.port = Some(n as u16);
            }
            other => return Err(format!("unknown parameter '{other}'")),
        }
    }
    Ok(f)
}

async fn healthz() -> Response {
    Json(json!({"status": "ok"})).into_response()
}

async fn summary(State(st): State<Arc<HttpState>>, RawQuery(q): RawQuery) -> Response {
    match parse_filter(q.as_deref()) {
        Ok(f) => Json(st.computed(&f).summary.clone()).into_response(),
        Err(e) => error_response(StatusCode::BAD_REQUEST, &e),
    }
}

async fn flows(State(st): State<Arc<HttpState>>, RawQuery(q): RawQuery) -> Response {
    match parse_filter(q.as_deref()) {
        Ok(f) => Json(st.computed(&f).flows.clone()).into_response(),
        Err(e) => error_response(StatusCode::BAD_REQUEST, &e),
    }
}

async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not found")
}

pub fn router(state: Arc<HttpState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/summary", get(summary))
        .route("/flows", get(flows))
        .fallback(not_found)
        .with_state(state)
}

enum HeadError {
    Status(StatusCode, &'static str),
    Closed,
}

/// Index just past the blank line ending the head, if complete. Accepts `\r\n` and bare `\n`.
fn head_end(buf: &[u8]) -> Option<usize> {
    let mut pos = 0;
    let mut first = true;
    while let Some(nl) = buf[pos..].iter().position(|&b| b == b'\n') {
        let line = &buf[pos..pos + nl];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        pos += nl + 1;
        if line.is_empty() && !first {
            return Some(pos);
        }
        first = false;
    }
    None
}

async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>, HeadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        match buf.iter().position(|&b| b == b'\n') {
            None if buf.len() > MAX_REQUEST_LINE + 1 => {
                return Err(HeadError::Status(StatusCode::URI_TOO_LONG, "request line too long"))
            }
            Some(p) => {
                let len = p - usize::from(p > 0 && buf[p - 1] == b'\r');
                if len > MAX_REQUEST_LINE {
                    return Err(HeadError::Status(StatusCode::URI_TOO_LONG, "request line too long"));
                }
                if buf.len() - (p + 1) > MAX_HEADER_BYTES + 3 {
                    // Tolerate the final blank line's terminator in the byte budget.
                    return Err(HeadError::Status(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "headers too large"));
                }
                if let Some(end) = head_end(&buf) {
                    if end - (p + 1) > MAX_HEADER_BYTES + 2 {
                        return Err(HeadError::Status(
                            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                            "headers too large",
                        ));
                    }
                    buf.truncate(end);
                    return Ok(buf);
                }
            }
            None => {}
        }
        let n = stream.read(&mut chunk).await.map_err(|_| HeadError::Closed)?;
        if n == 0 {
            return Err(HeadError::Closed);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Turn a request target (origin-form or absolute-form) into `path[?query]`.
fn normalize_target(t: &str) -> Option<String> {
    if t.bytes().any(|c| c <= b' ' || c == 0x7f || !c.is_ascii() || c == b'#') {
        return None;
    }
    if t.starts_with('/') {
        return Some(t.to_string());
    }
    let lower = t.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &t[7..]
    } else if lower.starts_with("https://") {
        &t[8..]
    } else {
        return None;
    };
    let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
    if auth_end == 0 {
        return None;
    }
    let tail = &rest[auth_end..];
    Some(match tail {
        "" => "/".to_string(),
        t if t.starts_with('?') => format!("/{t}"),
        t => t.to_string(),
    })
}

enum Parsed {
    Get(Box<Request<Body>>),
    Reply(StatusCode, &'static str, bool),
}

fn parse_request(head: &[u8]) -> Parsed {
    const BAD: Parsed = Parsed::Reply(StatusCode::BAD_REQUEST, "malformed request", false);
    let Ok(text) = std::str::from_utf8(head) else { return BAD };
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let Some(request_line) = lines.next() else { return BAD };
    let parts: Vec<&str> = request_line.split(' ').collect();
    let [method, target, version] = parts[..] else { return BAD };
    if method.is_empty() || !method.bytes().all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)) {
        return BAD;
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return BAD;
    }
    for l in lines {
        if !l.is_empty() && !l.contains(':') {
            return BAD;
        }
    }
    if method != "GET" {
        return Parsed::Reply(StatusCode::METHOD_NOT_ALLOWED, "method not allowed", true);
    }
    match normalize_target(target) {
        Some(t) => build_get(&t),
        None => BAD,
    }
}

fn build_get(path_and_query: &str) -> Parsed {
    match Request::builder().method("GET").uri(path_and_query).body(Body::empty()) {
        Ok(r) => Parsed::Get(Box::new(r)),
        Err(_) => Parsed::Reply(StatusCode::BAD_REQUEST, "malformed request target", false),
    }
}

async fn write_response(stream: &mut TcpStream, resp: Response) {
    let (parts, body) = resp.into_parts();
    let bytes: Bytes = axum::body::to_bytes(body, MAX_RESPONSE_BYTES).await.unwrap_or_default();
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        parts.status.as_u16(),
        parts.status.canonical_reason().unwrap_or(""),
        bytes.len()
    );
    if let Some(allow) = parts.headers.get(header::ALLOW).and_then(|v| v.to_str().ok()) {
        head.push_str(&format!("Allow: {allow}\r\n"));
    }
    head.push_str("\r\n");
    let write = async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&bytes).await?;
        stream.shutdown().await
    };
    let _ = tokio::time::timeout(READ_TIMEOUT, write).await;
    // Briefly drain unread request bytes so closing does not turn into a TCP
    // reset that would destroy the response the client has not read yet.
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(250), (&mut *stream).take(64 * 1024).read_to_end(&mut sink)).await;
}

fn plain_error(status: StatusCode, msg: &str, allow_get: bool) -> Response {
    let mut r = error_response(status, msg);
    if allow_get {
        r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET"));
    }
    r
}

async fn handle_conn(mut stream: TcpStream, app: Router) {
    let head = match tokio::time::timeout(READ_TIMEOUT, read_head(&mut stream)).await {
        Err(_) => {
            write_response(&mut stream, plain_error(StatusCode::REQUEST_TIMEOUT, "request timeout", false)).await;
            return;
        }
        Ok(Err(HeadError::Closed)) => return,
        Ok(Err(HeadError::Status(s, m))) => {
            write_response(&mut stream, plain_error(s, m, false)).await;
            return;
        }
        Ok(Ok(h)) => h,
    };
    let resp = match parse_request(&head) {
        Parsed::Reply(s, m, allow) => plain_error(s, m, allow),
        Parsed::Get(req) => match app.oneshot(*req).await {
            Ok(r) => r,
            Err(e) => match e {},
        },
    };
    write_response(&mut stream, resp).await;
}

/// Accept loop; runs until the task is aborted.
pub async fn serve(listener: TcpListener, state: Arc<HttpState>) {
    let app = router(state);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[server] http accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        match slots.clone().try_acquire_owned() {
            Ok(permit) => {
                let app = app.clone();
                tokio::spawn(async move {
                    handle_conn(stream, app).await;
                    drop(permit);
                });
            }
            Err(_) => {
                tokio::spawn(async move {
                    write_response(
                        &mut stream,
                        plain_error(StatusCode::SERVICE_UNAVAILABLE, "too many connections", false),
                    )
                    .await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp_core::wire::{build_packet, Mode};

    async fn start(seed: bool) -> (std::net::SocketAddr, Arc<Mutex<Aggregator>>, tokio::task::JoinHandle<()>) {
        let agg = Arc::new(Mutex::new(Aggregator::default()));
        if seed {
            let mut a = agg.lock().unwrap();
            for seq in 0..5u64 {
                let p = build_packet(Mode::Audio, seq, 0, 100).unwrap();
                a.on_packet(&p, "10.0.0.1", 4000, now_ns());
            }
        }
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(serve(l, HttpState::new(agg.clone(), 10.0)));
        (addr, agg, h)
    }

    async fn raw(addr: std::net::SocketAddr, req: &[u8]) -> (u16, String, Value) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let code = head.split(' ').nth(1).unwrap().parse().unwrap();
        (code, head.to_string(), serde_json::from_str(body).unwrap_or(Value::Null))
    }

    async fn get(addr: std::net::SocketAddr, target: &str) -> (u16, String, Value) {
        raw(addr, format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await
    }

    #[tokio::test]
    async fn healthz_and_headers() {
        let (addr, _, _h) = start(false).await;
        let (c, head, v) = get(addr, "/healthz?whatever=1&&").await;
        assert_eq!((c, v), (200, json!({"status": "ok"})));
        assert!(head.contains("Content-Type: application/json"));
        assert!(head.contains("Connection: close"));
    }

    #[tokio::test]
    async fn idle_and_active_summary() {
        let (addr, _, _h) = start(false).await;
        let (c, _, v) = get(addr, "/summary").await;
        assert_eq!((c, v), (200, json!({"idle": true, "active_flows": []})));
        let (_, _, v) = get(addr, "/flows").await;
        assert_eq!(v, json!({"flows": []}));

        let (addr, _, _h) = start(true).await;
        let (c, _, v) = get(addr, "/summary").await;
        assert_eq!(c, 200);
        assert_eq!(v["idle"], false);
        assert_eq!(v["active_count"], 1);
        assert_eq!(v["aggregate"]["packets"], 5);
        let (_, _, v) = get(addr, "/flows").await;
        assert_eq!(v["flows"][0]["remote"], "10.0.0.1");
        assert_eq!(v["flows"][0]["udp_port"], 4000);
        let (_, _, v) = get(addr, "/summary?host=10.0.0.1&port=04000").await;
        assert_eq!(v["active_count"], 1);
        let (_, _, v) = get(addr, "/summary?port=1").await;
        assert_eq!(v, json!({"idle": true, "active_flows": []}));
        let (_, _, v) = get(addr, "/flows?host=nope").await;
        assert_eq!(v, json!({"flows": []}));
    }

    #[tokio::test]
    async fn bad_queries_are_400() {
        let (addr, _, _h) = start(false).await;
        for q in [
            "?foo=1", "?host=a&host=b", "?port=1&port=2", "?host=", "?port=", "?port=+80", "?port=65536", "?port=x",
            "?port=-1", "?host=%zz", "?host=%ff", "?port=%3", "?host", "?host=a&&port=1", "?port=%31%3a",
        ] {
            let (c, _, v) = get(addr, &format!("/summary{q}")).await;
            assert_eq!(c, 400, "{q}");
            assert!(v["error"].is_string(), "{q}");
            assert_eq!(get(addr, &format!("/flows{q}")).await.0, 400, "{q}");
        }
        assert_eq!(get(addr, "/summary?host=%31%30&port=65535").await.0, 200);
    }

    #[tokio::test]
    async fn routing_and_methods() {
        let (addr, _, _h) = start(false).await;
        let (c, _, v) = get(addr, "/nope").await;
        assert_eq!(c, 404);
        assert!(v["error"].is_string());
        assert_eq!(get(addr, "/summary/").await.0, 404);
        for m in ["POST", "PUT", "DELETE", "HEAD", "PATCH"] {
            let (c, head, v) = raw(addr, format!("{m} /summary HTTP/1.1\r\n\r\n").as_bytes()).await;
            assert_eq!(c, 405, "{m}");
            assert!(head.contains("Allow: GET"));
            assert!(v["error"].is_string());
        }
    }

    #[tokio::test]
    async fn request_head_edge_cases() {
        let (addr, _, _h) = start(false).await;
        // bare \n line endings, absolute-form target
        assert_eq!(raw(addr, b"GET /healthz HTTP/1.1\nHost: x\n\n").await.0, 200);
        assert_eq!(raw(addr, b"GET http://example.com/healthz HTTP/1.1\r\n\r\n").await.0, 200);
        // absolute-form without a path routes as "/" (unknown -> 404, never 500)
        assert_eq!(raw(addr, b"GET http://example.com HTTP/1.1\r\n\r\n").await.0, 404);
        // malformed
        for req in [
            &b"GARBAGE\r\n\r\n"[..],
            b"GET /healthz\r\n\r\n",
            b"GET healthz HTTP/1.1\r\n\r\n",
            b"GET /a\x01b HTTP/1.1\r\n\r\n",
            b"GET /\xff HTTP/1.1\r\n\r\n",
            b"GET /healthz HTTP/2.0\r\n\r\n",
            b"GET /healthz HTTP/1.1\r\nnocolon\r\n\r\n",
            b"GET * HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(raw(addr, req).await.0, 400, "{:?}", String::from_utf8_lossy(req));
        }
        // request line too long
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_REQUEST_LINE));
        assert_eq!(raw(addr, long.as_bytes()).await.0, 414);
        // headers too large
        let big = format!("GET /healthz HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEADER_BYTES + 10));
        assert_eq!(raw(addr, big.as_bytes()).await.0, 431);
    }

    #[tokio::test]
    async fn slow_client_gets_408() {
        let (addr, _, _h) = start(false).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /healthz HT").await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(8), s.read_to_end(&mut out)).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 408"));
    }

    #[tokio::test]
    async fn connection_cap_gives_503() {
        let (addr, _, _h) = start(false).await;
        let mut held = vec![];
        for _ in 0..MAX_CONNECTIONS {
            held.push(TcpStream::connect(addr).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (c, _, v) = get(addr, "/healthz").await;
        assert_eq!(c, 503);
        assert!(v["error"].is_string());
        drop(held);
    }

    #[tokio::test]
    async fn lock_is_not_held_after_request() {
        let (addr, agg, _h) = start(true).await;
        assert_eq!(get(addr, "/summary").await.0, 200);
        assert!(agg.try_lock().is_ok());
    }

    #[test]
    fn percent_decoding_is_strict() {
        assert_eq!(percent_decode("a%2Fb+c").as_deref(), Some("a/b c"));
        assert_eq!(percent_decode("%"), None);
        assert_eq!(percent_decode("%g0"), None);
        assert_eq!(percent_decode("%c3%28"), None);
    }
}
