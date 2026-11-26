//! TCP control channel: hello/response handshake, path updates, final stats on disconnect.

use std::sync::{Arc, Mutex};

use mtp_core::clock::now_ns;
use mtp_core::control::{to_line, HelloResp};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::aggregator::{Aggregator, ConnInfo};
use crate::config::{Config, Out};
use crate::summary::{fmt, generate_summary, generate_summary_json};

/// Longest control line we accept.
const MAX_LINE: u64 = 64 * 1024;

pub struct Ctx {
    pub cfg: Config,
    pub agg: Arc<Mutex<Aggregator>>,
    pub out: Out,
    pub audio_port: u16,
    pub video_port: u16,
}

fn lock(m: &Mutex<Aggregator>) -> std::sync::MutexGuard<'_, Aggregator> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Read one line (including `\n`) of at most `MAX_LINE` bytes; 0 means EOF.
async fn read_line<R: AsyncBufReadExt + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    idle_timeout_s: f64,
) -> std::io::Result<usize> {
    buf.clear();
    let mut limited = r.take(MAX_LINE);
    let read = limited.read_until(b'\n', buf);
    if idle_timeout_s > 0.0 && idle_timeout_s.is_finite() {
        tokio::time::timeout(std::time::Duration::from_secs_f64(idle_timeout_s), read)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "control connection idle timeout"))?
    } else {
        read.await
    }
}

fn parse_json(line: &[u8]) -> Value {
    serde_json::from_slice(line).unwrap_or(Value::Null)
}

pub async fn handle_control(stream: TcpStream, ctx: Arc<Ctx>) {
    let start_ns = now_ns();
    let Ok(peer) = stream.peer_addr() else { return };
    let peer_ip = peer.ip().to_string();
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    let (mut bytes_in, mut bytes_out) = (0usize, 0usize);
    let mut hello_to_resp_ms = None;

    if let Err(e) = session(&ctx, &mut rd, &mut wr, &peer, &peer_ip, &mut bytes_in, &mut bytes_out, &mut hello_to_resp_ms).await {
        if e.kind() != std::io::ErrorKind::UnexpectedEof {
            eprintln!("[server] control error from {peer}: {e}");
        }
    }
    let _ = wr.shutdown().await;

    if hello_to_resp_ms.is_none() {
        // No handshake completed (e.g. an empty connection): nothing to report.
        return;
    }
    final_stats(&ctx, &peer, start_ns, bytes_in, bytes_out, hello_to_resp_ms);
}

#[allow(clippy::too_many_arguments)]
async fn session(
    ctx: &Ctx,
    rd: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    peer: &std::net::SocketAddr,
    peer_ip: &str,
    bytes_in: &mut usize,
    bytes_out: &mut usize,
    hello_to_resp_ms: &mut Option<f64>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    if read_line(rd, &mut buf, ctx.cfg.control_idle_timeout).await? == 0 {
        return Ok(());
    }
    let hello_rx_ns = now_ns();
    *bytes_in += buf.len();
    let hello = parse_json(&buf);

    let mode = hello.get("mode").and_then(Value::as_str).unwrap_or("audio").to_string();
    let client_udp_port = hello.get("client_udp_port").and_then(Value::as_i64);
    // Must be known before the connection line is built (the Python read it first).
    let server_udp_port = if mode == "video" { ctx.video_port } else { ctx.audio_port };

    let line = {
        let mut agg = lock(&ctx.agg);
        if let Some(p) = client_udp_port {
            agg.set_expected_udp_port(peer_ip, p);
        }
        agg.register_connection(
            peer_ip,
            ConnInfo {
                mode_name: mode.clone(),
                control_tcp: peer.port().to_string(),
                media_udp: server_udp_port,
                family: if peer.is_ipv6() { "IPv6" } else { "IPv4" }.into(),
            },
        )
    };
    if let Some(l) = line {
        ctx.out.line(l);
    }

    let resp = HelloResp {
        ok: true,
        mode,
        server_host_v4: Some(ctx.cfg.udp_host_v4.clone()),
        server_host_v6: Some(ctx.cfg.udp_host_v6.clone()),
        server_udp_port,
        audio_port: ctx.audio_port,
        video_port: ctx.video_port,
    };
    let out_line = to_line(&resp).map_err(std::io::Error::other)?;
    wr.write_all(&out_line).await?;
    *bytes_out += out_line.len();
    *hello_to_resp_ms = Some((now_ns().saturating_sub(hello_rx_ns) as f64 / 1e6).max(0.0));

    // Stay connected until the client closes; handle path updates meanwhile.
    loop {
        if read_line(rd, &mut buf, ctx.cfg.control_idle_timeout).await? == 0 {
            return Ok(());
        }
        *bytes_in += buf.len();
        let msg = parse_json(&buf);
        if let Some(port) = msg.pointer("/path_update/client_udp_port").and_then(Value::as_i64) {
            lock(&ctx.agg).set_expected_udp_port(peer_ip, port);
            ctx.out.line(format!("[server] Control: path_update from {peer_ip} reported_udp={port}"));
        }
    }
}

fn final_stats(
    ctx: &Ctx,
    peer: &std::net::SocketAddr,
    start_ns: u64,
    bytes_in: usize,
    bytes_out: usize,
    hello_to_resp_ms: Option<f64>,
) {
    let now = now_ns();
    // Long TTL so everything since startup is included; UDP may come from a
    // different NAT address than the TCP peer, so no host filter.
    let ttl = ctx.cfg.idle_ttl.max(3600.0);
    let snap = generate_summary(&mut lock(&ctx.agg), now, ttl, false);
    let open_dur = (now.saturating_sub(start_ns)) as f64 / 1e9;

    ctx.out.line(format!("Final stats for peer ('{}', {}) (control disconnect)", peer.ip(), peer.port()));
    ctx.out.line(snap);
    ctx.out.line("=== Control Stats ===");
    ctx.out.line(format!("  - Open duration: {open_dur:.2}s"));
    ctx.out.line("  - Handshake RTT (ms): n/a");
    ctx.out.line(format!("  - Hello->Resp (ms): {}", fmt(hello_to_resp_ms)));
    ctx.out.line(format!("  - Bytes: out={bytes_out} in={bytes_in}"));

    if ctx.cfg.json || ctx.cfg.json_file.is_some() {
        let summary = generate_summary_json(&lock(&ctx.agg), now_ns(), ttl, true);
        ctx.out.json(
            &ctx.cfg,
            &json!({
                "event": "final_stats",
                "peer": {"ip": peer.ip().to_string(), "tcp_port": peer.port()},
                "control_stats": {
                    "open_duration_s": open_dur,
                    "hello_to_resp_ms": hello_to_resp_ms,
                    "bytes_out": bytes_out,
                    "bytes_in": bytes_in,
                },
                "summary": summary,
                "ts_ns": now_ns(),
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_read_times_out() {
        let (_keep, srv) = tokio::io::duplex(64);
        let mut rd = BufReader::new(srv);
        let mut buf = Vec::new();
        let err = read_line(&mut rd, &mut buf, 0.05).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
