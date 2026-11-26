//! UDP reflector server: TCP control channel plus per-mode UDP echo sockets.

pub mod aggregator;
pub mod config;
pub mod control;
pub mod flow;
pub mod http;
pub mod net;
pub mod reflector;
pub mod summary;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};
use mtp_core::clock::now_ns;
use serde_json::json;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

use aggregator::Aggregator;
pub use config::{Config, Out};

pub struct Server {
    pub aggregator: Arc<Mutex<Aggregator>>,
    pub tcp_addrs: Vec<SocketAddr>,
    pub audio_addrs: Vec<SocketAddr>,
    pub video_addrs: Vec<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    tasks: Vec<JoinHandle<()>>,
}

fn udp_sockets(v4: &str, v6: &str, port: u16) -> Result<Vec<UdpSocket>> {
    let mut v = vec![];
    for host in [v4, v6].into_iter().filter(|h| !h.is_empty()) {
        v.push(net::bind_udp(host, port)?);
    }
    Ok(v)
}

fn fmt_addrs(addrs: &[SocketAddr]) -> String {
    addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
}

impl Server {
    /// Bind every socket and spawn all tasks. With port 0 the OS picks the port
    /// (the first address family's port is what clients are told).
    pub async fn start(cfg: Config, out: Out) -> Result<Server> {
        let header_lines = vec![
            format!("TCP control: v4 {}:{} | v6 [{}]:{}", cfg.tcp_host_v4, cfg.tcp_port, cfg.tcp_host_v6, cfg.tcp_port),
            format!("UDP audio: v4 {}:{} | v6 [{}]:{}", cfg.udp_host_v4, cfg.audio_port, cfg.udp_host_v6, cfg.audio_port),
            format!("UDP video: v4 {}:{} | v6 [{}]:{}", cfg.udp_host_v4, cfg.video_port, cfg.udp_host_v6, cfg.video_port),
        ];
        let mut aggregator = Aggregator::new(header_lines);
        aggregator.set_limits(cfg.max_flows, cfg.idle_ttl);
        let agg = Arc::new(Mutex::new(aggregator));

        let audio = udp_sockets(&cfg.udp_host_v4, &cfg.udp_host_v6, cfg.audio_port)?;
        let video = udp_sockets(&cfg.udp_host_v4, &cfg.udp_host_v6, cfg.video_port)?;
        let mut tcp: Vec<TcpListener> = vec![];
        for host in [&cfg.tcp_host_v4, &cfg.tcp_host_v6].into_iter().filter(|h| !h.is_empty()) {
            tcp.push(net::bind_tcp(host, cfg.tcp_port)?);
        }
        if audio.is_empty() || video.is_empty() || tcp.is_empty() {
            bail!("at least one of the IPv4/IPv6 hosts must be enabled for TCP and UDP");
        }

        let audio_addrs: Vec<_> = audio.iter().map(|s| s.local_addr()).collect::<Result<_, _>>()?;
        let video_addrs: Vec<_> = video.iter().map(|s| s.local_addr()).collect::<Result<_, _>>()?;
        let tcp_addrs: Vec<_> = tcp.iter().map(|s| s.local_addr()).collect::<Result<_, _>>()?;

        let ctx = Arc::new(control::Ctx {
            cfg: cfg.clone(),
            agg: agg.clone(),
            out: out.clone(),
            audio_port: audio_addrs[0].port(),
            video_port: video_addrs[0].port(),
        });

        let mut tasks = vec![];
        for s in audio.into_iter().chain(video) {
            tasks.push(tokio::spawn(reflector::reflect(Arc::new(s), agg.clone(), out.clone())));
        }
        let conn_slots = Arc::new(tokio::sync::Semaphore::new(cfg.max_control_conns.max(1)));
        for l in tcp {
            let ctx = ctx.clone();
            let conn_slots = conn_slots.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    match l.accept().await {
                        Ok((stream, peer)) => match conn_slots.clone().try_acquire_owned() {
                            Ok(permit) => {
                                let ctx = ctx.clone();
                                tokio::spawn(async move {
                                    control::handle_control(stream, ctx).await;
                                    drop(permit);
                                });
                            }
                            Err(_) => eprintln!("[server] too many control connections; refusing {peer}"),
                        },
                        Err(e) => {
                            eprintln!("[server] accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }));
        }
        let mut http_addr = None;
        if let Some(port) = cfg.http_port {
            let l = TcpListener::bind((cfg.http_host.as_str(), port)).await?;
            let addr = l.local_addr()?;
            http_addr = Some(addr);
            tasks.push(tokio::spawn(http::serve(l, http::HttpState::with_read_timeout(
                agg.clone(),
                cfg.idle_ttl,
                Duration::from_secs_f64(cfg.http_read_timeout.clamp(0.01, 3600.0)),
            ))));
            out.line(format!("[server] HTTP API listening on {addr}"));
        }
        if cfg.periodic_stats {
            tasks.push(tokio::spawn(periodic_stats(cfg.clone(), agg.clone(), out.clone())));
        }

        out.line(format!("[server] TCP control listening on {}", fmt_addrs(&tcp_addrs)));
        out.line(format!("[server] UDP audio reflector on {}", fmt_addrs(&audio_addrs)));
        out.line(format!("[server] UDP video reflector on {}", fmt_addrs(&video_addrs)));

        Ok(Server { aggregator: agg, tcp_addrs, audio_addrs, video_addrs, http_addr, tasks })
    }

    /// Wait until every task has exited (normally never) or `stop` resolves.
    /// Any task that exits early or panics is logged.
    pub async fn run_until<F: std::future::Future>(mut self, stop: F) {
        tokio::select! {
            _ = stop => {}
            _ = watch_tasks(&mut self.tasks) => {}
        }
        self.shutdown();
    }

    pub fn shutdown(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Resolve once all tasks have finished, logging each one as it ends.
async fn watch_tasks(tasks: &mut Vec<JoinHandle<()>>) {
    std::future::poll_fn(|cx| {
        let mut i = 0;
        while i < tasks.len() {
            match std::pin::Pin::new(&mut tasks[i]).poll(cx) {
                std::task::Poll::Ready(res) => {
                    match res {
                        Ok(()) => eprintln!("[server] background task exited unexpectedly"),
                        Err(e) if e.is_panic() => eprintln!("[server] background task panicked: {e}"),
                        Err(e) => eprintln!("[server] background task failed: {e}"),
                    }
                    tasks.swap_remove(i);
                }
                std::task::Poll::Pending => i += 1,
            }
        }
        if tasks.is_empty() {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}

async fn periodic_stats(cfg: Config, agg: Arc<Mutex<Aggregator>>, out: Out) {
    let mut tick = tokio::time::interval(Duration::from_secs_f64(cfg.stats_interval.max(0.1)));
    tick.tick().await; // first tick fires immediately
    loop {
        tick.tick().await;
        let (text, summary) = {
            let mut a = agg.lock().unwrap_or_else(|e| e.into_inner());
            let text = summary::generate_summary(&mut a, now_ns(), cfg.idle_ttl, cfg.silent_when_idle);
            let summary = (cfg.json || cfg.json_file.is_some())
                .then(|| summary::generate_summary_json(&a, now_ns(), cfg.idle_ttl, true))
                .flatten();
            (text, summary)
        };
        if text.is_empty() {
            continue;
        }
        out.line(text);
        if let Some(s) = summary {
            out.json(&cfg, &json!({"event": "periodic_stats", "summary": s, "ts_ns": now_ns()}));
        }
    }
}
