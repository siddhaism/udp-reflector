//! UDP reflector server: TCP control channel plus per-mode UDP echo sockets.

pub mod aggregator;
pub mod config;
pub mod control;
pub mod flow;
pub mod net;
pub mod reflector;
pub mod summary;

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
        let agg = Arc::new(Mutex::new(Aggregator::new(header_lines)));

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
        for l in tcp {
            let ctx = ctx.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    match l.accept().await {
                        Ok((stream, _)) => {
                            tokio::spawn(control::handle_control(stream, ctx.clone()));
                        }
                        Err(e) => {
                            eprintln!("[server] accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }));
        }
        if cfg.periodic_stats {
            tasks.push(tokio::spawn(periodic_stats(cfg.clone(), agg.clone(), out.clone())));
        }

        out.line(format!("[server] TCP control listening on {}", fmt_addrs(&tcp_addrs)));
        out.line(format!("[server] UDP audio reflector on {}", fmt_addrs(&audio_addrs)));
        out.line(format!("[server] UDP video reflector on {}", fmt_addrs(&video_addrs)));

        Ok(Server { aggregator: agg, tcp_addrs, audio_addrs, video_addrs, tasks })
    }

    /// Wait until a task exits (normally never) or `stop` resolves.
    pub async fn run_until<F: std::future::Future>(mut self, stop: F) {
        tokio::select! {
            _ = stop => {}
            _ = async {
                for t in self.tasks.iter_mut() {
                    let _ = t.await;
                }
            } => {}
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
