use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Parser;
use serde_json::Value;

/// Media transport server: TCP control + UDP reflector.
#[derive(Parser, Debug, Clone)]
#[command(version)]
pub struct Config {
    /// TCP control IPv4 host (empty disables IPv4)
    #[arg(long, default_value = "0.0.0.0")]
    pub tcp_host_v4: String,
    /// TCP control IPv6 host (empty disables IPv6)
    #[arg(long, default_value = "::")]
    pub tcp_host_v6: String,
    /// TCP control port
    #[arg(long, default_value_t = 5000)]
    pub tcp_port: u16,
    /// UDP IPv4 bind host (empty disables IPv4)
    #[arg(long, default_value = "0.0.0.0")]
    pub udp_host_v4: String,
    /// UDP IPv6 bind host (empty disables IPv6)
    #[arg(long, default_value = "::")]
    pub udp_host_v6: String,
    /// UDP port for audio reflection
    #[arg(long, default_value_t = 6000)]
    pub audio_port: u16,
    /// UDP port for video reflection
    #[arg(long, default_value_t = 6001)]
    pub video_port: u16,
    /// Seconds between periodic stats prints
    #[arg(long, default_value_t = 5.0)]
    pub stats_interval: f64,
    /// Enable periodic stats printing
    #[arg(long)]
    pub periodic_stats: bool,
    /// Seconds of inactivity after which a flow is idle
    #[arg(long, default_value_t = 10.0)]
    pub idle_ttl: f64,
    /// Do not print when there are no active flows
    #[arg(long)]
    pub silent_when_idle: bool,
    /// Emit JSON lines for summaries on stdout
    #[arg(long)]
    pub json: bool,
    /// Append JSON lines to this file
    #[arg(long)]
    pub json_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config::parse_from(["udp-server"])
    }
}

/// Where server output goes: stdout, or an in-memory buffer for tests.
#[derive(Clone, Default)]
pub struct Out {
    capture: Option<Arc<Mutex<Vec<String>>>>,
}

impl Out {
    pub fn stdout() -> Self {
        Self { capture: None }
    }

    pub fn captured() -> (Self, Arc<Mutex<Vec<String>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (Self { capture: Some(buf.clone()) }, buf)
    }

    pub fn line(&self, s: impl AsRef<str>) {
        match &self.capture {
            Some(buf) => buf.lock().unwrap_or_else(|e| e.into_inner()).push(s.as_ref().to_string()),
            None => println!("{}", s.as_ref()),
        }
    }

    /// Print a compact JSON line (if `--json`) and/or append it to `--json-file`.
    pub fn json(&self, cfg: &Config, v: &Value) {
        let line = v.to_string();
        if cfg.json {
            self.line(&line);
        }
        if let Some(path) = &cfg.json_file {
            let res = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut f| writeln!(f, "{line}"));
            if let Err(e) = res {
                eprintln!("[server] failed to write {}: {e}", path.display());
            }
        }
    }
}
