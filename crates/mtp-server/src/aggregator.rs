//! Flow table plus control/UDP correlation (port of `Aggregator` in `server.py`).

use std::collections::HashMap;

use mtp_core::wire::{self, Header};

use crate::flow::FlowStats;

/// (remote host, remote UDP port, mode byte)
pub type FlowKey = (String, u16, u8);

#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub mode_name: String,
    pub control_tcp: String,
    pub media_udp: u16,
    pub family: String,
}

#[derive(Default)]
pub struct Aggregator {
    pub flows: HashMap<FlowKey, FlowStats>,
    pub header_lines: Vec<String>,
    /// peer IP -> UDP port the client reported over TCP
    expected_udp_ports: HashMap<String, i64>,
    /// peer IP -> first NAT-mapped UDP source port seen
    observed_udp_ports: HashMap<String, u16>,
    /// connections waiting for their first UDP packet
    pending_conn: HashMap<String, ConnInfo>,
}

fn rep(p: Option<&i64>) -> String {
    p.map_or("n/a".to_string(), |v| v.to_string())
}

impl Aggregator {
    pub fn new(header_lines: Vec<String>) -> Self {
        Self { header_lines, ..Default::default() }
    }

    pub fn set_expected_udp_port(&mut self, host: &str, port: i64) {
        self.expected_udp_ports.insert(host.to_string(), port);
    }

    /// Record a new control connection. Returns the `Connection:` line to print
    /// now if UDP from this host was already seen; otherwise the info is parked
    /// until the first datagram arrives.
    pub fn register_connection(&mut self, host: &str, info: ConnInfo) -> Option<String> {
        match self.observed_udp_ports.get(host) {
            Some(nat) => Some(connection_line(&info, host, *nat, self.expected_udp_ports.get(host))),
            None => {
                self.pending_conn.insert(host.to_string(), info);
                None
            }
        }
    }

    /// Handle a datagram. Returns a line to print when this creates a new flow.
    pub fn on_packet(&mut self, data: &[u8], host: &str, port: u16, now_ns: u64) -> Option<String> {
        let Header { mode, seq, send_ns, .. } = wire::parse_packet(data)?;
        let key = (host.to_string(), port, mode);
        let mut announce = None;
        if !self.flows.contains_key(&key) {
            self.flows.insert(key.clone(), FlowStats::new(mode));
            self.observed_udp_ports.insert(host.to_string(), port);
            let exp = self.expected_udp_ports.get(host);
            announce = Some(match self.pending_conn.remove(host) {
                Some(info) => connection_line(&info, host, port, exp),
                None => {
                    let mode_name = match mode {
                        1 => "audio".to_string(),
                        2 => "video".to_string(),
                        m => m.to_string(),
                    };
                    format!(
                        "[server] Observed UDP: mode={mode_name} src_udp={port} reported_udp={} remote={host}",
                        rep(exp)
                    )
                }
            });
        }
        if let Some(fs) = self.flows.get_mut(&key) {
            fs.on_packet(seq, send_ns, now_ns, data.len());
        }
        announce
    }

    /// Drop flows idle for more than ten TTLs.
    pub fn prune(&mut self, now_ns: u64, ttl_ns: u64) {
        self.flows
            .retain(|_, fs| fs.last_ns.is_none_or(|l| now_ns.saturating_sub(l) <= ttl_ns.saturating_mul(10)));
    }
}

fn connection_line(info: &ConnInfo, host: &str, nat_udp: u16, reported: Option<&i64>) -> String {
    format!(
        "[server] Connection: mode={} control_tcp={} media_udp={} family={} remote={host} nat_udp={nat_udp} reported_udp={}",
        info.mode_name,
        info.control_tcp,
        info.media_udp,
        info.family,
        rep(reported)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp_core::wire::{build_packet, Mode};

    fn info() -> ConnInfo {
        ConnInfo {
            mode_name: "audio".into(),
            control_tcp: "40000".into(),
            media_udp: 6000,
            family: "IPv4".into(),
        }
    }

    fn pkt(seq: u64) -> Vec<u8> {
        build_packet(Mode::Audio, seq, 1, 64).unwrap()
    }

    #[test]
    fn tcp_first_prints_connection_on_first_udp() {
        let mut a = Aggregator::default();
        a.set_expected_udp_port("1.2.3.4", 50000);
        assert!(a.register_connection("1.2.3.4", info()).is_none());
        let line = a.on_packet(&pkt(0), "1.2.3.4", 50001, 10).unwrap();
        assert_eq!(
            line,
            "[server] Connection: mode=audio control_tcp=40000 media_udp=6000 family=IPv4 \
             remote=1.2.3.4 nat_udp=50001 reported_udp=50000"
        );
        // same flow again: no announcement
        assert!(a.on_packet(&pkt(1), "1.2.3.4", 50001, 20).is_none());
    }

    #[test]
    fn udp_first_prints_connection_on_hello() {
        let mut a = Aggregator::default();
        let first = a.on_packet(&pkt(0), "1.2.3.4", 50001, 10).unwrap();
        assert!(first.starts_with("[server] Observed UDP: mode=audio src_udp=50001 reported_udp=n/a"));
        a.set_expected_udp_port("1.2.3.4", 50000);
        let line = a.register_connection("1.2.3.4", info()).unwrap();
        assert!(line.contains("nat_udp=50001 reported_udp=50000"));
    }

    #[test]
    fn garbage_is_ignored() {
        let mut a = Aggregator::default();
        assert!(a.on_packet(b"hello", "h", 1, 1).is_none());
        assert!(a.flows.is_empty());
    }

    #[test]
    fn prune_removes_long_idle_flows() {
        let mut a = Aggregator::default();
        a.on_packet(&pkt(0), "h", 1, 1_000);
        a.prune(1_000 + 10, 1); // within 10*ttl
        assert_eq!(a.flows.len(), 1);
        a.prune(1_000 + 11, 1);
        assert!(a.flows.is_empty());
    }
}
