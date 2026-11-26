//! Flow table plus control/UDP correlation (port of `Aggregator` in `server.py`).

use std::collections::{HashMap, VecDeque};

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

/// Default cap on simultaneously tracked flows.
pub const DEFAULT_MAX_FLOWS: usize = 1024;
/// Default idle TTL used for automatic pruning (seconds).
pub const DEFAULT_IDLE_TTL_S: f64 = 10.0;
/// Cap on each per-host bookkeeping table.
pub const MAX_TRACKED_HOSTS: usize = 4096;

/// Insertion-ordered map with a hard size cap; the oldest insert is evicted first.
#[derive(Debug)]
struct BoundedMap<V> {
    map: HashMap<String, V>,
    order: VecDeque<String>,
    cap: usize,
}

impl<V> BoundedMap<V> {
    fn new(cap: usize) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), cap: cap.max(1) }
    }

    fn get(&self, k: &str) -> Option<&V> {
        self.map.get(k)
    }

    fn insert(&mut self, k: &str, v: V) {
        if self.map.insert(k.to_string(), v).is_none() {
            self.order.push_back(k.to_string());
            while self.map.len() > self.cap {
                match self.order.pop_front() {
                    Some(old) => {
                        self.map.remove(&old);
                    }
                    None => break,
                }
            }
        }
    }

    fn remove(&mut self, k: &str) -> Option<V> {
        let v = self.map.remove(k)?;
        self.order.retain(|x| x != k);
        Some(v)
    }

    fn retain_keys(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.map.retain(|k, _| keep(k));
        let map = &self.map;
        self.order.retain(|k| map.contains_key(k));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

pub struct Aggregator {
    pub flows: HashMap<FlowKey, FlowStats>,
    pub header_lines: Vec<String>,
    max_flows: usize,
    idle_ttl_ns: u64,
    /// peer IP -> UDP port the client reported over TCP
    expected_udp_ports: BoundedMap<i64>,
    /// peer IP -> first NAT-mapped UDP source port seen
    observed_udp_ports: BoundedMap<u16>,
    /// connections waiting for their first UDP packet
    pending_conn: BoundedMap<ConnInfo>,
}

impl Default for Aggregator {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            header_lines: Vec::new(),
            max_flows: DEFAULT_MAX_FLOWS,
            idle_ttl_ns: (DEFAULT_IDLE_TTL_S * 1e9) as u64,
            expected_udp_ports: BoundedMap::new(MAX_TRACKED_HOSTS),
            observed_udp_ports: BoundedMap::new(MAX_TRACKED_HOSTS),
            pending_conn: BoundedMap::new(MAX_TRACKED_HOSTS),
        }
    }
}

fn rep(p: Option<&i64>) -> String {
    p.map_or("n/a".to_string(), |v| v.to_string())
}

impl Aggregator {
    pub fn new(header_lines: Vec<String>) -> Self {
        Self { header_lines, ..Default::default() }
    }

    /// Configure the flow cap and the idle TTL used for automatic pruning.
    pub fn set_limits(&mut self, max_flows: usize, idle_ttl_s: f64) {
        self.max_flows = max_flows.max(1);
        self.idle_ttl_ns = (idle_ttl_s.max(0.0) * 1e9) as u64;
    }

    pub fn set_expected_udp_port(&mut self, host: &str, port: i64) {
        self.expected_udp_ports.insert(host, port);
    }

    /// Record a new control connection. Returns the `Connection:` line to print
    /// now if UDP from this host was already seen; otherwise the info is parked
    /// until the first datagram arrives.
    pub fn register_connection(&mut self, host: &str, info: ConnInfo) -> Option<String> {
        match self.observed_udp_ports.get(host) {
            Some(nat) => Some(connection_line(&info, host, *nat, self.expected_udp_ports.get(host))),
            None => {
                self.pending_conn.insert(host, info);
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
            self.make_room(now_ns);
            self.flows.insert(key.clone(), FlowStats::new(mode));
            self.observed_udp_ports.insert(host, port);
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

    /// Drop flows idle for more than ten TTLs, and per-host state for hosts
    /// that no longer have any flow.
    pub fn prune(&mut self, now_ns: u64, ttl_ns: u64) {
        self.flows
            .retain(|_, fs| fs.last_ns.is_none_or(|l| now_ns.saturating_sub(l) <= ttl_ns.saturating_mul(10)));
        let hosts: std::collections::HashSet<&str> = self.flows.keys().map(|(h, _, _)| h.as_str()).collect();
        self.observed_udp_ports.retain_keys(|h| hosts.contains(h));
    }

    /// Ensure one more flow fits: prune long-idle flows, then evict the
    /// longest-idle flow while still at the cap.
    fn make_room(&mut self, now_ns: u64) {
        if self.flows.len() < self.max_flows {
            return;
        }
        self.prune(now_ns, self.idle_ttl_ns);
        while self.flows.len() >= self.max_flows {
            let oldest = self
                .flows
                .iter()
                .min_by_key(|(k, fs)| (fs.last_ns.unwrap_or(0), (*k).clone()))
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.flows.remove(&k);
                }
                None => break,
            }
        }
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
    fn flow_cap_evicts_oldest_idle() {
        let mut a = Aggregator::default();
        a.set_limits(3, 10.0);
        for (i, port) in [1u16, 2, 3].into_iter().enumerate() {
            a.on_packet(&pkt(0), "h", port, 100 + i as u64);
        }
        a.on_packet(&pkt(1), "h", 1, 200); // port 1 is fresh again; port 2 is oldest
        a.on_packet(&pkt(0), "h", 4, 300);
        assert_eq!(a.flows.len(), 3);
        assert!(!a.flows.contains_key(&("h".to_string(), 2, 1)));
        assert!(a.flows.contains_key(&("h".to_string(), 1, 1)));
        assert!(a.flows.contains_key(&("h".to_string(), 4, 1)));
    }

    #[test]
    fn many_flows_stay_bounded() {
        let mut a = Aggregator::default();
        a.set_limits(16, 10.0);
        for i in 0..1000u64 {
            a.on_packet(&pkt(0), &format!("10.0.{}.{}", i / 250, i % 250), 1000, i + 1);
        }
        assert_eq!(a.flows.len(), 16);
    }

    #[test]
    fn insert_prunes_long_idle_flows() {
        let mut a = Aggregator::default();
        a.set_limits(2, 1.0);
        a.on_packet(&pkt(0), "h", 1, 1);
        a.on_packet(&pkt(0), "h", 2, 2);
        // both far older than 10 TTLs by now
        a.on_packet(&pkt(0), "h", 3, 100_000_000_000);
        assert_eq!(a.flows.len(), 1);
    }

    #[test]
    fn host_tables_are_bounded() {
        let mut a = Aggregator::default();
        for i in 0..(MAX_TRACKED_HOSTS + 50) {
            let h = format!("h{i}");
            a.set_expected_udp_port(&h, 1);
            a.register_connection(&h, info());
        }
        assert_eq!(a.expected_udp_ports.len(), MAX_TRACKED_HOSTS);
        assert_eq!(a.pending_conn.len(), MAX_TRACKED_HOSTS);
        // oldest was evicted, newest kept
        assert!(a.pending_conn.get("h0").is_none());
        assert!(a.pending_conn.get(&format!("h{}", MAX_TRACKED_HOSTS + 49)).is_some());
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
