//! Per-flow statistics for the reflector (port of `FlowStats` in `server.py`).

use std::collections::{HashSet, VecDeque};

/// Samples kept per series (matches the Python `deque(maxlen=5000)`).
pub const SERIES_CAP: usize = 5000;
/// Sequence numbers remembered for duplicate detection.
pub const DEDUP_CAP: usize = 65536;

fn push_capped(q: &mut VecDeque<f64>, v: f64) {
    if q.len() == SERIES_CAP {
        q.pop_front();
    }
    q.push_back(v);
}

#[derive(Debug, Default)]
pub struct FlowStats {
    pub mode: u8,
    pub packets: u64,
    pub bytes: u64,
    pub bytes_out: u64,
    pub first_ns: Option<u64>,
    pub last_ns: Option<u64>,
    last_arrival_ns: Option<u64>,
    pub ipa_ms: VecDeque<f64>,
    pub pps_series: VecDeque<f64>,
    pub arrival_ms: VecDeque<f64>,
    last_transit_ms: Option<f64>,
    pub jitter_samples_ms: VecDeque<f64>,
    pub rfc_jitter_ms: f64,
    first_seq: Option<u64>,
    seq_expected: Option<u64>,
    pub lost: u64,
    pub reordered: u64,
    pub loss_bursts: VecDeque<f64>,
    pub reorder_depths: VecDeque<f64>,
    pub duplicates: u64,
    seen: HashSet<u64>,
    seen_fifo: VecDeque<u64>,
}

impl FlowStats {
    pub fn new(mode: u8) -> Self {
        Self { mode, ..Default::default() }
    }

    pub fn on_packet(&mut self, seq: u64, send_ns: u64, recv_ns: u64, length: usize) {
        let length = length as u64;
        // Duplicates only count toward byte totals.
        if self.seen.contains(&seq) {
            self.duplicates += 1;
            self.bytes += length;
            self.bytes_out += length;
            return;
        }
        if self.seen_fifo.len() == DEDUP_CAP {
            if let Some(old) = self.seen_fifo.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(seq);
        self.seen_fifo.push_back(seq);

        self.packets += 1;
        self.bytes += length;
        self.bytes_out += length;
        self.first_ns.get_or_insert(recv_ns);
        self.last_ns = Some(recv_ns);
        push_capped(&mut self.arrival_ms, recv_ns as f64 / 1e6);

        if let Some(prev) = self.last_arrival_ns {
            let ipa = ((recv_ns as i64 - prev as i64) as f64 / 1e6).max(0.0);
            push_capped(&mut self.ipa_ms, ipa);
            if ipa > 0.0 {
                push_capped(&mut self.pps_series, 1000.0 / ipa);
            }
        }
        self.last_arrival_ns = Some(recv_ns);

        // Transit time against the client's send timestamp (clocks may differ).
        let transit_ms = (recv_ns as i64 - send_ns as i64) as f64 / 1e6;
        if let Some(prev) = self.last_transit_ms {
            let dt = (transit_ms - prev).abs();
            push_capped(&mut self.jitter_samples_ms, dt);
            // RFC 3550 estimator.
            self.rfc_jitter_ms += (dt - self.rfc_jitter_ms) / 16.0;
        }
        self.last_transit_ms = Some(transit_ms);

        match self.seq_expected {
            None => {
                self.first_seq = Some(seq);
                self.seq_expected = Some(seq + 1);
            }
            Some(exp) if seq == exp => self.seq_expected = Some(exp + 1),
            Some(exp) if seq > exp => {
                let gap = seq - exp;
                self.lost += gap;
                push_capped(&mut self.loss_bursts, gap as f64);
                self.seq_expected = Some(seq + 1);
            }
            Some(exp) => {
                self.reordered += 1;
                push_capped(&mut self.reorder_depths, (exp - seq) as f64);
                // Deliberate fix vs. the Python: a late packet was counted lost
                // when its gap was seen, so give that back (never below zero, and
                // not for sequence numbers before the first one we saw).
                if self.first_seq.is_some_and(|f| seq >= f) {
                    self.lost = self.lost.saturating_sub(1);
                }
            }
        }
    }

    /// Elapsed seconds between first and last packet (0 if undefined).
    pub fn elapsed_s(&self) -> f64 {
        match (self.first_ns, self.last_ns) {
            (Some(f), Some(l)) => ((l - f) as f64 / 1e9).max(1e-9),
            _ => 0.0,
        }
    }

    pub fn kbps_in(&self) -> f64 {
        kbps(self.bytes, self.elapsed_s())
    }

    pub fn kbps_out(&self) -> f64 {
        kbps(self.bytes_out, self.elapsed_s())
    }

    pub fn loss_pct(&self) -> f64 {
        let seen = self.packets + self.lost;
        if seen > 0 {
            self.lost as f64 / seen as f64 * 100.0
        } else {
            0.0
        }
    }
}

pub fn kbps(bytes: u64, elapsed_s: f64) -> f64 {
    if elapsed_s > 0.0 {
        bytes as f64 * 8.0 / 1000.0 / elapsed_s
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    fn feed(fs: &mut FlowStats, seqs: &[u64]) {
        for (i, &s) in seqs.iter().enumerate() {
            fs.on_packet(s, 1_000 * MS, 1_000 * MS + (i as u64) * 20 * MS, 100);
        }
    }

    #[test]
    fn in_order_has_no_loss() {
        let mut fs = FlowStats::new(1);
        feed(&mut fs, &[0, 1, 2, 3]);
        assert_eq!((fs.packets, fs.lost, fs.reordered, fs.duplicates), (4, 0, 0, 0));
        assert_eq!(fs.ipa_ms.len(), 3);
        assert!(fs.ipa_ms.iter().all(|v| (*v - 20.0).abs() < 1e-9));
        assert!((fs.pps_series[0] - 50.0).abs() < 1e-9);
    }

    #[test]
    fn gap_counts_as_burst() {
        let mut fs = FlowStats::new(1);
        feed(&mut fs, &[0, 1, 5]);
        assert_eq!(fs.lost, 3);
        assert_eq!(fs.loss_bursts, VecDeque::from([3.0]));
        assert!((fs.loss_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn late_packet_gives_back_loss() {
        let mut fs = FlowStats::new(1);
        feed(&mut fs, &[0, 1, 3, 2]);
        assert_eq!(fs.reordered, 1);
        assert_eq!(fs.lost, 0);
        assert_eq!(fs.reorder_depths, VecDeque::from([2.0]));
    }

    #[test]
    fn packet_before_first_seq_is_not_credited() {
        let mut fs = FlowStats::new(1);
        feed(&mut fs, &[5, 6, 8, 3]);
        assert_eq!(fs.lost, 1); // seq 7 only
        assert_eq!(fs.reordered, 1);
    }

    #[test]
    fn duplicates_only_add_bytes() {
        let mut fs = FlowStats::new(1);
        feed(&mut fs, &[0, 1, 1]);
        assert_eq!((fs.packets, fs.duplicates, fs.bytes, fs.bytes_out), (2, 1, 300, 300));
        assert_eq!(fs.ipa_ms.len(), 1);
    }

    #[test]
    fn jitter_and_rfc() {
        let mut fs = FlowStats::new(1);
        // transit: 0ms then 16ms -> dt 16, rfc = 1.0
        fs.on_packet(0, 0, 0, 22);
        fs.on_packet(1, 0, 16 * MS, 22);
        assert_eq!(fs.jitter_samples_ms, VecDeque::from([16.0]));
        assert!((fs.rfc_jitter_ms - 1.0).abs() < 1e-12);
    }

    #[test]
    fn series_are_capped() {
        let mut fs = FlowStats::new(1);
        for i in 0..(SERIES_CAP as u64 + 10) {
            fs.on_packet(i, 0, i * MS, 22);
        }
        assert_eq!(fs.arrival_ms.len(), SERIES_CAP);
        assert_eq!(fs.packets, SERIES_CAP as u64 + 10);
    }

    #[test]
    fn dedup_window_is_bounded() {
        let mut fs = FlowStats::new(1);
        for i in 0..(DEDUP_CAP as u64 + 5) {
            fs.on_packet(i, 0, i * 1000, 22);
        }
        assert_eq!(fs.seen.len(), DEDUP_CAP);
        // evicted seq 0 is no longer recognised as a duplicate
        fs.on_packet(0, 0, 10_000_000_000, 22);
        assert_eq!(fs.duplicates, 0);
    }
}
