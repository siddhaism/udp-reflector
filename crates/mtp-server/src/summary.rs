//! Text and JSON summaries (ports of `generate_summary` / `generate_summary_json`).

use serde_json::{json, Value};

use mtp_core::stats::{percentile, stddev};

use crate::aggregator::{Aggregator, FlowKey};
use crate::flow::{kbps, FlowStats};

const MAX_FLOWS: usize = 8;

pub fn fmt(v: Option<f64>) -> String {
    v.map_or("n/a".to_string(), |v| format!("{v:.2}"))
}

fn vec(q: &std::collections::VecDeque<f64>) -> Vec<f64> {
    q.iter().copied().collect()
}

fn p3(d: &[f64]) -> [Option<f64>; 3] {
    [percentile(d, 50.0), percentile(d, 95.0), percentile(d, 99.0)]
}

fn p3_str(d: &[f64]) -> String {
    let [a, b, c] = p3(d);
    format!("{}/{}/{}", fmt(a), fmt(b), fmt(c))
}

fn pps_str(d: &[f64]) -> String {
    let [a, b, c] = p3(d);
    format!("{}/{}/{}/{}", fmt(a), fmt(b), fmt(c), fmt(stddev(d)))
}

type Active<'a> = Vec<(&'a FlowKey, &'a FlowStats)>;

fn active_flows(agg: &Aggregator, now_ns: u64, ttl_ns: u64) -> Active<'_> {
    agg.flows
        .iter()
        .filter(|(_, fs)| fs.last_ns.is_some_and(|l| now_ns.saturating_sub(l) <= ttl_ns))
        .collect()
}

fn by_bytes_desc(active: &mut Active<'_>) {
    // tie-break on key so output is deterministic
    active.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then_with(|| a.0.cmp(b.0)));
}

fn ttl_to_ns(idle_ttl_s: f64) -> u64 {
    (idle_ttl_s * 1e9) as u64
}

/// Human-readable summary. Prunes long-idle flows first. Returns an empty string
/// when idle and `silent_when_idle` is set.
pub fn generate_summary(agg: &mut Aggregator, now_ns: u64, idle_ttl_s: f64, silent_when_idle: bool) -> String {
    let ttl_ns = ttl_to_ns(idle_ttl_s);
    agg.prune(now_ns, ttl_ns);
    let mut active = active_flows(agg, now_ns, ttl_ns);
    if active.is_empty() {
        return if silent_when_idle { String::new() } else { "[server] idle (no active flows)".into() };
    }

    let mut lines: Vec<String> = vec!["=== Server Media Stats ===".into()];
    lines.extend(agg.header_lines.iter().cloned());
    lines.push(format!("Active flows: {} (TTL {:.0}s)", active.len(), idle_ttl_s));

    by_bytes_desc(&mut active);
    for ((host, port, _), fs) in active.iter().take(MAX_FLOWS) {
        let ipa = vec(&fs.ipa_ms);
        let jit = vec(&fs.jitter_samples_ms);
        let pps = vec(&fs.pps_series);
        lines.push(format!("- Flow: {host}:{port} mode={}", fs.mode));
        lines.push(format!("  - Packets: {}", fs.packets));
        lines.push("  - Latency (ms): P50/P95/P99 = n/a/n/a/n/a".into());
        lines.push("  - RTT (ms):     P50/P95/P99 = n/a/n/a/n/a".into());
        lines.push(format!(
            "  - Jitter (ms):  P50/P95/P99 = {}, RFC3550={:.2}",
            p3_str(&jit),
            fs.rfc_jitter_ms
        ));
        lines.push(format!("  - IPA (ms):     P50/P95/P99 = {}", p3_str(&ipa)));
        lines.push(format!("  - Throughput (kbps): in={:.1} out={:.1}", fs.kbps_in(), fs.kbps_out()));
        lines.push(format!("  - PPS:          P50/P95/P99/std = {}", pps_str(&pps)));
        lines.push(format!("  - Duplicates: {}", fs.duplicates));
    }

    // A single flow's aggregate would just repeat it.
    if active.len() == 1 {
        return lines.join("\n");
    }

    let (mut pkts, mut dups, mut bytes, mut bytes_out) = (0u64, 0u64, 0u64, 0u64);
    let (mut first, mut last): (Option<u64>, Option<u64>) = (None, None);
    let (mut ipa, mut jit, mut pps) = (vec![], vec![], vec![]);
    for (_, fs) in &active {
        pkts += fs.packets;
        dups += fs.duplicates;
        bytes += fs.bytes;
        bytes_out += fs.bytes_out;
        first = min_opt(first, fs.first_ns);
        last = max_opt(last, fs.last_ns);
        ipa.extend(fs.ipa_ms.iter());
        jit.extend(fs.jitter_samples_ms.iter());
        pps.extend(fs.pps_series.iter());
    }
    let elapsed = span_s(first, last);
    lines.push("Aggregate:".into());
    lines.push(format!("  - Packets: {pkts}"));
    lines.push("  - Latency (ms): P50/P95/P99 = n/a/n/a/n/a".into());
    lines.push("  - RTT (ms):     P50/P95/P99 = n/a/n/a/n/a".into());
    lines.push(format!("  - Jitter (ms):  P50/P95/P99 = {}", p3_str(&jit)));
    lines.push(format!("  - IPA (ms):     P50/P95/P99 = {}", p3_str(&ipa)));
    lines.push(format!(
        "  - Throughput (kbps): in={:.1} out={:.1}",
        kbps(bytes, elapsed),
        kbps(bytes_out, elapsed)
    ));
    lines.push(format!("  - PPS:          P50/P95/P99/std = {}", pps_str(&pps)));
    lines.push(format!("  - Duplicates: {dups}"));
    lines.join("\n")
}

fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (x, None) | (None, x) => x,
    }
}

fn max_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (x, None) | (None, x) => x,
    }
}

fn span_s(first: Option<u64>, last: Option<u64>) -> f64 {
    match (first, last) {
        (Some(f), Some(l)) => (l.saturating_sub(f) as f64 / 1e9).max(1e-9),
        _ => 0.0,
    }
}

fn q_json(d: &[f64]) -> Value {
    let [a, b, c] = p3(d);
    json!({"p50": a, "p95": b, "p99": c})
}

fn pps_json(d: &[f64]) -> Value {
    let [a, b, c] = p3(d);
    json!({"p50": a, "p95": b, "p99": c, "std": stddev(d)})
}

/// Optional exact-match filters on a flow's remote host / UDP port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Filter {
    pub host: Option<String>,
    pub port: Option<u16>,
}

impl Filter {
    fn matches(&self, key: &FlowKey) -> bool {
        self.host.as_deref().is_none_or(|h| h == key.0) && self.port.is_none_or(|p| p == key.1)
    }
}

/// Owned copy of what the JSON needs from one flow, so the aggregator lock can
/// be released before any percentile work is done.
#[derive(Debug, Clone)]
pub struct FlowSnap {
    host: String,
    port: u16,
    mode: u8,
    packets: u64,
    duplicates: u64,
    bytes: u64,
    bytes_out: u64,
    first_ns: Option<u64>,
    last_ns: Option<u64>,
    kbps_in: f64,
    kbps_out: f64,
    rfc_jitter_ms: f64,
    ipa: Vec<f64>,
    jit: Vec<f64>,
    pps: Vec<f64>,
}

/// Copy the (up to eight) most active matching flows out of the aggregator.
pub fn snapshot_flows(agg: &Aggregator, now_ns: u64, idle_ttl_s: f64, filter: &Filter) -> Vec<FlowSnap> {
    let mut active = active_flows(agg, now_ns, ttl_to_ns(idle_ttl_s));
    active.retain(|(k, _)| filter.matches(k));
    by_bytes_desc(&mut active);
    active
        .iter()
        .take(MAX_FLOWS)
        .map(|((host, port, mode), fs)| FlowSnap {
            host: host.clone(),
            port: *port,
            mode: *mode,
            packets: fs.packets,
            duplicates: fs.duplicates,
            bytes: fs.bytes,
            bytes_out: fs.bytes_out,
            first_ns: fs.first_ns,
            last_ns: fs.last_ns,
            kbps_in: fs.kbps_in(),
            kbps_out: fs.kbps_out(),
            rfc_jitter_ms: fs.rfc_jitter_ms,
            ipa: vec(&fs.ipa_ms),
            jit: vec(&fs.jitter_samples_ms),
            pps: vec(&fs.pps_series),
        })
        .collect()
}

/// Per-flow JSON object.
pub fn flow_json(f: &FlowSnap) -> Value {
    let mut jit_obj = q_json(&f.jit);
    jit_obj["rfc3550"] = json!(f.rfc_jitter_ms);
    json!({
        "remote": f.host,
        "udp_port": f.port,
        "mode": f.mode,
        "packets": f.packets,
        "duplicates": f.duplicates,
        "throughput_kbps": {"in": f.kbps_in, "out": f.kbps_out},
        "ipa_ms": q_json(&f.ipa),
        "jitter_ms": jit_obj,
        "pps": pps_json(&f.pps),
    })
}

/// Build the summary JSON from a snapshot; `None` when empty and `silent_when_idle`.
pub fn summary_json_from(flows: &[FlowSnap], silent_when_idle: bool) -> Option<Value> {
    if flows.is_empty() {
        return if silent_when_idle { None } else { Some(json!({"idle": true, "active_flows": []})) };
    }
    let (mut bytes, mut bytes_out, mut pkts, mut dups) = (0u64, 0u64, 0u64, 0u64);
    let (mut first, mut last): (Option<u64>, Option<u64>) = (None, None);
    let (mut ipa_all, mut jit_all, mut pps_all) = (vec![], vec![], vec![]);

    // Like the Python, the aggregate covers only the flows that are listed.
    for f in flows {
        bytes = bytes.saturating_add(f.bytes);
        bytes_out = bytes_out.saturating_add(f.bytes_out);
        pkts = pkts.saturating_add(f.packets);
        dups = dups.saturating_add(f.duplicates);
        first = min_opt(first, f.first_ns);
        last = max_opt(last, f.last_ns);
        ipa_all.extend(f.ipa.iter().copied());
        jit_all.extend(f.jit.iter().copied());
        pps_all.extend(f.pps.iter().copied());
    }
    let elapsed = span_s(first, last);
    Some(json!({
        "idle": false,
        "active_count": flows.len(),
        "flows": flows.iter().map(flow_json).collect::<Vec<_>>(),
        "aggregate": {
            "packets": pkts,
            "duplicates": dups,
            "throughput_kbps": {"in": kbps(bytes, elapsed), "out": kbps(bytes_out, elapsed)},
            "ipa_ms": q_json(&ipa_all),
            "jitter_ms": q_json(&jit_all),
            "pps": pps_json(&pps_all),
        },
    }))
}

/// Machine-readable summary restricted to flows matching `filter`; `None` when
/// idle and `silent_when_idle`.
pub fn generate_summary_json_filtered(
    agg: &Aggregator,
    now_ns: u64,
    idle_ttl_s: f64,
    silent_when_idle: bool,
    filter: &Filter,
) -> Option<Value> {
    summary_json_from(&snapshot_flows(agg, now_ns, idle_ttl_s, filter), silent_when_idle)
}

/// Machine-readable summary; `None` when idle and `silent_when_idle`.
pub fn generate_summary_json(agg: &Aggregator, now_ns: u64, idle_ttl_s: f64, silent_when_idle: bool) -> Option<Value> {
    generate_summary_json_filtered(agg, now_ns, idle_ttl_s, silent_when_idle, &Filter::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp_core::wire::{build_packet, Mode};

    fn agg_with(flows: &[(&str, u16, u64)]) -> Aggregator {
        let mut a = Aggregator::new(vec!["HDR".into()]);
        for &(host, port, n) in flows {
            for seq in 0..n {
                let p = build_packet(Mode::Audio, seq, 0, 100).unwrap();
                a.on_packet(&p, host, port, 1_000_000_000 + seq * 20_000_000);
            }
        }
        a
    }

    #[test]
    fn idle_variants() {
        let mut a = Aggregator::default();
        assert_eq!(generate_summary(&mut a, 0, 10.0, false), "[server] idle (no active flows)");
        assert_eq!(generate_summary(&mut a, 0, 10.0, true), "");
        assert_eq!(generate_summary_json(&a, 0, 10.0, true), None);
        assert_eq!(generate_summary_json(&a, 0, 10.0, false).unwrap()["idle"], true);
    }

    #[test]
    fn single_flow_has_no_aggregate_block() {
        let mut a = agg_with(&[("h", 1, 50)]);
        let s = generate_summary(&mut a, 2_000_000_000, 10.0, false);
        assert!(s.contains("Active flows: 1 (TTL 10s)"));
        assert!(s.contains("HDR"));
        assert!(s.contains("IPA (ms):     P50/P95/P99 = 20.00/20.00/20.00"));
        assert!(!s.contains("Aggregate:"));
    }

    #[test]
    fn two_flows_have_aggregate_block() {
        let mut a = agg_with(&[("h", 1, 50), ("g", 2, 10)]);
        let s = generate_summary(&mut a, 2_000_000_000, 10.0, false);
        assert!(s.contains("Aggregate:"));
        assert!(s.contains("  - Packets: 60"));
    }

    #[test]
    fn json_shape() {
        let a = agg_with(&[("h", 1, 50)]);
        let v = generate_summary_json(&a, 2_000_000_000, 10.0, false).unwrap();
        assert_eq!(v["active_count"], 1);
        assert_eq!(v["flows"][0]["packets"], 50);
        assert_eq!(v["flows"][0]["mode"], 1);
        assert!(v["flows"][0]["jitter_ms"]["rfc3550"].is_number());
        assert_eq!(v["aggregate"]["packets"], 50);
    }

    #[test]
    fn json_filters() {
        let a = agg_with(&[("h", 1, 50), ("g", 2, 10), ("g", 3, 5)]);
        let now = 2_000_000_000;
        let f = |host: Option<&str>, port| Filter { host: host.map(String::from), port };
        let v = generate_summary_json_filtered(&a, now, 10.0, false, &f(Some("g"), None)).unwrap();
        assert_eq!(v["active_count"], 2);
        assert_eq!(v["aggregate"]["packets"], 15);
        let v = generate_summary_json_filtered(&a, now, 10.0, false, &f(None, Some(2))).unwrap();
        assert_eq!(v["active_count"], 1);
        assert_eq!(v["flows"][0]["remote"], "g");
        let v = generate_summary_json_filtered(&a, now, 10.0, false, &f(Some("h"), Some(2))).unwrap();
        assert_eq!(v, json!({"idle": true, "active_flows": []}));
        assert!(generate_summary_json_filtered(&a, now, 10.0, true, &f(Some("zz"), None)).is_none());
        // unfiltered matches the old entry point
        assert_eq!(
            generate_summary_json(&a, now, 10.0, false),
            generate_summary_json_filtered(&a, now, 10.0, false, &Filter::default())
        );
    }

    #[test]
    fn stale_flows_are_not_active() {
        let mut a = agg_with(&[("h", 1, 5)]);
        // 11s after the last packet with a 10s TTL
        let s = generate_summary(&mut a, 12_000_000_000, 10.0, false);
        assert_eq!(s, "[server] idle (no active flows)");
    }
}
