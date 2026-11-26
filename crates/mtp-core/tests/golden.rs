//! Compare mtp-core against fixtures produced by the Python reference (tools/gen_golden.py).

use mtp_core::{mos, stats};
use serde_json::Value;

fn load() -> Value {
    let raw = include_str!("fixtures/golden.json");
    serde_json::from_str(raw).unwrap()
}

fn f64s(v: &Value) -> Vec<f64> {
    v.as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect()
}

fn opt(v: &Value) -> Option<f64> {
    v.as_f64()
}

fn close(a: Option<f64>, b: Option<f64>, what: &str) {
    match (a, b) {
        (None, None) => {}
        (Some(a), Some(b)) => assert!((a - b).abs() <= 1e-9 * b.abs().max(1.0), "{what}: {a} vs {b}"),
        _ => panic!("{what}: {a:?} vs {b:?}"),
    }
}

#[test]
fn stats_match_python() {
    for (i, c) in load()["stats"].as_array().unwrap().iter().enumerate() {
        let s = f64s(&c["samples"]);
        close(stats::percentile(&s, 50.0), opt(&c["p50"]), &format!("case {i} p50"));
        close(stats::percentile(&s, 95.0), opt(&c["p95"]), &format!("case {i} p95"));
        close(stats::percentile(&s, 99.0), opt(&c["p99"]), &format!("case {i} p99"));
        close(stats::stddev(&s), opt(&c["stddev"]), &format!("case {i} stddev"));
        if let Some(a) = c.get("arrivals_ms") {
            let got = stats::smoothed_packet_rates(&f64s(a));
            assert_eq!(got, f64s(&c["smoothed"]), "case {i} smoothed");
        }
    }
}

#[test]
fn mos_match_python() {
    for (i, c) in load()["mos"].as_array().unwrap().iter().enumerate() {
        let ow = f64s(&c["one_way_ms"]);
        let jit = f64s(&c["jitter_ms"]);
        let avg = ow.iter().sum::<f64>() / ow.len() as f64;
        let loss_pct = c["loss_pct"].as_f64().unwrap();
        close(Some(loss_pct), opt(&c["loss_pct"]), "loss");

        let audio = mos::audio_mos(avg, loss_pct);
        close(Some(audio), opt(&c["audio_mos"]), &format!("case {i} audio"));

        let video = mos::video_mos(
            avg,
            stats::percentile(&ow, 95.0),
            stats::percentile(&jit, 95.0),
            c["kbps_send"].as_f64().unwrap(),
            c["kbps_recv"].as_f64().unwrap(),
        );
        close(Some(video), opt(&c["video_mos"]), &format!("case {i} video"));
        close(
            Some(mos::call_usability(audio, video)),
            opt(&c["call_usability"]),
            &format!("case {i} usability"),
        );
    }
}
