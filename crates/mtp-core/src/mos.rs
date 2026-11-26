//! MOS estimates ported from `Metrics.summarize` in `client.py`.

/// Simplified E-model (G.711-like, Ie=0, Bpl=10). `one_way_ms` is the mean one-way delay.
pub fn audio_mos(one_way_ms: f64, loss_pct: f64) -> f64 {
    let d = one_way_ms;
    let id = 0.024 * d + 0.11 * (d - 177.3).max(0.0);
    let (ie, bpl) = (0.0, 10.0);
    let ppl = loss_pct;
    let ie_eff = if ppl + bpl > 0.0 { ie + (95.0 - ie) * (ppl / (ppl + bpl)) } else { ie };
    let r = (94.2 - id - ie_eff).clamp(0.0, 100.0);
    let mos = 1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7.0e-6;
    mos.clamp(1.0, 4.5)
}

/// Heuristic from throughput ratio plus p95 delay / jitter headroom.
/// `delay_p95` and `jitter_p95` fall back like the Python `x or fallback`:
/// `None` (and 0.0) use `avg_one_way` / `0.0`.
pub fn video_mos(
    avg_one_way: f64,
    delay_p95: Option<f64>,
    jitter_p95: Option<f64>,
    kbps_send: f64,
    kbps_recv: f64,
) -> f64 {
    let ratio = if kbps_send > 0.0 { kbps_recv / kbps_send } else { 0.0 }.clamp(0.0, 1.0);
    let d95 = delay_p95.filter(|v| *v != 0.0).unwrap_or(avg_one_way);
    let j95 = jitter_p95.unwrap_or(0.0);
    let delay_factor = 1.0 / (1.0 + (d95 - 150.0).max(0.0) / 150.0);
    let jitter_factor = 1.0 / (1.0 + (j95 - 30.0).max(0.0) / 30.0);
    (1.0 + 4.0 * ratio * delay_factor * jitter_factor).clamp(1.0, 4.5)
}

/// Average of the two MOS values normalised to 0..100.
pub fn call_usability(audio: f64, video: f64) -> f64 {
    let norm = |m: f64| ((m - 1.0) / (4.5 - 1.0)).clamp(0.0, 1.0);
    100.0 * (norm(audio) + norm(video)) / 2.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_clean_path_is_high() {
        let m = audio_mos(20.0, 0.0);
        assert!(m > 4.3 && m <= 4.5, "{m}");
    }

    #[test]
    fn loss_lowers_audio_mos() {
        assert!(audio_mos(20.0, 10.0) < audio_mos(20.0, 0.0));
    }

    #[test]
    fn usability_bounds() {
        assert_eq!(call_usability(1.0, 1.0), 0.0);
        assert_eq!(call_usability(4.5, 4.5), 100.0);
    }
}
