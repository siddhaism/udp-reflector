//! Statistics helpers ported from `metrics.py`.

/// Interpolated percentile; `None` when there are no samples.
pub fn percentile(data: &[f64], percent: f64) -> Option<f64> {
    if data.is_empty() {
        return None;
    }
    let mut sorted: Vec<f64> = data.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    if percent <= 0.0 {
        return Some(sorted[0]);
    }
    if percent >= 100.0 {
        return Some(sorted[sorted.len() - 1]);
    }
    let position = (sorted.len() - 1) as f64 * (percent / 100.0);
    let lo = position.floor() as usize;
    let hi = position.ceil() as usize;
    if lo == hi {
        return Some(sorted[lo]);
    }
    let lw = hi as f64 - position;
    let uw = position - lo as f64;
    Some(sorted[lo] * lw + sorted[hi] * uw)
}

/// Population standard deviation; `None` for an empty slice.
pub fn stddev(samples: &[f64]) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let n = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / n;
    let var = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n;
    Some(var.sqrt())
}

/// Packets in each trailing second (both endpoints inclusive) of an ordered
/// timestamp sequence in milliseconds.
pub fn smoothed_packet_rates(arrival_ms: &[f64]) -> Vec<f64> {
    let mut rates = Vec::with_capacity(arrival_ms.len());
    let mut start = 0usize;
    for (i, &t) in arrival_ms.iter().enumerate() {
        let window_start = t - 1000.0;
        while start < i && arrival_ms[start] < window_start {
            start += 1;
        }
        rates.push((i - start + 1) as f64);
    }
    rates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_basics() {
        assert_eq!(percentile(&[], 50.0), None);
        assert_eq!(percentile(&[3.0, 1.0, 2.0], 0.0), Some(1.0));
        assert_eq!(percentile(&[3.0, 1.0, 2.0], 100.0), Some(3.0));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 50.0), Some(2.5));
        assert_eq!(percentile(&[5.0], 95.0), Some(5.0));
    }

    #[test]
    fn stddev_basics() {
        assert_eq!(stddev(&[]), None);
        assert_eq!(stddev(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]), Some(2.0));
    }

    #[test]
    fn smoothed_rates_window() {
        // 0, 500, 1000, 1600: window at 1600 starts at 600 -> only 1000, 1600
        let r = smoothed_packet_rates(&[0.0, 500.0, 1000.0, 1600.0]);
        assert_eq!(r, vec![1.0, 2.0, 3.0, 2.0]);
    }
}
