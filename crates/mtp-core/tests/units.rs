//! Unit tests for wire, mos, stats and control message parsing (public API only).

use mtp_core::control::{to_line, ControlMsg, Hello, HelloResp};
use mtp_core::mos::{audio_mos, call_usability, video_mos};
use mtp_core::stats::{percentile, smoothed_packet_rates, stddev};
use mtp_core::wire::{build_packet, parse_packet, Mode, WireError, HEADER_LEN, MAGIC, VERSION};

// ---------- wire ----------

#[test]
fn wire_header_len_boundary() {
    assert_eq!(build_packet(Mode::Audio, 0, 0, HEADER_LEN - 1), Err(WireError::SizeTooSmall(HEADER_LEN - 1)));
    assert_eq!(build_packet(Mode::Audio, 0, 0, 0), Err(WireError::SizeTooSmall(0)));
    assert_eq!(build_packet(Mode::Audio, 0, 0, HEADER_LEN).unwrap().len(), HEADER_LEN);
}

#[test]
fn wire_roundtrip_extremes() {
    for (seq, ns) in [(0u64, 0u64), (u64::MAX, u64::MAX), (1, u64::MAX), (u64::MAX, 1)] {
        for mode in [Mode::Audio, Mode::Video] {
            let p = build_packet(mode, seq, ns, HEADER_LEN).unwrap();
            let h = parse_packet(&p).unwrap();
            assert_eq!((h.version, h.mode, h.seq, h.send_ns), (VERSION, mode.flag(), seq, ns));
        }
    }
}

#[test]
fn wire_large_packet_roundtrip() {
    let p = build_packet(Mode::Video, 9, 10, 60_000).unwrap();
    assert_eq!(p.len(), 60_000);
    assert!(p[HEADER_LEN..].iter().all(|&b| b == 0));
    assert_eq!(parse_packet(&p).unwrap().seq, 9);
}

#[test]
fn wire_truncated_at_every_length_is_none() {
    let p = build_packet(Mode::Audio, 5, 6, HEADER_LEN).unwrap();
    for n in 0..HEADER_LEN {
        assert!(parse_packet(&p[..n]).is_none(), "len {n}");
    }
}

#[test]
fn wire_empty_and_garbage() {
    assert!(parse_packet(&[]).is_none());
    assert!(parse_packet(b"hello world, this is not a packet at all").is_none());
    assert!(parse_packet(&[0xFFu8; 100]).is_none());
    assert!(parse_packet(&[0u8; 100]).is_none());
}

#[test]
fn wire_bad_magic_every_byte() {
    for i in 0..4 {
        let mut p = build_packet(Mode::Audio, 1, 1, 64).unwrap();
        p[i] ^= 0xFF;
        assert!(parse_packet(&p).is_none(), "magic byte {i}");
    }
}

#[test]
fn wire_unknown_version_and_mode_are_accepted_raw() {
    let mut p = build_packet(Mode::Audio, 1, 1, 64).unwrap();
    p[4] = 99;
    p[5] = 200;
    let h = parse_packet(&p).unwrap();
    assert_eq!((h.version, h.mode), (99, 200));
}

#[test]
fn wire_trailing_nonzero_payload_ignored() {
    let mut p = build_packet(Mode::Audio, 3, 4, 100).unwrap();
    p[50..].fill(0xAB);
    let h = parse_packet(&p).unwrap();
    assert_eq!((h.seq, h.send_ns), (3, 4));
    assert_eq!(&p[..4], &MAGIC);
}

#[test]
fn wire_big_endian_layout() {
    let p = build_packet(Mode::Video, 0x0102030405060708, 0x1112131415161718, 22).unwrap();
    assert_eq!(&p[6..14], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&p[14..22], &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
}

// ---------- stats ----------

#[test]
fn percentile_empty_single_and_clamps() {
    assert_eq!(percentile(&[], 0.0), None);
    assert_eq!(percentile(&[], 100.0), None);
    for p in [0.0, 1.0, 50.0, 99.0, 100.0] {
        assert_eq!(percentile(&[7.5], p), Some(7.5));
    }
    let d = [1.0, 2.0, 3.0];
    assert_eq!(percentile(&d, -10.0), Some(1.0));
    assert_eq!(percentile(&d, 250.0), Some(3.0));
}

#[test]
fn percentile_interpolates_and_ignores_input_order() {
    let d = [10.0, 40.0, 20.0, 30.0];
    assert_eq!(percentile(&d, 50.0), Some(25.0));
    // position = 3 * 0.25 = 0.75 -> 10*0.25 + 20*0.75 = 17.5
    let v = percentile(&d, 25.0).unwrap();
    assert!((v - 17.5).abs() < 1e-9, "{v}");
    assert_eq!(percentile(&[2.0, 2.0, 2.0], 37.0), Some(2.0));
}

#[test]
fn percentile_does_not_mutate_input() {
    let d = vec![3.0, 1.0, 2.0];
    let _ = percentile(&d, 50.0);
    assert_eq!(d, vec![3.0, 1.0, 2.0]);
}

#[test]
fn stddev_edges() {
    assert_eq!(stddev(&[]), None);
    assert_eq!(stddev(&[42.0]), Some(0.0));
    assert_eq!(stddev(&[5.0, 5.0, 5.0]), Some(0.0));
    let s = stddev(&[0.0, 10.0]).unwrap();
    assert!((s - 5.0).abs() < 1e-12);
}

#[test]
fn smoothed_rates_edges() {
    assert!(smoothed_packet_rates(&[]).is_empty());
    assert_eq!(smoothed_packet_rates(&[123.0]), vec![1.0]);
    // exactly 1000ms apart: window start == earlier timestamp, so inclusive
    assert_eq!(smoothed_packet_rates(&[0.0, 1000.0]), vec![1.0, 2.0]);
    assert_eq!(smoothed_packet_rates(&[0.0, 1000.5]), vec![1.0, 1.0]);
    // identical timestamps all count
    assert_eq!(smoothed_packet_rates(&[5.0, 5.0, 5.0]), vec![1.0, 2.0, 3.0]);
}

// ---------- mos ----------

#[test]
fn audio_mos_bounds_and_monotonic() {
    let mut prev = f64::MAX;
    for d in [0.0, 50.0, 150.0, 177.3, 250.0, 500.0, 5000.0] {
        let m = audio_mos(d, 0.0);
        assert!((1.0..=4.5).contains(&m), "{d} -> {m}");
        assert!(m <= prev + 1e-12, "not monotonic at {d}");
        prev = m;
    }
    let mut prev = f64::MAX;
    for l in [0.0, 1.0, 5.0, 20.0, 50.0, 100.0] {
        let m = audio_mos(20.0, l);
        assert!((1.0..=4.5).contains(&m));
        assert!(m <= prev + 1e-12);
        prev = m;
    }
}

#[test]
fn audio_mos_total_loss_is_floor_ish_and_zero_inputs_ok() {
    assert!(audio_mos(0.0, 0.0).is_finite());
    assert!(audio_mos(20.0, 100.0) < 2.0);
    assert_eq!(audio_mos(1e9, 100.0), 1.0);
}

#[test]
fn video_mos_ideal_and_degraded() {
    assert_eq!(video_mos(20.0, Some(20.0), Some(1.0), 1000.0, 1000.0), 4.5);
    // nothing received
    assert_eq!(video_mos(20.0, None, None, 1000.0, 0.0), 1.0);
    // nothing sent -> ratio 0
    assert_eq!(video_mos(20.0, None, None, 0.0, 1000.0), 1.0);
    // recv > send is clamped to ratio 1
    assert_eq!(video_mos(20.0, None, None, 100.0, 1e6), 4.5);
}

#[test]
fn video_mos_fallbacks_and_penalties() {
    // None / 0.0 delay_p95 falls back to avg_one_way
    let a = video_mos(400.0, None, None, 100.0, 100.0);
    let b = video_mos(400.0, Some(0.0), None, 100.0, 100.0);
    let c = video_mos(0.0, Some(400.0), None, 100.0, 100.0);
    assert_eq!(a, b);
    assert!((a - c).abs() < 1e-12);
    assert!(a < 4.5);
    // jitter penalty
    assert!(video_mos(10.0, None, Some(200.0), 100.0, 100.0) < video_mos(10.0, None, Some(10.0), 100.0, 100.0));
    // half throughput
    let h = video_mos(10.0, None, None, 100.0, 50.0);
    assert!((h - 3.0).abs() < 1e-12, "{h}");
}

#[test]
fn call_usability_values() {
    assert_eq!(call_usability(1.0, 1.0), 0.0);
    assert_eq!(call_usability(4.5, 4.5), 100.0);
    assert_eq!(call_usability(4.5, 1.0), 50.0);
    // out-of-range inputs are clamped
    assert_eq!(call_usability(-3.0, 99.0), 50.0);
}

// ---------- control ----------

#[test]
fn hello_defaults_and_errors() {
    let h: Hello = serde_json::from_str(r#"{"mode":"audio"}"#).unwrap();
    assert_eq!(h.client_udp_port, None);
    let h: Hello = serde_json::from_str(r#"{"mode":"x","client_udp_port":null,"extra":1}"#).unwrap();
    assert_eq!(h.mode, "x");
    assert!(serde_json::from_str::<Hello>("{}").is_err());
    assert!(serde_json::from_str::<Hello>("not json").is_err());
    assert!(serde_json::from_str::<Hello>("").is_err());
    assert!(serde_json::from_str::<Hello>(r#"{"mode":"a","client_udp_port":70000}"#).is_err());
    assert!(serde_json::from_str::<Hello>(r#"{"mode":"a","client_udp_port":-1}"#).is_err());
}

#[test]
fn control_msg_variants() {
    let m: ControlMsg = serde_json::from_str("{}").unwrap();
    assert!(m.path_update.is_none());
    let m: ControlMsg = serde_json::from_str(r#"{"path_update":{"client_udp_port":null}}"#).unwrap();
    assert_eq!(m.path_update.unwrap().client_udp_port, None);
    assert!(serde_json::from_str::<ControlMsg>("[1,2]").is_err());
    assert!(serde_json::from_str::<ControlMsg>(r#"{"path_update":5}"#).is_err());
}

#[test]
fn to_line_is_single_line() {
    let r = HelloResp {
        ok: true,
        mode: "audio".into(),
        server_host_v4: None,
        server_host_v6: Some("::".into()),
        server_udp_port: 1,
        audio_port: 1,
        video_port: 2,
    };
    let l = to_line(&r).unwrap();
    assert_eq!(l.iter().filter(|&&b| b == b'\n').count(), 1);
    assert_eq!(*l.last().unwrap(), b'\n');
    assert_eq!(serde_json::from_slice::<HelloResp>(&l).unwrap(), r);
}
