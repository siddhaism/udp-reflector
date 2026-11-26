#!/usr/bin/env python3
"""Generate golden fixtures for mtp-core from the reference Python implementation.

Usage: python3 tools/gen_golden.py > crates/mtp-core/tests/fixtures/golden.json
"""
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from client import Metrics  # noqa: E402
from metrics import percentile, smoothed_packet_rates, stddev  # noqa: E402

rng = random.Random(1234)


def stats_case(samples, arrivals=None):
    c = {
        "samples": samples,
        "p50": percentile(samples, 50),
        "p95": percentile(samples, 95),
        "p99": percentile(samples, 99),
        "stddev": stddev(samples),
    }
    if arrivals is not None:
        c["arrivals_ms"] = arrivals
        c["smoothed"] = smoothed_packet_rates(arrivals)
    return c


def mos_case(n_sent, rtts, kbps_send, kbps_recv):
    m = Metrics()
    for _ in range(n_sent):
        m.on_send(100)
    t = 0.0
    for seq, rtt in enumerate(rtts):
        t += 20.0
        m.on_recv(seq, rtt, t)
    # duration chosen so kbps_send matches the requested value
    duration = (m.bytes_sent * 8) / 1000.0 / kbps_send
    s = m.summarize(duration, recv_bytes_actual=kbps_recv * duration * 1000.0 / 8)
    return {
        "one_way_ms": m.one_way_ms,
        "jitter_ms": m.jitter_ms,
        "sent": m.sent,
        "recv": m.recv,
        "kbps_send": s["throughput_kbps"][0],
        "kbps_recv": s["throughput_kbps"][1],
        "loss_pct": s["loss_pct"],
        "audio_mos": s["audio_mos"],
        "video_mos": s["video_mos"],
        "call_usability": s["call_usability"],
    }


out = {
    "stats": [
        stats_case([]),
        stats_case([5.0]),
        stats_case([1.0, 2.0, 3.0, 4.0]),
        stats_case([rng.uniform(0, 100) for _ in range(997)],
                   sorted(rng.uniform(0, 5000) for _ in range(997))),
        stats_case([rng.expovariate(0.1) for _ in range(50)],
                   sorted(rng.uniform(0, 3000) for _ in range(50))),
    ],
    "mos": [
        mos_case(100, [40.0 + rng.uniform(0, 5) for _ in range(100)], 64.0, 64.0),
        mos_case(100, [40.0 + rng.uniform(0, 5) for _ in range(90)], 64.0, 57.6),
        mos_case(100, [500.0 + rng.uniform(0, 200) for _ in range(95)], 100.0, 95.0),
        mos_case(50, [20.0 for _ in range(50)], 500.0, 100.0),
    ],
}
json.dump(out, sys.stdout, indent=1)
print()
