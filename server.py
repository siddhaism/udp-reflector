#!/usr/bin/env python3
import argparse
import asyncio
import json
import socket
import time
import math
from collections import deque, defaultdict
from dataclasses import dataclass

# ===== Metrics Aggregator =====
MAGIC = b"MTP1"


def percentile(data, p):
    if not data:
        return None
    if p <= 0:
        return float(min(data))
    if p >= 100:
        return float(max(data))
    s = sorted(data)
    k = (len(s) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(s[int(k)])
    d0 = s[int(f)] * (c - k)
    d1 = s[int(c)] * (k - f)
    return float(d0 + d1)


class FlowStats:
    __slots__ = (
        "mode",
        "packets",
        "bytes",
        "bytes_out",
        "first_ns",
        "last_ns",
        "last_arrival_ns",
        "ipa_ms",
        "pps_series",
        "arrival_ms",
        "last_transit_ms",
        "jitter_samples_ms",
        "rfc_jitter_ms",
        "seq_expected",
        "lost",
        "reordered",
        "last_seq",
        "loss_bursts",
        "reorder_depths",
        "duplicates",
        "_seen",
        "_seen_fifo",
    )

    def __init__(self, mode):
        self.mode = mode
        self.packets = 0
        self.bytes = 0
        self.bytes_out = 0
        self.first_ns = 0
        self.last_ns = 0
        self.last_arrival_ns = None
        self.ipa_ms = deque(maxlen=5000)
        self.last_transit_ms = None
        self.pps_series = deque(maxlen=5000)
        self.arrival_ms = deque(maxlen=5000)
        self.jitter_samples_ms = deque(maxlen=5000)
        self.rfc_jitter_ms = 0.0
        self.seq_expected = None
        self.lost = 0
        self.reordered = 0
        self.last_seq = None
        self.loss_bursts = deque(maxlen=5000)
        self.reorder_depths = deque(maxlen=5000)
        self.duplicates = 0
        self._seen = set()
        self._seen_fifo = deque(maxlen=65536)

    def on_packet(self, seq, send_ns, recv_ns, length):
        # Duplicate detection: ignore for jitter/ipa/loss, count and return
        if seq in self._seen:
            self.duplicates += 1
            self.bytes += length  # still counts towards RX bytes
            self.bytes_out += length  # reflector echoes back
            return
        self._seen.add(seq)
        self._seen_fifo.append(seq)
        if len(self._seen_fifo) == self._seen_fifo.maxlen:
            # when over capacity, deque will discard left on next append; proactively remove
            try:
                old = self._seen_fifo.popleft()
                self._seen.discard(old)
            except IndexError:
                pass

        self.packets += 1
        self.bytes += length
        self.bytes_out += length
        if self.first_ns == 0:
            self.first_ns = recv_ns
        self.last_ns = recv_ns
        # Track arrival timestamp (ms) for smoothed PPS
        try:
            self.arrival_ms.append(recv_ns / 1e6)
        except Exception:
            pass

        # IPA
        if self.last_arrival_ns is not None:
            ipa = max(0.0, (recv_ns - self.last_arrival_ns) / 1e6)
            self.ipa_ms.append(ipa)
            if ipa > 0:
                self.pps_series.append(1000.0 / ipa)
        self.last_arrival_ns = recv_ns

        # Transit time using client send timestamp (ms)
        transit_ms = (recv_ns - send_ns) / 1e6
        if self.last_transit_ms is not None:
            dt = abs(transit_ms - self.last_transit_ms)
            self.jitter_samples_ms.append(dt)
            # RFC3550 jitter estimator (ms)
            self.rfc_jitter_ms += (dt - self.rfc_jitter_ms) / 16.0
        self.last_transit_ms = transit_ms

        # Loss / reordering (seq tracking)
        if self.seq_expected is None:
            self.seq_expected = seq + 1
            self.last_seq = seq
        else:
            if seq == self.seq_expected:
                self.seq_expected += 1
            elif seq > self.seq_expected:
                gap = (seq - self.seq_expected)
                self.lost += gap
                # treat this gap as one burst of length=gap
                self.loss_bursts.append(gap)
                self.seq_expected = seq + 1
            else:  # seq < expected
                self.reordered += 1
                depth = self.seq_expected - seq
                if depth > 0:
                    self.reorder_depths.append(depth)
            self.last_seq = seq


class Aggregator:
    def __init__(self, header_lines=None):
        self.flows = {}  # key -> FlowStats
        self.header_lines = header_lines or []
        # Map peer IP -> last reported client UDP port from control channel
        self.expected_udp_ports = {}
        # Map peer IP -> first observed NAT-mapped UDP port
        self.observed_udp_ports = {}
        # Pending connection infos awaiting NAT UDP observation
        self.pending_conn = {}

    def set_expected_udp_port(self, host, port):
        try:
            if host and port is not None:
                self.expected_udp_ports[str(host)] = int(port)
        except Exception:
            pass

    def set_pending_connection(self, host, info):
        try:
            if host and info:
                self.pending_conn[str(host)] = dict(info)
        except Exception:
            pass

    def _parse(self, data):
        # Expect MAGIC + ver(1)+mode(1)+seq(8)+send_ns(8)
        if len(data) < 22 or data[:4] != MAGIC:
            return None
        ver = data[4]
        mode = data[5]
        try:
            # big endian
            seq = int.from_bytes(data[6:14], "big")
            send_ns = int.from_bytes(data[14:22], "big")
        except Exception:
            return None
        return ver, mode, seq, send_ns

    def on_packet(self, udp_name, data, addr):
        parsed = self._parse(data)
        now_ns = time.time_ns()
        if not parsed:
            return
        ver, mode, seq, send_ns = parsed
        # Normalize addr key (host, port)
        if isinstance(addr, tuple) and len(addr) >= 2:
            host = addr[0]
            port = addr[1]
        else:
            host = str(addr)
            port = 0
        key = (host, port, mode)
        fs = self.flows.get(key)
        if fs is None:
            fs = FlowStats(mode)
            self.flows[key] = fs
            # Record observed NAT-mapped UDP source port
            try:
                self.observed_udp_ports[host] = int(port)
            except Exception:
                self.observed_udp_ports[host] = port
            # If we have pending connection info for this host, print a unified Connection line now
            try:
                info = self.pending_conn.pop(host, None)
                exp = self.expected_udp_ports.get(host)
                mode_name = info.get("mode_name") if isinstance(info, dict) else None
                if not mode_name:
                    mode_name = ("audio" if mode == 1 else ("video" if mode == 2 else str(mode)))
                if info:
                    ctcp = info.get("control_tcp", "n/a")
                    mudp = info.get("media_udp", "n/a")
                    fams = info.get("family", "n/a")
                    # Use consistent field order, include NAT UDP and reported UDP
                    rep_udp = (str(exp) if exp is not None else "n/a")
                    print(
                        f"[server] Connection: mode={mode_name} control_tcp={ctcp} media_udp={mudp} "
                        f"family={fams} remote={host} nat_udp={port} reported_udp={rep_udp}"
                    )
                else:
                    # Fallback to Observed UDP line
                    rep_udp = (str(exp) if exp is not None else "n/a")
                    print(
                        f"[server] Observed UDP: mode={mode_name} src_udp={port} reported_udp={rep_udp} remote={host}"
                    )
            except Exception:
                pass
        fs.on_packet(seq, send_ns, now_ns, len(data))

    def render_summary(self):
        lines = []
        lines.append("[server] === Stats ===")
        if not self.flows:
            lines.append("[server] no flows yet")
            return "\n".join(lines)
        # Show up to 8 busiest flows by bytes
        flows_sorted = sorted(self.flows.items(), key=lambda kv: kv[1].bytes, reverse=True)[:8]
        for (host, port, mode), fs in flows_sorted:
            elapsed = max(1e-9, (fs.last_ns - fs.first_ns) / 1e9) if fs.first_ns and fs.last_ns else 0.0
            kbps_in = (fs.bytes * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
            kbps_out = (fs.bytes_out * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
            ipa_p50 = percentile(list(fs.ipa_ms), 50)
            ipa_p95 = percentile(list(fs.ipa_ms), 95)
            ipa_p99 = percentile(list(fs.ipa_ms), 99)
            jit_p50 = percentile(list(fs.jitter_samples_ms), 50)
            jit_p95 = percentile(list(fs.jitter_samples_ms), 95)
            jit_p99 = percentile(list(fs.jitter_samples_ms), 99)
            total_seen = fs.packets + fs.lost
            loss_pct = (fs.lost / total_seen * 100.0) if total_seen > 0 else 0.0
            # Burst loss and reorder depth
            burst_p50 = percentile(list(fs.loss_bursts), 50)
            burst_p95 = percentile(list(fs.loss_bursts), 95)
            burst_max = max(fs.loss_bursts) if fs.loss_bursts else None
            rord_p50 = percentile(list(fs.reorder_depths), 50)
            rord_p95 = percentile(list(fs.reorder_depths), 95)
            rord_max = max(fs.reorder_depths) if fs.reorder_depths else None
            # PPS stability
            pps_p50 = percentile(list(fs.pps_series), 50)
            pps_p95 = percentile(list(fs.pps_series), 95)
            pps_p99 = percentile(list(fs.pps_series), 99)
            pps_std = stddev(list(fs.pps_series))
            # Smoothed PPS (1s window) using arrival_ms series
            smooth_rates = []
            ts = list(fs.arrival_ms)
            j = 0
            for i in range(len(ts)):
                t = ts[i]
                win_start = t - 1000.0
                while j < i and ts[j] < win_start:
                    j += 1
                count = (i - j + 1)
                if count > 0:
                    smooth_rates.append(float(count))
            sp50 = percentile(smooth_rates, 50)
            sp95 = percentile(smooth_rates, 95)
            sp99 = percentile(smooth_rates, 99)
            spstd = stddev(smooth_rates)
            lines.append(
                f"[server] flow {host}:{port} mode={mode} pkts={fs.packets} lost={fs.lost} ({loss_pct:.2f}%) "
                f"reordered={fs.reordered} dups={fs.duplicates} in_kbps={kbps_in:.1f} out_kbps={kbps_out:.1f}"
            )
            lines.append(
                f"  IPA(ms) P50/P95/P99={fmt(ipa_p50)}/{fmt(ipa_p95)}/{fmt(ipa_p99)} "
                f"Jitter(ms) P50/P95/P99={fmt(jit_p50)}/{fmt(jit_p95)}/{fmt(jit_p99)} RFC3550={fs.rfc_jitter_ms:.2f}"
            )
            lines.append(
                f"  Instantaneous PPS (from IPA) P50/P95/P99/std={fmt(pps_p50)}/{fmt(pps_p95)}/{fmt(pps_p99)}/{fmt(pps_std)}"
            )
            lines.append(
                f"  Smoothed PPS (1s window)     P50/P95/P99/std={fmt(sp50)}/{fmt(sp95)}/{fmt(sp99)}/{fmt(spstd)}"
            )

        # Aggregate across all flows
        total_pkts = 0
        total_lost = 0
        total_reordered = 0
        total_duplicates = 0
        total_bytes = 0
        g_first = None
        g_last = None
        all_ipa = []
        all_jit = []
        all_bursts = []
        all_rdepths = []
        all_pps = []
        all_ts = []
        for fs in self.flows.values():
            total_pkts += fs.packets
            total_lost += fs.lost
            total_reordered += fs.reordered
            total_duplicates += fs.duplicates
            total_bytes += fs.bytes
            if fs.first_ns:
                g_first = fs.first_ns if g_first is None else min(g_first, fs.first_ns)
            if fs.last_ns:
                g_last = fs.last_ns if g_last is None else max(g_last, fs.last_ns)
            all_ipa.extend(list(fs.ipa_ms))
            all_jit.extend(list(fs.jitter_samples_ms))
            all_bursts.extend(list(fs.loss_bursts))
            all_rdepths.extend(list(fs.reorder_depths))
            all_pps.extend(list(fs.pps_series))
            all_ts.extend(list(fs.arrival_ms))

        elapsed = max(1e-9, (g_last - g_first) / 1e9) if g_first and g_last else 0.0
        in_kbps = (total_bytes * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
        agg_loss_pct = (total_lost / (total_pkts + total_lost) * 100.0) if (total_pkts + total_lost) > 0 else 0.0
        agg_ipa = (percentile(all_ipa, 50), percentile(all_ipa, 95), percentile(all_ipa, 99))
        agg_jit = (percentile(all_jit, 50), percentile(all_jit, 95), percentile(all_jit, 99))
        agg_burst = (percentile(all_bursts, 50), percentile(all_bursts, 95), max(all_bursts) if all_bursts else None)
        agg_rdepth = (percentile(all_rdepths, 50), percentile(all_rdepths, 95), max(all_rdepths) if all_rdepths else None)
        agg_pps_inst = (percentile(all_pps, 50), percentile(all_pps, 95), percentile(all_pps, 99), stddev(all_pps))
        # Aggregate smoothed PPS: build sliding counts across all arrivals
        all_ts.sort()
        smooth_rates = []
        j = 0
        for i in range(len(all_ts)):
            t = all_ts[i]
            win_start = t - 1000.0
            while j < i and all_ts[j] < win_start:
                j += 1
            count = (i - j + 1)
            if count > 0:
                smooth_rates.append(float(count))
        agg_pps_smooth = (percentile(smooth_rates, 50), percentile(smooth_rates, 95), percentile(smooth_rates, 99), stddev(smooth_rates))

        lines.append(
            f"[server] aggregate pkts={total_pkts} lost={total_lost} ({agg_loss_pct:.2f}%) "
            f"reordered={total_reordered} dups={total_duplicates} in_kbps={in_kbps:.1f}"
        )
        lines.append(
            f"  IPA(ms) P50/P95/P99 {fmt(agg_ipa[0])}/{fmt(agg_ipa[1])}/{fmt(agg_ipa[2])} "
            f"Jitter(ms) P50/P95/P99 {fmt(agg_jit[0])}/{fmt(agg_jit[1])}/{fmt(agg_jit[2])} "
            f"LossBurst P50/P95/max={fmt(agg_burst[0])}/{fmt(agg_burst[1])}/{fmt(agg_burst[2])} "
            f"ReorderDepth P50/P95/max={fmt(agg_rdepth[0])}/{fmt(agg_rdepth[1])}/{fmt(agg_rdepth[2])}"
        )
        lines.append(
            f"  Instantaneous PPS (from IPA) P50/P95/P99/std={fmt(agg_pps_inst[0])}/{fmt(agg_pps_inst[1])}/{fmt(agg_pps_inst[2])}/{fmt(agg_pps_inst[3])}"
        )
        lines.append(
            f"  Smoothed PPS (1s window)     P50/P95/P99/std={fmt(agg_pps_smooth[0])}/{fmt(agg_pps_smooth[1])}/{fmt(agg_pps_smooth[2])}/{fmt(agg_pps_smooth[3])}"
        )
        return "\n".join(lines)


def stddev(xs):
    if not xs:
        return None
    m = sum(xs) / len(xs)
    return (sum((x - m) ** 2 for x in xs) / len(xs)) ** 0.5


def fmt(v):
    return "n/a" if v is None else f"{v:.2f}"


def emit_json(obj, cfg):
    try:
        line = json.dumps(obj, separators=(",", ":"))
        if getattr(cfg, 'json', False):
            print(line)
        path = getattr(cfg, 'json_file', None)
        if path:
            with open(path, 'a') as f:
                f.write(line + "\n")
    except Exception:
        pass


def generate_summary_json(aggregator, now_ns, idle_ttl_s=10.0, silent_when_idle=False, filter_host=None, filter_port=None):
    ttl_ns = int(idle_ttl_s * 1e9)
    active = []
    for k, fs in aggregator.flows.items():
        host, port, mode = k
        if filter_host is not None and host != filter_host:
            continue
        if filter_port is not None and port != filter_port:
            continue
        if fs.last_ns and (now_ns - fs.last_ns) <= ttl_ns:
            active.append((k, fs))

    if not active:
        if silent_when_idle:
            return None
        return {"idle": True, "active_flows": []}

    flows = []
    total_bytes = 0
    total_bytes_out = 0
    total_pkts = 0
    total_dups = 0
    g_first = None
    g_last = None
    all_ipa = []
    all_jit = []
    all_pps = []

    for (host, port, mode), fs in sorted(active, key=lambda kv: kv[1].bytes, reverse=True)[:8]:
        elapsed = max(1e-9, (fs.last_ns - fs.first_ns) / 1e9) if fs.first_ns and fs.last_ns else 0.0
        kbps_in = (fs.bytes * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
        kbps_out = (getattr(fs, 'bytes_out', 0) * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
        ipa_p50 = percentile(list(fs.ipa_ms), 50)
        ipa_p95 = percentile(list(fs.ipa_ms), 95)
        ipa_p99 = percentile(list(fs.ipa_ms), 99)
        jit_p50 = percentile(list(fs.jitter_samples_ms), 50)
        jit_p95 = percentile(list(fs.jitter_samples_ms), 95)
        jit_p99 = percentile(list(fs.jitter_samples_ms), 99)
        pps_p50 = percentile(list(fs.pps_series), 50)
        pps_p95 = percentile(list(fs.pps_series), 95)
        pps_p99 = percentile(list(fs.pps_series), 99)
        pps_std = stddev(list(fs.pps_series))

        flows.append({
            "remote": host,
            "udp_port": port,
            "mode": int(mode),
            "packets": fs.packets,
            "duplicates": fs.duplicates,
            "throughput_kbps": {"in": kbps_in, "out": kbps_out},
            "ipa_ms": {"p50": ipa_p50, "p95": ipa_p95, "p99": ipa_p99},
            "jitter_ms": {"p50": jit_p50, "p95": jit_p95, "p99": jit_p99, "rfc3550": fs.rfc_jitter_ms},
            "pps": {"p50": pps_p50, "p95": pps_p95, "p99": pps_p99, "std": pps_std},
        })

        total_bytes += fs.bytes
        total_bytes_out += getattr(fs, 'bytes_out', 0)
        total_pkts += fs.packets
        total_dups += fs.duplicates
        if fs.first_ns:
            g_first = fs.first_ns if g_first is None else min(g_first, fs.first_ns)
        if fs.last_ns:
            g_last = fs.last_ns if g_last is None else max(g_last, fs.last_ns)
        all_ipa.extend(list(fs.ipa_ms))
        all_jit.extend(list(fs.jitter_samples_ms))
        all_pps.extend(list(fs.pps_series))

    elapsed = max(1e-9, (g_last - g_first) / 1e9) if g_first and g_last else 0.0
    agg = {
        "packets": total_pkts,
        "duplicates": total_dups,
        "throughput_kbps": {
            "in": ((total_bytes * 8) / 1000.0 / elapsed) if elapsed > 0 else 0.0,
            "out": ((total_bytes_out * 8) / 1000.0 / elapsed) if elapsed > 0 else 0.0,
        },
        "ipa_ms": {
            "p50": percentile(all_ipa, 50),
            "p95": percentile(all_ipa, 95),
            "p99": percentile(all_ipa, 99),
        },
        "jitter_ms": {
            "p50": percentile(all_jit, 50),
            "p95": percentile(all_jit, 95),
            "p99": percentile(all_jit, 99),
        },
        "pps": {
            "p50": percentile(all_pps, 50),
            "p95": percentile(all_pps, 95),
            "p99": percentile(all_pps, 99),
            "std": stddev(all_pps),
        },
    }

    return {
        "idle": False,
        "active_count": len(flows),
        "flows": flows,
        "aggregate": agg,
    }


@dataclass
class UdpReflector:
    name: str
    host_v4: str
    host_v6: str
    port: int

    async def start(self, aggregator):
        loop = asyncio.get_running_loop()

        transports = []
        # IPv4 socket
        if self.host_v4:
            sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock4.bind((self.host_v4, self.port))
            transport4, _ = await loop.create_datagram_endpoint(
                lambda: _EchoProtocol(self.name, aggregator), sock=sock4
            )
            transports.append(transport4)

        # IPv6 socket (v6-only to avoid dual-stack conflicts)
        if self.host_v6:
            sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except OSError:
                pass
            sock6.bind((self.host_v6, self.port))
            transport6, _ = await loop.create_datagram_endpoint(
                lambda: _EchoProtocol(self.name, aggregator), sock=sock6
            )
            transports.append(transport6)

        return transports


class _EchoProtocol(asyncio.DatagramProtocol):
    def __init__(self, name: str, aggregator):
        self.name = name
        self.aggregator = aggregator

    def datagram_received(self, data, addr):
        # Echo the payload back immediately to reflect RTT
        # Keep payload unchanged so client can compute RTT using its timestamp
        # Errors are ignored intentionally for max throughput
        try:
            # Update metrics
            self.aggregator.on_packet(self.name, data, addr)
            # Echo back
            self.transport.sendto(data, addr)
        except Exception:
            pass

    def connection_made(self, transport):
        self.transport = transport

    def error_received(self, exc):
        # Silently ignore
        pass


async def handle_control(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg, aggregator):
    peer = writer.get_extra_info("peername")
    start_ns = time.time_ns()
    bytes_in = 0
    bytes_out = 0
    hello_rx_ns = None
    resp_tx_ns = None
    try:
        raw = await reader.readline()
        if not raw:
            writer.close()
            await writer.wait_closed()
            return
        try:
            hello = json.loads(raw.decode("utf-8", errors="ignore"))
        except json.JSONDecodeError:
            hello = {}
        hello_rx_ns = time.time_ns()
        bytes_in += len(raw)

        mode = hello.get("mode", "audio")
        # Client can provide its UDP port; we don't strictly need it, but accept it
        client_udp_port = hello.get("client_udp_port")

        # Record connection details on client connect. If NAT UDP already observed, print immediately;
        # otherwise store pending and print when first UDP arrives.
        try:
            peer_ip = None
            peer_tcp_port = None
            fam = None
            if isinstance(peer, tuple) and len(peer) >= 2:
                peer_ip = peer[0]
                peer_tcp_port = peer[1]
            sock = writer.get_extra_info("socket")
            if sock is not None:
                fam = "IPv6" if sock.family == socket.AF_INET6 else "IPv4"
            # Normalize for printing
            cip = peer_ip or "unknown"
            ctcp = str(peer_tcp_port) if peer_tcp_port is not None else "n/a"
            cudp = str(client_udp_port) if client_udp_port is not None else "n/a"
            fams = fam or "n/a"
            mudp = server_udp_port
            # If we already saw a UDP packet from this host, print full connection now with NAT UDP
            nat_udp = aggregator.observed_udp_ports.get(cip)
            if nat_udp is not None:
                rep_udp = str(client_udp_port) if client_udp_port is not None else "n/a"
                print(
                    f"[server] Connection: mode={mode} control_tcp={ctcp} media_udp={mudp} "
                    f"family={fams} remote={cip} nat_udp={nat_udp} reported_udp={rep_udp}"
                )
            else:
                # Store pending until first UDP observed
                aggregator.set_pending_connection(cip, {
                    "mode_name": mode,
                    "control_tcp": ctcp,
                    "media_udp": mudp,
                    "family": fams,
                    "reported_udp": cudp,
                })
        except Exception:
            pass

        # Select server UDP port for the requested mode
        if mode == "video":
            server_udp_port = cfg.video_port
        else:
            server_udp_port = cfg.audio_port

        # Record the client's reported UDP port (by peer IP) to correlate with observed media flow
        try:
            if isinstance(peer, tuple) and len(peer) >= 2 and client_udp_port is not None:
                aggregator.set_expected_udp_port(peer[0], client_udp_port)
        except Exception:
            pass

        resp = {
            "ok": True,
            "mode": mode,
            # Informational; client should ignore wildcard and use its supplied server_host
            "server_host_v4": cfg.udp_host_v4,
            "server_host_v6": cfg.udp_host_v6,
            "server_udp_port": server_udp_port,
            "audio_port": cfg.audio_port,
            "video_port": cfg.video_port,
        }
        out_line = (json.dumps(resp) + "\n").encode("utf-8")
        writer.write(out_line)
        bytes_out += len(out_line)
        await writer.drain()
        resp_tx_ns = time.time_ns()
        # Keep control connection open until client closes it
        # Read JSON lines for future control messages (e.g., path updates)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                bytes_in += len(line)
                try:
                    msg = json.loads(line.decode("utf-8", errors="ignore"))
                except json.JSONDecodeError:
                    continue
                upd = msg.get("path_update") if isinstance(msg, dict) else None
                if isinstance(upd, dict):
                    # Update expected UDP port for this TCP peer host
                    try:
                        if isinstance(peer, tuple) and len(peer) >= 2:
                            cip = peer[0]
                            cup = upd.get("client_udp_port")
                            if cup is not None:
                                aggregator.set_expected_udp_port(cip, int(cup))
                                print(f"[server] Control: path_update from {cip} reported_udp={cup}")
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        # Print a final stats snapshot on control disconnect
        try:
            header = f"Final stats for peer {peer} (control disconnect)"
            peer_host = None
            try:
                peer_host = peer[0]
            except Exception:
                peer_host = None
            snap = generate_summary(
                aggregator,
                time.time_ns(),
                # Use large TTL to include all recent flow data since run started
                idle_ttl_s=max(3600.0, getattr(cfg, 'idle_ttl', 10.0)),
                silent_when_idle=False,
                # Do not filter by TCP peer host; UDP may use different NAT IP
                filter_host=None,
            )
            if snap:
                print(header)
                print(snap)
                # Control stats section aligned with client order
                print("=== Control Stats ===")
                end_ns = time.time_ns()
                open_dur = (end_ns - start_ns) / 1e9 if start_ns else None
                hello_to_resp_ms = None
                if hello_rx_ns and resp_tx_ns:
                    hello_to_resp_ms = max(0.0, (resp_tx_ns - hello_rx_ns) / 1e6)
                print(f"  - Open duration: {open_dur:.2f}s" if open_dur is not None else "  - Open duration: n/a")
                print("  - Handshake RTT (ms): n/a")
                print(f"  - Hello->Resp (ms): {fmt(hello_to_resp_ms)}")
                print(f"  - Bytes: out={bytes_out} in={bytes_in}")

                # Optional JSON emission for machine parsing
                try:
                    if getattr(cfg, 'json', False) or getattr(cfg, 'json_file', None):
                        summary_obj = generate_summary_json(
                            aggregator,
                            time.time_ns(),
                            idle_ttl_s=max(3600.0, getattr(cfg, 'idle_ttl', 10.0)),
                            silent_when_idle=True,
                            filter_host=None,
                        )
                        event = {
                            "event": "final_stats",
                            "peer": {
                                "ip": (peer[0] if isinstance(peer, tuple) else None),
                                "tcp_port": (peer[1] if isinstance(peer, tuple) and len(peer) > 1 else None),
                            },
                            "control_stats": {
                                "open_duration_s": open_dur,
                                "hello_to_resp_ms": hello_to_resp_ms,
                                "bytes_out": bytes_out,
                                "bytes_in": bytes_in,
                            },
                            "summary": summary_obj,
                            "ts_ns": time.time_ns(),
                        }
                        emit_json(event, cfg)
                except Exception:
                    pass
        except Exception:
            pass


def generate_summary(aggregator, now_ns, idle_ttl_s=10.0, silent_when_idle=False, filter_host=None, filter_port=None):
    ttl_ns = int(idle_ttl_s * 1e9)
    active = []
    prune = []
    for k, fs in aggregator.flows.items():
        host, port, mode = k
        if filter_host is not None and host != filter_host:
            continue
        if filter_port is not None and port != filter_port:
            continue
        if fs.last_ns and (now_ns - fs.last_ns) <= ttl_ns:
            active.append((k, fs))
        elif fs.last_ns and (now_ns - fs.last_ns) > 10 * ttl_ns:
            prune.append(k)
    for k in prune:
        aggregator.flows.pop(k, None)

    if not active:
        if silent_when_idle:
            return ""
        return "[server] idle (no active flows)"

    lines = []
    lines.append("=== Server Media Stats ===")
    header_lines = getattr(aggregator, 'header_lines', None)
    if header_lines:
        lines.extend(header_lines)
    lines.append(f"Active flows: {len(active)} (TTL {idle_ttl_s:.0f}s)")

    flows_sorted = sorted(active, key=lambda kv: kv[1].bytes, reverse=True)[:8]
    for (host, port, mode), fs in flows_sorted:
        elapsed = max(1e-9, (fs.last_ns - fs.first_ns) / 1e9) if fs.first_ns and fs.last_ns else 0.0
        kbps_in = (fs.bytes * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
        kbps_out = (fs.bytes_out * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
        ipa_p50 = percentile(list(fs.ipa_ms), 50)
        ipa_p95 = percentile(list(fs.ipa_ms), 95)
        ipa_p99 = percentile(list(fs.ipa_ms), 99)
        jit_p50 = percentile(list(fs.jitter_samples_ms), 50)
        jit_p95 = percentile(list(fs.jitter_samples_ms), 95)
        jit_p99 = percentile(list(fs.jitter_samples_ms), 99)
        total_seen = fs.packets + fs.lost
        loss_pct = (fs.lost / total_seen * 100.0) if total_seen > 0 else 0.0
        burst_p50 = percentile(list(fs.loss_bursts), 50)
        burst_p95 = percentile(list(fs.loss_bursts), 95)
        burst_max = max(fs.loss_bursts) if fs.loss_bursts else None
        rord_p50 = percentile(list(fs.reorder_depths), 50)
        rord_p95 = percentile(list(fs.reorder_depths), 95)
        rord_max = max(fs.reorder_depths) if fs.reorder_depths else None
        pps_p50 = percentile(list(fs.pps_series), 50)
        pps_p95 = percentile(list(fs.pps_series), 95)
        pps_p99 = percentile(list(fs.pps_series), 99)
        pps_std = stddev(list(fs.pps_series))
        lines.append(f"- Flow: {host}:{port} mode={mode}")
        lines.append(
            f"  - Packets: {fs.packets}"
        )
        # Align sequence with client: Latency -> RTT -> Jitter -> IPA -> Throughput -> Loss burst -> Reorder depth -> PPS -> Duplicates
        lines.append("  - Latency (ms): P50/P95/P99 = n/a/n/a/n/a")
        lines.append("  - RTT (ms):     P50/P95/P99 = n/a/n/a/n/a")
        lines.append(
            f"  - Jitter (ms):  P50/P95/P99 = {fmt(jit_p50)}/{fmt(jit_p95)}/{fmt(jit_p99)}, RFC3550={fs.rfc_jitter_ms:.2f}"
        )
        lines.append(
            f"  - IPA (ms):     P50/P95/P99 = {fmt(ipa_p50)}/{fmt(ipa_p95)}/{fmt(ipa_p99)}"
        )
        lines.append(f"  - Throughput (kbps): in={kbps_in:.1f} out={kbps_out:.1f}")
        # Loss burst and reorder depth are not meaningful on a reflector; omit
        lines.append(
            f"  - PPS:          P50/P95/P99/std = {fmt(pps_p50)}/{fmt(pps_p95)}/{fmt(pps_p99)}/{fmt(pps_std)}"
        )
        lines.append(f"  - Duplicates: {fs.duplicates}")

    total_pkts = 0
    total_lost = 0
    total_reordered = 0
    total_duplicates = 0
    total_bytes = 0
    total_bytes_out = 0
    g_first = None
    g_last = None
    all_ipa = []
    all_jit = []
    all_bursts = []
    all_rdepths = []
    all_pps = []
    for _, fs in active:
        total_pkts += fs.packets
        total_lost += fs.lost
        total_reordered += fs.reordered
        total_duplicates += fs.duplicates
        total_bytes += fs.bytes
        total_bytes_out += getattr(fs, 'bytes_out', 0)
        if fs.first_ns:
            g_first = fs.first_ns if g_first is None else min(g_first, fs.first_ns)
        if fs.last_ns:
            g_last = fs.last_ns if g_last is None else max(g_last, fs.last_ns)
        all_ipa.extend(list(fs.ipa_ms))
        all_jit.extend(list(fs.jitter_samples_ms))
        all_bursts.extend(list(fs.loss_bursts))
        all_rdepths.extend(list(fs.reorder_depths))
        all_pps.extend(list(fs.pps_series))

    elapsed = max(1e-9, (g_last - g_first) / 1e9) if g_first and g_last else 0.0
    in_kbps = (total_bytes * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
    out_kbps = (total_bytes_out * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
    agg_loss_pct = (total_lost / (total_pkts + total_lost) * 100.0) if (total_pkts + total_lost) > 0 else 0.0
    agg_ipa = (percentile(all_ipa, 50), percentile(all_ipa, 95), percentile(all_ipa, 99))
    agg_jit = (percentile(all_jit, 50), percentile(all_jit, 95), percentile(all_jit, 99))
    agg_burst = (percentile(all_bursts, 50), percentile(all_bursts, 95), max(all_bursts) if all_bursts else None)
    agg_rdepth = (percentile(all_rdepths, 50), percentile(all_rdepths, 95), max(all_rdepths) if all_rdepths else None)
    agg_pps = (percentile(all_pps, 50), percentile(all_pps, 95), percentile(all_pps, 99), stddev(all_pps))

    # If only one active flow, aggregate equals that flow; suppress duplicate
    if len(active) == 1:
        return "\n".join(lines)

    lines.append("Aggregate:")
    lines.append(
        f"  - Packets: {total_pkts}"
    )
    lines.append("  - Latency (ms): P50/P95/P99 = n/a/n/a/n/a")
    lines.append("  - RTT (ms):     P50/P95/P99 = n/a/n/a/n/a")
    lines.append(
        f"  - Jitter (ms):  P50/P95/P99 = {fmt(agg_jit[0])}/{fmt(agg_jit[1])}/{fmt(agg_jit[2])}"
    )
    lines.append(
        f"  - IPA (ms):     P50/P95/P99 = {fmt(agg_ipa[0])}/{fmt(agg_ipa[1])}/{fmt(agg_ipa[2])}"
    )
    lines.append(f"  - Throughput (kbps): in={in_kbps:.1f} out={out_kbps:.1f}")
    # Omit aggregate loss burst and reorder depth on reflector
    lines.append(
        f"  - PPS:          P50/P95/P99/std = {fmt(agg_pps[0])}/{fmt(agg_pps[1])}/{fmt(agg_pps[2])}/{fmt(agg_pps[3])}"
    )
    lines.append(f"  - Duplicates: {total_duplicates}")
    return "\n".join(lines)

async def main():
    ap = argparse.ArgumentParser(description="Media transport server: TCP control + UDP reflector")
    ap.add_argument("--tcp-host-v4", default="0.0.0.0", help="TCP control IPv4 host (default: 0.0.0.0)")
    ap.add_argument("--tcp-host-v6", default="::", help="TCP control IPv6 host (default: ::)")
    ap.add_argument("--tcp-port", type=int, default=5000, help="TCP control port (default: 5000)")
    ap.add_argument("--udp-host-v4", default="0.0.0.0", help="UDP IPv4 bind host (default: 0.0.0.0)")
    ap.add_argument("--udp-host-v6", default="::", help="UDP IPv6 bind host (default: ::)")
    ap.add_argument("--audio-port", type=int, default=6000, help="UDP port for audio reflection (default: 6000)")
    ap.add_argument("--video-port", type=int, default=6001, help="UDP port for video reflection (default: 6001)")
    ap.add_argument("--stats-interval", type=float, default=5.0, help="Seconds between server stats prints (default: 5)")
    ap.add_argument("--periodic-stats", action="store_true", help="Enable periodic stats printing (default: off)")
    ap.add_argument("--idle-ttl", type=float, default=10.0, help="Seconds of inactivity to consider a flow idle (default: 10)")
    ap.add_argument("--silent-when-idle", action="store_true", help="Do not print when no active flows in window")
    ap.add_argument("--json", action="store_true", help="Emit JSON lines for summaries (stdout)")
    ap.add_argument("--json-file", default=None, help="Append JSON lines to file path")

    args = ap.parse_args()

    # Metrics aggregator with header details
    header_lines = [
        f"TCP control: v4 {args.tcp_host_v4}:{args.tcp_port} | v6 [{args.tcp_host_v6}]:{args.tcp_port}",
        f"UDP audio: v4 {args.udp_host_v4}:{args.audio_port} | v6 [{args.udp_host_v6}]:{args.audio_port}",
        f"UDP video: v4 {args.udp_host_v4}:{args.video_port} | v6 [{args.udp_host_v6}]:{args.video_port}",
    ]
    aggregator = Aggregator(header_lines)

    # Start UDP reflectors (IPv4 + IPv6)
    audio_reflector = UdpReflector("audio", args.udp_host_v4, args.udp_host_v6, args.audio_port)
    video_reflector = UdpReflector("video", args.udp_host_v4, args.udp_host_v6, args.video_port)
    a_transports = await audio_reflector.start(aggregator)
    v_transports = await video_reflector.start(aggregator)

    # Start TCP control servers on IPv4 and IPv6 with v6-only socket
    async def _make_tcp_server(host_v4, host_v6, port):
        servers = []
        # IPv4
        if host_v4:
            srv4 = await asyncio.start_server(lambda r, w: handle_control(r, w, args, aggregator), host_v4, port)
            servers.append(srv4)
        # IPv6 with v6only ensured via pre-created socket
        if host_v6:
            sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except OSError:
                pass
            sock6.bind((host_v6, port))
            sock6.listen(100)
            sock6.setblocking(False)
            srv6 = await asyncio.start_server(lambda r, w: handle_control(r, w, args, aggregator), sock=sock6)
            servers.append(srv6)
        return servers

    servers = await _make_tcp_server(args.tcp_host_v4, args.tcp_host_v6, args.tcp_port)
    addr_list = []
    for srv in servers:
        addr_list.extend(str(sock.getsockname()) for sock in (srv.sockets or []))
    print(f"[server] TCP control listening on {', '.join(addr_list)}")
    print(f"[server] UDP audio reflector on v4 {args.udp_host_v4}:{args.audio_port} and v6 [{args.udp_host_v6}]:{args.audio_port}")
    print(f"[server] UDP video reflector on v4 {args.udp_host_v4}:{args.video_port} and v6 [{args.udp_host_v6}]:{args.video_port}")

    async def serve_all():
        async def serve(s):
            async with s:
                await s.serve_forever()
        await asyncio.gather(*(serve(s) for s in servers))

    # Periodic stats (optional)
    task = None
    if args.periodic_stats:
        async def stats_task():
            while True:
                await asyncio.sleep(args.stats_interval)
                out = generate_summary(aggregator, time.time_ns(), idle_ttl_s=args.idle_ttl, silent_when_idle=args.silent_when_idle)
                if out:
                    print(out)
                    # Also emit JSON line if requested
                    try:
                        if args.json or args.json_file:
                            summary_obj = generate_summary_json(
                                aggregator,
                                time.time_ns(),
                                idle_ttl_s=args.idle_ttl,
                                silent_when_idle=True,
                            )
                            if summary_obj:
                                emit_json({"event": "periodic_stats", "summary": summary_obj, "ts_ns": time.time_ns()}, args)
                    except Exception:
                        pass
        task = asyncio.create_task(stats_task())

    try:
        await serve_all()
    finally:
        if task is not None:
            task.cancel()
        for t in a_transports + v_transports:
            try:
                t.close()
            except Exception:
                pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

# ===== Metrics Aggregator =====
MAGIC = b"MTP1"


def percentile(data, p):
    if not data:
        return None
    if p <= 0:
        return float(min(data))
    if p >= 100:
        return float(max(data))
    s = sorted(data)
    k = (len(s) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(s[int(k)])
    d0 = s[int(f)] * (c - k)
    d1 = s[int(c)] * (k - f)
    return float(d0 + d1)


class FlowStats:
    __slots__ = (
        "mode",
        "packets",
        "bytes",
        "first_ns",
        "last_ns",
        "last_arrival_ns",
        "ipa_ms",
        "last_transit_ms",
        "jitter_samples_ms",
        "rfc_jitter_ms",
        "seq_expected",
        "lost",
        "reordered",
        "last_seq"
    )

    def __init__(self, mode):
        self.mode = mode
        self.packets = 0
        self.bytes = 0
        self.first_ns = 0
        self.last_ns = 0
        self.last_arrival_ns = None
        self.ipa_ms = deque(maxlen=5000)
        self.last_transit_ms = None
        self.jitter_samples_ms = deque(maxlen=5000)
        self.rfc_jitter_ms = 0.0
        self.seq_expected = None
        self.lost = 0
        self.reordered = 0
        self.last_seq = None

    def on_packet(self, seq, send_ns, recv_ns, length):
        self.packets += 1
        self.bytes += length
        if self.first_ns == 0:
            self.first_ns = recv_ns
        self.last_ns = recv_ns

        # IPA
        if self.last_arrival_ns is not None:
            self.ipa_ms.append(max(0.0, (recv_ns - self.last_arrival_ns) / 1e6))
        self.last_arrival_ns = recv_ns

        # Transit time using client send timestamp (ms)
        transit_ms = (recv_ns - send_ns) / 1e6
        if self.last_transit_ms is not None:
            dt = abs(transit_ms - self.last_transit_ms)
            self.jitter_samples_ms.append(dt)
            # RFC3550 jitter estimator (ms)
            self.rfc_jitter_ms += (dt - self.rfc_jitter_ms) / 16.0
        self.last_transit_ms = transit_ms

        # Loss / reordering (seq tracking)
        if self.seq_expected is None:
            self.seq_expected = seq + 1
            self.last_seq = seq
        else:
            if seq == self.seq_expected:
                self.seq_expected += 1
            elif seq > self.seq_expected:
                self.lost += (seq - self.seq_expected)
                self.seq_expected = seq + 1
            else:  # seq < expected
                self.reordered += 1
            self.last_seq = seq


class Aggregator:
    def __init__(self):
        self.flows = {}  # key -> FlowStats

    def _parse(self, data):
        # Expect MAGIC + ver(1)+mode(1)+seq(8)+send_ns(8)
        if len(data) < 22 or data[:4] != MAGIC:
            return None
        ver = data[4]
        mode = data[5]
        try:
            # big endian
            seq = int.from_bytes(data[6:14], "big")
            send_ns = int.from_bytes(data[14:22], "big")
        except Exception:
            return None
        return ver, mode, seq, send_ns

    def on_packet(self, udp_name, data, addr):
        parsed = self._parse(data)
        now_ns = time.time_ns()
        if not parsed:
            return
        ver, mode, seq, send_ns = parsed
        # Normalize addr key (host, port)
        if isinstance(addr, tuple) and len(addr) >= 2:
            host = addr[0]
            port = addr[1]
        else:
            host = str(addr)
            port = 0
        key = (host, port, mode)
        fs = self.flows.get(key)
        if fs is None:
            fs = FlowStats(mode)
            self.flows[key] = fs
        fs.on_packet(seq, send_ns, now_ns, len(data))

    def render_summary(self, now_ns, idle_ttl_s=10.0, silent_when_idle=False):
        # Determine active flows within TTL and prune very stale ones
        ttl_ns = int(idle_ttl_s * 1e9)
        active = []
        prune = []
        for k, fs in self.flows.items():
            if fs.last_ns and (now_ns - fs.last_ns) <= ttl_ns:
                active.append((k, fs))
            elif fs.last_ns and (now_ns - fs.last_ns) > 10 * ttl_ns:
                prune.append(k)
        for k in prune:
            self.flows.pop(k, None)

        if not active:
            if silent_when_idle:
                return ""
            return "[server] idle (no active flows)"

        lines = []
        lines.append("=== Server Media Stats ===")
        if self.header_lines:
            lines.extend(self.header_lines)
        lines.append(f"Active flows: {len(active)} (TTL {idle_ttl_s:.0f}s)")
        # Show up to 8 busiest active flows by bytes
        flows_sorted = sorted(active, key=lambda kv: kv[1].bytes, reverse=True)[:8]
        for (host, port, mode), fs in flows_sorted:
            elapsed = max(1e-9, (fs.last_ns - fs.first_ns) / 1e9) if fs.first_ns and fs.last_ns else 0.0
            kbps_in = (fs.bytes * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
            ipa_p50 = percentile(list(fs.ipa_ms), 50)
            ipa_p95 = percentile(list(fs.ipa_ms), 95)
            ipa_p99 = percentile(list(fs.ipa_ms), 99)
            jit_p50 = percentile(list(fs.jitter_samples_ms), 50)
            jit_p95 = percentile(list(fs.jitter_samples_ms), 95)
            jit_p99 = percentile(list(fs.jitter_samples_ms), 99)
            total_seen = fs.packets + fs.lost
            loss_pct = (fs.lost / total_seen * 100.0) if total_seen > 0 else 0.0
            # Burst loss and reorder depth
            burst_p50 = percentile(list(fs.loss_bursts), 50)
            burst_p95 = percentile(list(fs.loss_bursts), 95)
            burst_max = max(fs.loss_bursts) if fs.loss_bursts else None
            rord_p50 = percentile(list(fs.reorder_depths), 50)
            rord_p95 = percentile(list(fs.reorder_depths), 95)
            rord_max = max(fs.reorder_depths) if fs.reorder_depths else None
            # PPS stability
            pps_p50 = percentile(list(fs.pps_series), 50)
            pps_p95 = percentile(list(fs.pps_series), 95)
            pps_p99 = percentile(list(fs.pps_series), 99)
            pps_std = stddev(list(fs.pps_series))
            lines.append(f"- Flow: {host}:{port} mode={mode}")
            lines.append(
                f"  - Packets: {fs.packets}"
            )
            # Align with client ordering
            lines.append("  - Latency (ms): P50/P95/P99 = n/a/n/a/n/a")
            lines.append("  - RTT (ms):     P50/P95/P99 = n/a/n/a/n/a")
            lines.append(
                f"  - Jitter (ms):  P50/P95/P99 = {fmt(jit_p50)}/{fmt(jit_p95)}/{fmt(jit_p99)}, RFC3550={fs.rfc_jitter_ms:.2f}"
            )
            lines.append(
                f"  - IPA (ms):     P50/P95/P99 = {fmt(ipa_p50)}/{fmt(ipa_p95)}/{fmt(ipa_p99)}"
            )
            lines.append(f"  - Throughput (kbps): in={kbps_in:.1f} out={kbps_out:.1f}")
            # Loss burst and reorder depth are not meaningful on a reflector; omit
            lines.append(
                f"  - PPS:          P50/P95/P99/std = {fmt(pps_p50)}/{fmt(pps_p95)}/{fmt(pps_p99)}/{fmt(pps_std)}"
            )
            lines.append(f"  - Duplicates: {fs.duplicates}")

        # Aggregate across active flows
        total_pkts = 0
        total_lost = 0
        total_reordered = 0
        total_duplicates = 0
        total_bytes = 0
        total_bytes_out = 0
        g_first = None
        g_last = None
        all_ipa = []
        all_jit = []
        all_bursts = []
        all_rdepths = []
        all_pps = []
        for _, fs in active:
            total_pkts += fs.packets
            total_lost += fs.lost
            total_reordered += fs.reordered
            total_duplicates += fs.duplicates
            total_bytes += fs.bytes
            total_bytes_out += getattr(fs, 'bytes_out', 0)
            if fs.first_ns:
                g_first = fs.first_ns if g_first is None else min(g_first, fs.first_ns)
            if fs.last_ns:
                g_last = fs.last_ns if g_last is None else max(g_last, fs.last_ns)
            all_ipa.extend(list(fs.ipa_ms))
            all_jit.extend(list(fs.jitter_samples_ms))
            all_bursts.extend(list(fs.loss_bursts))
            all_rdepths.extend(list(fs.reorder_depths))
            all_pps.extend(list(fs.pps_series))

        elapsed = max(1e-9, (g_last - g_first) / 1e9) if g_first and g_last else 0.0
        in_kbps = (total_bytes * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
        out_kbps = (total_bytes_out * 8) / 1000.0 / elapsed if elapsed > 0 else 0.0
        agg_loss_pct = (total_lost / (total_pkts + total_lost) * 100.0) if (total_pkts + total_lost) > 0 else 0.0
        agg_ipa = (percentile(all_ipa, 50), percentile(all_ipa, 95), percentile(all_ipa, 99))
        agg_jit = (percentile(all_jit, 50), percentile(all_jit, 95), percentile(all_jit, 99))
        agg_burst = (percentile(all_bursts, 50), percentile(all_bursts, 95), max(all_bursts) if all_bursts else None)
        agg_rdepth = (percentile(all_rdepths, 50), percentile(all_rdepths, 95), max(all_rdepths) if all_rdepths else None)
        agg_pps = (percentile(all_pps, 50), percentile(all_pps, 95), percentile(all_pps, 99), stddev(all_pps))

        # If only one active flow, aggregate equals that flow; suppress duplicate
        if len(active) == 1:
            return "\n".join(lines)

        lines.append("Aggregate:")
        lines.append(
            f"  - Packets: {total_pkts}"
        )
        lines.append("  - Latency (ms): P50/P95/P99 = n/a/n/a/n/a")
        lines.append("  - RTT (ms):     P50/P95/P99 = n/a/n/a/n/a")
        lines.append(
            f"  - Jitter (ms):  P50/P95/P99 = {fmt(agg_jit[0])}/{fmt(agg_jit[1])}/{fmt(agg_jit[2])}"
        )
        lines.append(
            f"  - IPA (ms):     P50/P95/P99 = {fmt(agg_ipa[0])}/{fmt(agg_ipa[1])}/{fmt(agg_ipa[2])}"
        )
        lines.append(f"  - Throughput (kbps): in={in_kbps:.1f} out={out_kbps:.1f}")
        # Omit aggregate loss burst and reorder depth on reflector
        lines.append(
            f"  - PPS:          P50/P95/P99/std = {fmt(agg_pps[0])}/{fmt(agg_pps[1])}/{fmt(agg_pps[2])}/{fmt(agg_pps[3])}"
        )
        lines.append(f"  - Duplicates: {total_duplicates}")
        return "\n".join(lines)


def fmt(v):
    return "n/a" if v is None else f"{v:.2f}"
