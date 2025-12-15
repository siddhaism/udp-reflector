#!/usr/bin/env python3
import argparse
import asyncio
import json
import math
import os
import platform
import socket
import struct
import subprocess
from typing import Optional
import time
from statistics import mean


MAGIC = b"MTP1"
VERSION = 1
MODE_AUDIO = 1
MODE_VIDEO = 2


def now_ns():
    return time.time_ns()


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


def fmt_opt(v, unit=""):
    return "n/a" if v is None else (f"{v:.2f}{unit}" if unit else f"{v:.2f}")


class Metrics:
    def __init__(self):
        self.sent = 0
        self.recv = 0
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.rtts_ms = []
        self.one_way_ms = []
        self.jitter_ms = []
        self.ipa_ms = []
        self.pps_series = []
        self.arrival_ms_series = []
        self._last_one_way_ms = None
        self._last_arrival_ms = None
        # Loss/reorder/duplicate tracking
        self.seq_expected = None
        self.lost = 0
        self.reordered = 0
        self.loss_bursts = []
        self.reorder_depths = []
        self.duplicates = 0
        self._seen_seq = set()
        self._seen_order = []  # FIFO for bounded memory
        # Starvation tracking (large gaps or loss bursts)
        self.starvation_events = []  # list of (timestamp_ms, reason, value)

    def on_send(self, payload_len):
        self.sent += 1
        self.bytes_sent += payload_len

    def on_recv(self, seq, rtt_ms, arrival_ms, starvation_gap_ms=None):
        # Duplicate detection: ignore duplicates for latency/jitter stats
        if seq in self._seen_seq:
            self.duplicates += 1
            return
        self._seen_seq.add(seq)
        self._seen_order.append(seq)
        if len(self._seen_order) > 65536:
            old = self._seen_order.pop(0)
            self._seen_seq.discard(old)

        self.recv += 1
        self.bytes_recv += 0  # accounted via datagram length externally if desired
        self.rtts_ms.append(rtt_ms)
        ow = rtt_ms / 2.0
        self.one_way_ms.append(ow)
        if self._last_one_way_ms is not None:
            self.jitter_ms.append(abs(ow - self._last_one_way_ms))
        self._last_one_way_ms = ow

        # Track arrival time for windowed PPS
        self.arrival_ms_series.append(arrival_ms)

        if self._last_arrival_ms is not None:
            ipa = max(0.0, arrival_ms - self._last_arrival_ms)
            self.ipa_ms.append(ipa)
            if ipa > 0:
                self.pps_series.append(1000.0 / ipa)
            # Starvation detection via IPA threshold
            if starvation_gap_ms is not None and ipa >= starvation_gap_ms:
                self.starvation_events.append((arrival_ms, "gap_ms", ipa))
        self._last_arrival_ms = arrival_ms

        # Loss/reorder using expected sequence
        if self.seq_expected is None:
            self.seq_expected = seq + 1
        else:
            if seq == self.seq_expected:
                self.seq_expected += 1
            elif seq > self.seq_expected:
                gap = seq - self.seq_expected
                self.lost += gap
                self.loss_bursts.append(gap)
                # Record starvation due to loss burst (timestamp = arrival time if available)
                ts = self._last_arrival_ms if self._last_arrival_ms is not None else (time.time_ns() / 1e6)
                self.starvation_events.append((ts, "loss_burst", float(gap)))
                self.seq_expected = seq + 1
            else:  # seq < expected
                self.reordered += 1
                depth = self.seq_expected - seq
                if depth > 0:
                    self.reorder_depths.append(depth)

    def summarize(self, duration_s, recv_bytes_actual=None):
        # Throughput kbps
        kbps_send = (self.bytes_sent * 8) / duration_s / 1000.0 if duration_s > 0 else 0.0
        rb = recv_bytes_actual if recv_bytes_actual is not None else self.bytes_recv
        kbps_recv = (rb * 8) / duration_s / 1000.0 if duration_s > 0 else 0.0

        lat_p50 = percentile(self.one_way_ms, 50)
        lat_p95 = percentile(self.one_way_ms, 95)
        lat_p99 = percentile(self.one_way_ms, 99)

        rtt_p50 = percentile(self.rtts_ms, 50)
        rtt_p95 = percentile(self.rtts_ms, 95)
        rtt_p99 = percentile(self.rtts_ms, 99)

        jit_p50 = percentile(self.jitter_ms, 50)
        jit_p95 = percentile(self.jitter_ms, 95)
        jit_p99 = percentile(self.jitter_ms, 99)

        ipa_p50 = percentile(self.ipa_ms, 50)
        ipa_p95 = percentile(self.ipa_ms, 95)
        ipa_p99 = percentile(self.ipa_ms, 99)

        loss = max(0, self.sent - self.recv)
        loss_pct = (loss / self.sent * 100.0) if self.sent > 0 else 0.0
        avg_one_way = mean(self.one_way_ms) if self.one_way_ms else None

        # Client-side loss bursts and reorder depth
        burst_p50 = percentile(self.loss_bursts, 50)
        burst_p95 = percentile(self.loss_bursts, 95)
        burst_max = max(self.loss_bursts) if self.loss_bursts else None
        rord_p50 = percentile(self.reorder_depths, 50)
        rord_p95 = percentile(self.reorder_depths, 95)
        rord_max = max(self.reorder_depths) if self.reorder_depths else None

        # PPS stability from IPA
        def stddev(xs):
            if not xs:
                return None
            m = sum(xs) / len(xs)
            return (sum((x - m) ** 2 for x in xs) / len(xs)) ** 0.5
        pps_p50 = percentile(self.pps_series, 50)
        pps_p95 = percentile(self.pps_series, 95)
        pps_p99 = percentile(self.pps_series, 99)
        pps_std = stddev(self.pps_series)

        # Smoothed PPS over 1s sliding window using arrival timestamps
        smooth_rates = []
        ts = self.arrival_ms_series
        j = 0
        for i in range(len(ts)):
            t = ts[i]
            win_start = t - 1000.0
            while j < i and ts[j] < win_start:
                j += 1
            count = (i - j + 1)
            if count > 0:
                smooth_rates.append(float(count))  # per 1s window
        sp50 = percentile(smooth_rates, 50)
        sp95 = percentile(smooth_rates, 95)
        sp99 = percentile(smooth_rates, 99)
        spstd = (lambda xs: None if not xs else ((sum((x - (sum(xs)/len(xs)))**2 for x in xs)/len(xs))**0.5))(smooth_rates)

        # Audio MOS using simplified E-model approximation (G.711-like, Ie=0, Bpl=10)
        audio_mos = None
        if avg_one_way is not None:
            d = avg_one_way  # ms
            # Delay impairment Id per ITU-T G.107 (simplified)
            Id = 0.024 * d + 0.11 * max(0.0, d - 177.3)
            Ppl = loss_pct  # % packet loss
            Ie = 0.0
            Bpl = 10.0
            Ie_eff = Ie + (95.0 - Ie) * (Ppl / (Ppl + Bpl)) if (Ppl + Bpl) > 0 else Ie
            R = 94.2 - Id - Ie_eff
            R = max(0.0, min(100.0, R))
            audio_mos = 1.0 + 0.035 * R + R * (R - 60.0) * (100.0 - R) * 7.0e-6
            audio_mos = max(1.0, min(4.5, audio_mos))

        # Video MOS heuristic based on throughput ratio and delay/jitter headroom
        video_mos = None
        if avg_one_way is not None:
            ratio = kbps_recv / kbps_send if kbps_send > 0 else 0.0
            ratio = max(0.0, min(1.0, ratio))
            d95 = lat_p95 or avg_one_way
            j95 = jit_p95 or 0.0
            delay_factor = 1.0 / (1.0 + max(0.0, (d95 - 150.0)) / 150.0)
            jitter_factor = 1.0 / (1.0 + max(0.0, (j95 - 30.0)) / 30.0)
            video_mos = 1.0 + 4.0 * ratio * delay_factor * jitter_factor
            video_mos = max(1.0, min(4.5, video_mos))

        # Call usability: average of normalized audio/video MOS
        call_usability = None
        if audio_mos is not None and video_mos is not None:
            def norm(m):
                return max(0.0, min(1.0, (m - 1.0) / (4.5 - 1.0)))
            call_usability = 100.0 * (norm(audio_mos) + norm(video_mos)) / 2.0

        return {
            "latency_ms": (lat_p50, lat_p95, lat_p99),
            "rtt_ms": (rtt_p50, rtt_p95, rtt_p99),
            "jitter_ms": (jit_p50, jit_p95, jit_p99),
            "ipa_ms": (ipa_p50, ipa_p95, ipa_p99),
            "throughput_kbps": (kbps_send, kbps_recv),
            "sent": self.sent,
            "recv": self.recv,
            "loss_pct": loss_pct,
            "dup_count": self.duplicates,
            "burst_loss": (burst_p50, burst_p95, burst_max),
            "reorder_depth": (rord_p50, rord_p95, rord_max),
            "pps_inst": (pps_p50, pps_p95, pps_p99, pps_std),
            "pps_smooth_1s": (sp50, sp95, sp99, spstd),
            "audio_mos": audio_mos,
            "video_mos": video_mos,
            "call_usability": call_usability,
        }


async def tcp_exchange(server_host, tcp_port, mode, client_udp_port):
    ctrl_metrics = {
        "conn_start_ns": time.time_ns(),
        "conn_end_ns": None,
        "hello_sent_ns": None,
        "resp_recv_ns": None,
        "bytes_out": 0,
        "bytes_in": 0,
    }
    reader, writer = await asyncio.open_connection(server_host, tcp_port)
    ctrl_metrics["conn_end_ns"] = time.time_ns()
    hello = {"mode": mode, "client_udp_port": client_udp_port}
    hello_line = (json.dumps(hello) + "\n").encode("utf-8")
    writer.write(hello_line)
    ctrl_metrics["hello_sent_ns"] = time.time_ns()
    ctrl_metrics["bytes_out"] += len(hello_line)
    await writer.drain()
    line = await reader.readline()
    if not line:
        raise RuntimeError("No response from server control channel")
    ctrl_metrics["resp_recv_ns"] = time.time_ns()
    ctrl_metrics["bytes_in"] += len(line)
    resp = json.loads(line.decode("utf-8", errors="ignore"))
    if not resp.get("ok"):
        raise RuntimeError("Server responded with error")
    # Keep control channel open; caller will close when test completes
    return resp, reader, writer, ctrl_metrics


def build_packet(mode_flag, seq, payload_size):
    # Header: MAGIC(4) + VER(1) + MODE(1) + SEQ(8) + SEND_NS(8) = 22 bytes
    header_len = 22
    if payload_size < header_len:
        raise ValueError(f"packet_size must be >= {header_len}")
    send_ns = now_ns()
    header = MAGIC + struct.pack(
        ">BBQQ", VERSION, mode_flag, seq, send_ns
    )
    pad_len = payload_size - header_len
    if pad_len:
        header += b"\x00" * pad_len
    return header, send_ns


def parse_packet(data):
    if len(data) < 22 or data[:4] != MAGIC:
        return None
    try:
        ver, mode_flag, seq, send_ns = struct.unpack(
            ">BBQQ", data[4:4 + 1 + 1 + 8 + 8]
        )
        return {
            "version": ver,
            "mode": mode_flag,
            "seq": seq,
            "send_ns": send_ns,
            "len": len(data),
        }
    except struct.error:
        return None


async def run_client(args):
    mode_flag = MODE_AUDIO if args.mode == "audio" else MODE_VIDEO

    # Prepare UDP socket after resolving server address family
    # TCP exchange uses provided args.server_host
    tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        tmp_sock.bind(("0.0.0.0", args.client_udp_port or 0))
        local_port = tmp_sock.getsockname()[1]
    finally:
        tmp_sock.close()

    ctrl, ctrl_reader, ctrl_writer, ctrl_metrics = await tcp_exchange(args.server_host, args.tcp_port, args.mode, local_port)
    server_udp_port = ctrl["server_udp_port"]
    # Indicate control connection established
    print(f"[client] Connected to control {args.server_host}:{args.tcp_port}; mode={args.mode}, media_udp_port={server_udp_port}")
    print(f"[client] Starting test: duration={int(args.duration)}s, packet_size={args.packet_size}B, rate={args.rate}pps")
    # Prefer explicit server host from args when server returns wildcard
    ch_v4 = ctrl.get("server_host_v4")
    ch_v6 = ctrl.get("server_host_v6")
    preferred_host = args.server_host
    server_udp_host = preferred_host
    # If the user passed a hostname that resolves to both families, resolution will decide
    # Avoid using wildcard control hosts
    if ch_v6 and ch_v6 not in ("::", "0:0:0:0:0:0:0:0"):
        # Keep for information but do not override preferred_host
        pass
    if ch_v4 and ch_v4 != "0.0.0.0":
        pass

    # Resolve server address for UDP
    gai = socket.getaddrinfo(server_udp_host, server_udp_port, proto=socket.IPPROTO_UDP, type=socket.SOCK_DGRAM)
    if not gai:
        raise RuntimeError("DNS resolution failed for server_udp_host")
    af, socktype, proto, canonname, sa = gai[0]
    udp_sock = socket.socket(af, socket.SOCK_DGRAM)
    # For IPv6 client socket, ensure v6only to avoid surprises
    if af == socket.AF_INET6:
        try:
            udp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except OSError:
            pass
        bind_host = "::"
    else:
        bind_host = "0.0.0.0"
    udp_sock.setblocking(False)
    udp_sock.bind((bind_host, args.client_udp_port or 0))
    local_port = udp_sock.getsockname()[1]
    # Connect UDP socket to enable loop.sock_recv (for environments lacking sock_recvfrom)
    try:
        udp_sock.connect(sa)
    except OSError:
        # If connect fails, we'll still try to sendto/recv fallback
        pass

    async def rebind_udp_socket():
        nonlocal udp_sock, local_port
        try:
            try:
                udp_sock.close()
            except Exception:
                pass
            new_sock = socket.socket(af, socket.SOCK_DGRAM)
            if af == socket.AF_INET6:
                try:
                    new_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                except OSError:
                    pass
                bhost = "::"
            else:
                bhost = "0.0.0.0"
            new_sock.setblocking(False)
            # Best-effort: try to reuse previous local port, else 0
            try:
                new_sock.bind((bhost, local_port))
            except Exception:
                new_sock.bind((bhost, 0))
            local_port = new_sock.getsockname()[1]
            try:
                new_sock.connect(sa)
            except OSError:
                pass
            udp_sock = new_sock
            # Notify server (optional) via control channel
            try:
                update = {"path_update": {"client_udp_port": local_port}}
                ctrl_writer.write((json.dumps(update) + "\n").encode("utf-8"))
                await ctrl_writer.drain()
            except Exception:
                pass
            print(f"[client] Rebound UDP socket on transition; local_udp={local_port}")
        except Exception as e:
            print(f"[client] UDP rebind failed: {e}")

    loop = asyncio.get_running_loop()

    # Link state monitoring utilities
    def classify_iface(name: str) -> str:
        n = (name or "").lower()
        # Android/Linux cellular
        if n.startswith("rmnet") or n.startswith("ccmni") or n.startswith("pdp") or n.startswith("wwan"):
            return "cellular"
        # iOS cellular
        if n.startswith("pdp_ip"):
            return "cellular"
        # Wi-Fi common
        if n.startswith("wlan") or n.startswith("wifi") or n.startswith("wl"):
            return "wifi"
        # Apple Wi‑Fi typically en0 on iOS/mac, awdl0 is Wi‑Fi aux
        if n.startswith("en") or n.startswith("awdl"):
            # Heuristic: treat en* as Wi‑Fi on Apple handhelds/laptops
            return "wifi"
        # Wired ethernet
        if n.startswith("eth") or n.startswith("enp") or n.startswith("eno"):
            return "ethernet"
        return "unknown"

    def detect_default_iface_linux() -> Optional[str]:
        try:
            with open("/proc/net/route", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split() if line.strip() else []
                    if len(parts) < 4 or parts[0] == "Iface":
                        continue
                    iface, dest_hex, flags_hex = parts[0], parts[1], parts[3]
                    # Default route Dest=00000000 and flags has RTF_UP (0x1)
                    if dest_hex == "00000000" and (int(flags_hex, 16) & 0x1):
                        return iface
        except Exception:
            return None
        return None

    def detect_default_iface_darwin() -> Optional[str]:
        # Prefer: route -n get default -> interface: en0
        try:
            out = subprocess.run(
                ["/sbin/route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=1.0,
            )
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("interface: "):
                        return line.split(":", 1)[1].strip()
        except Exception:
            pass
        # Fallback: scutil --nwi can list interfaces; pick the first non-loopback
        try:
            out = subprocess.run(
                ["/usr/sbin/scutil", "--nwi"],
                capture_output=True, text=True, timeout=1.0,
            )
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    s = line.strip()
                    if s.startswith("Network interfaces:"):
                        # e.g., Network interfaces: en0
                        rest = s.split(":", 1)[1].strip()
                        if rest:
                            return rest.split()[0]
        except Exception:
            pass
        return None

    def detect_default_iface_windows() -> Optional[str]:
        # Best-effort omitted; return None for now
        return None

    def detect_default_iface() -> Optional[str]:
        sys = platform.system().lower()
        if sys == "linux":
            return detect_default_iface_linux()
        if sys == "darwin":
            return detect_default_iface_darwin()
        if sys == "windows":
            return detect_default_iface_windows()
        return None

    class LinkMonitor:
        def __init__(self, poll_interval_s: float = 1.0):
            self.poll_interval_s = poll_interval_s
            self.current_iface = None
            self.current_type = None
            self.transitions = []  # list of dicts: {t_ms, from, to, iface}

        async def run(self, stop_event: asyncio.Event):
            # Initial sample
            self.current_iface = detect_default_iface()
            self.current_type = classify_iface(self.current_iface or "")
            while not stop_event.is_set():
                await asyncio.sleep(self.poll_interval_s)
                iface = detect_default_iface()
                typ = classify_iface(iface or "")
                if typ != self.current_type:
                    t_ms = time.time_ns() / 1e6
                    self.transitions.append({
                        "t_ms": t_ms,
                        "from": self.current_type,
                        "to": typ,
                        "iface": iface,
                    })
                    self.current_type = typ
                    self.current_iface = iface

    metrics = Metrics()
    send_count = 0
    recv_bytes = 0
    in_flight = {}
    stop_event = asyncio.Event()

    # Configure starvation threshold and link monitor
    expected_interval_ms = 1000.0 / float(args.rate)
    starvation_gap_ms = args.starvation_gap_ms
    if starvation_gap_ms is None:
        starvation_gap_ms = max(200.0, 3.0 * expected_interval_ms)
    link_monitor = LinkMonitor(poll_interval_s=args.link_poll_interval) if not args.disable_link_monitor else None
    link_task = None
    if link_monitor is not None:
        link_task = asyncio.create_task(link_monitor.run(stop_event))

    async def sender():
        nonlocal send_count
        interval = 1.0 / float(args.rate)
        deadline = time.monotonic() + args.duration
        next_t = time.monotonic()
        seq = 0
        while time.monotonic() < deadline:
            pkt, send_ns = build_packet(mode_flag, seq, args.packet_size)
            in_flight[seq] = send_ns
            try:
                # Prefer connected UDP send for broader compatibility
                await loop.sock_sendall(udp_sock, pkt)
            except Exception:
                pass
            send_count += 1
            metrics.on_send(len(pkt))
            seq += 1
            next_t += interval
            # busy-wait friendly sleep
            await asyncio.sleep(max(0.0, next_t - time.monotonic()))
        stop_event.set()

    async def receiver():
        nonlocal recv_bytes
        # Receive until stop + small grace
        grace_until = None
        while True:
            if stop_event.is_set() and grace_until is None:
                grace_until = time.monotonic() + 1.0
            if grace_until is not None and time.monotonic() > grace_until:
                break
            try:
                data = await asyncio.wait_for(loop.sock_recv(udp_sock, 65536), timeout=0.2)
            except asyncio.TimeoutError:
                continue
            except Exception:
                # Socket likely changed/closed during rebind; retry
                await asyncio.sleep(0.01)
                continue
            pkt = parse_packet(data)
            if not pkt:
                continue
            recv_bytes += len(data)
            recv_time_ns = now_ns()
            send_ns = pkt["send_ns"]
            rtt_ms = max(0.0, (recv_time_ns - send_ns) / 1e6)
            metrics.on_recv(pkt["seq"], rtt_ms, arrival_ms=recv_time_ns / 1e6, starvation_gap_ms=starvation_gap_ms)
            # cleanup in_flight for accuracy
            in_flight.pop(pkt["seq"], None)

    async def roamer():
        if link_monitor is None or not args.reestablish_on_transition:
            return
        seen = 0
        while not stop_event.is_set():
            await asyncio.sleep(0.1)
            if len(link_monitor.transitions) != seen:
                seen = len(link_monitor.transitions)
                # small delay to allow routing to settle
                await asyncio.sleep(args.rebind_delay_s)
                await rebind_udp_socket()

    start = time.monotonic()
    wall_start_ms = time.time_ns() / 1e6
    tasks = [sender(), receiver()]
    if link_monitor is not None and args.reestablish_on_transition:
        tasks.append(roamer())
    await asyncio.gather(*tasks)
    elapsed = max(1e-9, time.monotonic() - start)

    summary = metrics.summarize(duration_s=elapsed, recv_bytes_actual=recv_bytes)
    # Close control channel to signal server to print final stats, then print local stats
    try:
        ctrl_writer.close()
        await ctrl_writer.wait_closed()
    except Exception:
        pass
    close_ns = time.time_ns()

    # Print report after control termination
    fam = "IPv6" if af == socket.AF_INET6 else "IPv4"
    target_host = sa[0] if isinstance(sa, tuple) else str(sa)
    lat = summary["latency_ms"]
    rtt = summary["rtt_ms"]
    jit = summary["jitter_ms"]
    ipa = summary["ipa_ms"]
    kbps = summary["throughput_kbps"]

    print("=== Media Transport Report ===")
    print(f"Mode: {args.mode}")
    # Align field order with server for easy comparison
    print(
        f"Connection: mode={args.mode} control_tcp={args.tcp_port} media_udp={server_udp_port} "
        f"family={fam} remote={target_host} local_udp={local_port}"
    )
    print(f"Duration: {elapsed:.2f}s, Packet size: {args.packet_size} bytes, Rate: {args.rate} pps")
    print(f"Sent packets: {summary['sent']}, Recv packets: {summary['recv']}, Loss: {summary['loss_pct']:.2f}%")
    print("Latency (ms): P50/P95/P99 = ", 
          f"{fmt_opt(lat[0])}/{fmt_opt(lat[1])}/{fmt_opt(lat[2])}")
    print("RTT (ms):     P50/P95/P99 = ", 
          f"{fmt_opt(rtt[0])}/{fmt_opt(rtt[1])}/{fmt_opt(rtt[2])}")
    print("Jitter (ms):  P50/P95/P99 = ", 
          f"{fmt_opt(jit[0])}/{fmt_opt(jit[1])}/{fmt_opt(jit[2])}")
    print("IPA (ms):     P50/P95/P99 = ", 
          f"{fmt_opt(ipa[0])}/{fmt_opt(ipa[1])}/{fmt_opt(ipa[2])}")
    # Show PPS metrics immediately after IPA for easier comparison
    pps_inst = summary.get("pps_inst")
    if pps_inst:
        print("Instantaneous PPS (from IPA): P50/P95/P99/std = ", f"{fmt_opt(pps_inst[0])}/{fmt_opt(pps_inst[1])}/{fmt_opt(pps_inst[2])}/{fmt_opt(pps_inst[3])}")
    pps_sm = summary.get("pps_smooth_1s")
    if pps_sm:
        print("Smoothed PPS (1s window):     P50/P95/P99/std = ", f"{fmt_opt(pps_sm[0])}/{fmt_opt(pps_sm[1])}/{fmt_opt(pps_sm[2])}/{fmt_opt(pps_sm[3])}")
    print(f"Throughput (kbps): send/recv = {kbps[0]:.2f}/{kbps[1]:.2f}")
    bl = summary["burst_loss"]
    rd = summary["reorder_depth"]
    print("Loss burst:  P50/P95/max = ", f"{fmt_opt(bl[0])}/{fmt_opt(bl[1])}/{fmt_opt(bl[2])}")
    print("Reorder depth: P50/P95/max = ", f"{fmt_opt(rd[0])}/{fmt_opt(rd[1])}/{fmt_opt(rd[2])}")
    print(f"Duplicates: {summary['dup_count']}")
    print(f"Audio MOS: {fmt_opt(summary['audio_mos'])}")
    print(f"Video MOS: {fmt_opt(summary['video_mos'])}")
    if summary["call_usability"] is not None:
        print(f"Call usability score: {summary['call_usability']:.1f}")
    else:
        print("Call usability score: n/a")

    # Link transitions and starvation correlation
    if link_monitor is not None:
        print("=== Link Transitions ===")
        if link_monitor.transitions:
            for ev in link_monitor.transitions:
                t_rel = (ev["t_ms"] - wall_start_ms) / 1000.0
                print(f"  - t={t_rel:+.2f}s: {ev['from']} -> {ev['to']} (iface={ev['iface']})")
        else:
            print("  - none detected")

    # Starvation summary
    if metrics.starvation_events:
        gap_count = sum(1 for t, r, v in metrics.starvation_events if r == "gap_ms")
        lb_count = sum(1 for t, r, v in metrics.starvation_events if r == "loss_burst")
        print("=== Starvation Events ===")
        print(f"  - total={len(metrics.starvation_events)} gap_ms={gap_count} loss_burst={lb_count}")
        print(f"  - gap threshold: {starvation_gap_ms:.1f} ms")
    else:
        print("=== Starvation Events ===")
        print("  - none detected")

    # Correlate starvation events with link transitions within window
    if link_monitor is not None and metrics.starvation_events:
        window_ms = args.corr_window_ms
        trans_ts = [ev["t_ms"] for ev in link_monitor.transitions]
        correlated = 0
        for ts, reason, value in metrics.starvation_events:
            if any(abs(ts - tt) <= window_ms for tt in trans_ts):
                correlated += 1
        print("=== Correlation ===")
        print(f"  - window: ±{window_ms} ms around transition")
        print(f"  - starvation near transitions: {correlated}/{len(metrics.starvation_events)}")

    # Control (TCP) stats aligned with server order
    hs_rtt_ms = None
    if ctrl_metrics.get("hello_sent_ns") and ctrl_metrics.get("resp_recv_ns"):
        hs_rtt_ms = max(0.0, (ctrl_metrics["resp_recv_ns"] - ctrl_metrics["hello_sent_ns"]) / 1e6)
    open_dur_s = None
    if ctrl_metrics.get("conn_start_ns"):
        end_ns_for_open = close_ns if close_ns else (ctrl_metrics.get("conn_end_ns") or ctrl_metrics["conn_start_ns"])
        open_dur_s = max(0.0, (end_ns_for_open - ctrl_metrics["conn_start_ns"]) / 1e9)

    print("=== Control Stats ===")
    print(f"  - Open duration: {open_dur_s:.2f}s" if open_dur_s is not None else "  - Open duration: n/a")
    print(f"  - Handshake RTT (ms): {fmt_opt(hs_rtt_ms)}")
    print("  - Hello->Resp (ms): n/a")
    print(f"  - Bytes: out={ctrl_metrics['bytes_out']} in={ctrl_metrics['bytes_in']}")


def main():
    ap = argparse.ArgumentParser(description="Media transport client with TCP control + UDP reflection test")
    ap.add_argument("--server-host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    ap.add_argument("--tcp-port", type=int, default=5000, help="TCP control port (default: 5000)")
    ap.add_argument("--mode", choices=["audio", "video"], default="audio", help="Test mode")
    ap.add_argument("--duration", type=float, default=None, help="Test duration seconds (default per mode)")
    ap.add_argument("--packet-size", type=int, default=None, help="Payload size bytes (default per mode)")
    ap.add_argument("--rate", type=float, default=None, help="Packets per second (default per mode)")
    ap.add_argument("--client-udp-port", type=int, default=None, help="Optional fixed client UDP port to bind")
    ap.add_argument("--starvation-gap-ms", type=float, default=None, help="Gap threshold in ms to flag starvation (default: max(200, 3x interval))")
    ap.add_argument("--corr-window-ms", type=float, default=2000.0, help="Correlation window in ms around link transitions (default: 2000)")
    ap.add_argument("--link-poll-interval", type=float, default=1.0, help="Link monitor poll interval seconds (default: 1.0)")
    ap.add_argument("--disable-link-monitor", action="store_true", help="Disable link transition monitoring")
    ap.add_argument("--reestablish-on-transition", action="store_true", help="Recreate UDP socket when link changes and notify server via TCP")
    ap.add_argument("--rebind-delay-s", type=float, default=0.3, help="Delay after transition before UDP rebind (s)")

    args = ap.parse_args()

    # Mode defaults
    if args.mode == "audio":
        duration = 10.0 if args.duration is None else args.duration
        pkt = 160 if args.packet_size is None else args.packet_size
        rate = 50.0 if args.rate is None else args.rate
    else:
        duration = 10.0 if args.duration is None else args.duration
        pkt = 1200 if args.packet_size is None else args.packet_size
        rate = 30.0 if args.rate is None else args.rate

    args.duration = float(duration)
    args.packet_size = int(pkt)
    args.rate = float(rate)

    try:
        asyncio.run(run_client(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
