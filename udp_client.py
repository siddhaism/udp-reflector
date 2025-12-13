#!/usr/bin/env python3
import socket, time, struct, statistics

# ================= CONFIG =================
SERVER_IP   = "143.244.185.11"
SERVER_PORT = 5005

PACKET_SIZE = 200
SEND_INTERVAL = 0.020           # 20 ms (audio cadence)
RUN_DURATION  = 120             # seconds
HOLE_PUNCH_PACKETS = 10
STARVATION_THRESHOLD = 0.100    # 100 ms
# =========================================

"""
TWAMP-style header carried in both directions:
    seq:   uint32 (network byte order)
    T1:    double (client send time)
    T2:    double (server receive time)
    T3:    double (server send time)

On client -> server, only seq and T1 are meaningful; T2/T3 are set to 0.0.
On server -> client, all fields are filled: seq, original T1, server's T2 and T3.
Client measures T4 on receipt.
"""
HEADER_FORMAT = "!Iddd"           # seq, T1, T2, T3
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)

# ---------- Freeze-aware MOS helpers ----------
def starvation_penalty(starvations, audio=True):
    """
    audio=True  -> harsher penalties
    audio=False -> video (more tolerant)
    """
    penalty = 0.0
    for s in starvations:
        ms = s * 1000
        if ms > 2000:
            penalty += 2.5 if audio else 1.5
        elif ms > 1000:
            penalty += 2.0 if audio else 1.0
        elif ms > 300:
            penalty += 0.8 if audio else 0.4
        else:
            penalty += 0.2 if audio else 0.1
    return penalty

def base_mos(latency_ms, loss_pct):
    # Simplified E-model core
    R = (
        94.2
        - 0.024 * latency_ms
        - 0.11 * max(latency_ms - 177.0, 0)
        - 2.5 * loss_pct
    )
    mos = 1 + 0.035 * R + 7e-6 * R * (R - 60) * (100 - R)
    return max(1.0, min(4.5, mos))

def freeze_aware_mos(latency_ms, loss_pct, starvations, audio=True):
    mos = base_mos(latency_ms, loss_pct)
    mos -= starvation_penalty(starvations, audio)

    max_freeze = max([s*1000 for s in starvations], default=0)
    # Hard caps (this fixes your earlier paradox)
    if max_freeze > 2000:
        mos = min(mos, 2.5 if audio else 3.0)
    elif max_freeze > 1000:
        mos = min(mos, 3.2 if audio else 3.6)
    elif max_freeze > 300:
        mos = min(mos, 3.8 if audio else 4.0)

    return max(1.0, min(4.5, mos))

def call_usability_score(audio_mos, video_mos, starvations):
    worst_freeze = max([s*1000 for s in starvations], default=0)

    if worst_freeze > 2000:
        return 1
    if audio_mos < 2.8:
        return 2
    if audio_mos < 3.4:
        return 3
    if audio_mos < 4.0:
        return 4
    return 5
# -------------------------------------------

family = socket.AF_INET6 if ":" in SERVER_IP else socket.AF_INET
sock = socket.socket(family, socket.SOCK_DGRAM)
sock.connect((SERVER_IP, SERVER_PORT))
sock.settimeout(2.0)

print(f"Client connected to server {SERVER_IP}:{SERVER_PORT}")
print("Performing NAT hole punching...")

# ---------- NAT hole punch ----------
for _ in range(HOLE_PUNCH_PACKETS):
    now = time.time()
    # During hole punching, send T1; T2/T3 are zero placeholders
    pkt = struct.pack(HEADER_FORMAT, 0, now, 0.0, 0.0)
    pkt = pkt.ljust(PACKET_SIZE, b"x")
    sock.send(pkt)
    time.sleep(0.05)

print("Hole punching complete. Starting measurement...\n")

# ---------- Stats ----------
packets_sent = 0
packets_received = 0
sequence_gaps = 0

arrivals = []
ipas = []
jitters = []
starvations = []
rtts = []

# Directional metrics (using T1..T4)
uplink_owd = []       # T2 - T1 (client->server)
downlink_owd = []     # T4 - T3 (server->client)

# To reconstruct upstream IPAs (server clock) locally via consecutive T2s
last_srv_t2 = None
uplink_ipas = []
uplink_starvations = []

# NTP-style clock offset estimates per packet (assumes path symmetry)
clock_offsets = []     # theta = ((T2 - T1) + (T3 - T4)) / 2
uplink_owd_adj = []    # (T2 - T1) - theta
downlink_owd_adj = []  # (T4 - T3) + theta

send_times = {}
last_seq = None

seq = 1
start = time.time()

# ---------- Main loop ----------
while time.time() - start < RUN_DURATION:
    send_ts = time.time()  # T1
    # Send probe: seq, T1, T2=0.0, T3=0.0
    pkt = struct.pack(HEADER_FORMAT, seq, send_ts, 0.0, 0.0)
    pkt = pkt.ljust(PACKET_SIZE, b"x")
    sock.send(pkt)

    send_times[seq] = send_ts
    packets_sent += 1
    seq += 1

    try:
        data = sock.recv(1500)
        recv_ts = time.time()  # T4

        if len(data) >= HEADER_SIZE:
            rseq, t1, t2, t3 = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
            packets_received += 1

            if last_seq is not None and rseq != last_seq + 1:
                sequence_gaps += abs(rseq - last_seq - 1)
            last_seq = rseq

            # TWAMP-style RTT excluding server residence time: (T4 - T1) - (T3 - T2)
            if rseq in send_times:
                # Keep map consistent; we still pop tracked sends
                send_times.pop(rseq, None)
            rtts.append((recv_ts - t1) - (t3 - t2))

            # Directional one-way delays (raw, include clock offset)
            uplink_owd.append(t2 - t1)
            downlink_owd.append(recv_ts - t3)

            # NTP offset estimate (theta) and de-skewed OWDs assuming path symmetry
            theta = ((t2 - t1) + (t3 - recv_ts)) / 2.0
            clock_offsets.append(theta)
            uplink_owd_adj.append((t2 - t1) - theta)
            downlink_owd_adj.append((recv_ts - t3) + theta)

            # Reconstruct uplink IPAs using server receive timestamps (T2) to see server-side starvations locally
            if last_srv_t2 is not None:
                srv_ipa = t2 - last_srv_t2
                uplink_ipas.append(srv_ipa)
                if srv_ipa > STARVATION_THRESHOLD:
                    uplink_starvations.append(srv_ipa)
            last_srv_t2 = t2

            arrivals.append(recv_ts)
            if len(arrivals) >= 2:
                ipa = arrivals[-1] - arrivals[-2]
                ipas.append(ipa)
                if ipa > STARVATION_THRESHOLD:
                    starvations.append(ipa)

            if len(ipas) >= 2:
                jitters.append(abs(ipas[-1] - ipas[-2]))

    except socket.timeout:
        pass

    time.sleep(SEND_INTERVAL)

# ---------- Final metrics ----------
true_loss = max(0, packets_sent - packets_received)
loss_pct = (true_loss / packets_sent) * 100 if packets_sent else 0.0

latencies = [rtt / 2 for rtt in rtts]
uplink_jitters = [abs(uplink_owd[i] - uplink_owd[i-1]) for i in range(1, len(uplink_owd))]
downlink_jitters = [abs(downlink_owd[i] - downlink_owd[i-1]) for i in range(1, len(downlink_owd))]
avg_uplink_ms = statistics.mean(uplink_owd) * 1000 if uplink_owd else 0.0
avg_downlink_ms = statistics.mean(downlink_owd) * 1000 if downlink_owd else 0.0
avg_theta_ms = statistics.median(clock_offsets) * 1000 if clock_offsets else 0.0
uplink_jitters_adj = [abs(uplink_owd_adj[i] - uplink_owd_adj[i-1]) for i in range(1, len(uplink_owd_adj))]
downlink_jitters_adj = [abs(downlink_owd_adj[i] - downlink_owd_adj[i-1]) for i in range(1, len(downlink_owd_adj))]
avg_latency_ms = statistics.mean(latencies) * 1000 if latencies else 0.0

audio_mos = freeze_aware_mos(avg_latency_ms, loss_pct, starvations, audio=True)
video_mos = freeze_aware_mos(avg_latency_ms, loss_pct, starvations, audio=False)
cus = call_usability_score(audio_mos, video_mos, starvations)

# ---------- Output ----------
def fmt(name, values):
    if not values:
        return f"{name}: No data"
    return (
        f"{name} (mean/median/max): "
        f"{statistics.mean(values)*1000:.2f} ms / "
        f"{statistics.median(values)*1000:.2f} ms / "
        f"{max(values)*1000:.2f} ms"
    )

print("\n=== CLIENT STATS ===")
print(f"Server: {SERVER_IP}:{SERVER_PORT}")
print(f"Packets sent:              {packets_sent}")
print(f"Packets received:          {packets_received}")
print(f"True packet loss:          {true_loss} ({loss_pct:.2f}%)")
print(f"Sequence gaps detected:    {sequence_gaps}")

print(fmt("IPA", ipas))
print(fmt("Jitter", jitters))
print(fmt("RTT", rtts))
print(fmt("Latency (RTT/2)", latencies))

print("\n--- Directional (TWAMP-style) ---")
print(fmt("Uplink OWD (T2-T1)", uplink_owd))
print(fmt("Downlink OWD (T4-T3)", downlink_owd))
print(fmt("Uplink Jitter", uplink_jitters))
print(fmt("Downlink Jitter", downlink_jitters))
print(f"Avg uplink latency:        {avg_uplink_ms:.2f} ms")
print(f"Avg downlink latency:      {avg_downlink_ms:.2f} ms")

print("\n--- Directional (deskewed, NTP symmetric assumption) ---")
print(f"Estimated clock offset (median): {avg_theta_ms:.2f} ms (server - client)")
print(fmt("Uplink OWD adj", uplink_owd_adj))
print(fmt("Downlink OWD adj", downlink_owd_adj))
print(fmt("Uplink Jitter adj", uplink_jitters_adj))
print(fmt("Downlink Jitter adj", downlink_jitters_adj))

print(f"Starvation windows (>100 ms): {len(starvations)}")
if starvations:
    print(f"Max starvation: {max(starvations)*1000:.2f} ms")

print(f"Uplink starvations (>100 ms): {len(uplink_starvations)}")
if uplink_starvations:
    print(f"Max uplink starvation: {max(uplink_starvations)*1000:.2f} ms")

print(f"\nAudio MOS (freeze-aware):  {audio_mos:.2f} / 5.0")
print(f"Video MOS (freeze-aware):  {video_mos:.2f} / 5.0")
print(f"Call Usability Score:      {cus} / 5")

print("\nMeasurement complete.")
