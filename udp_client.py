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

HEADER_FORMAT = "!Id"           # seq, send_ts
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
    pkt = struct.pack(HEADER_FORMAT, 0, now)
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

send_times = {}
last_seq = None

seq = 1
start = time.time()

# ---------- Main loop ----------
while time.time() - start < RUN_DURATION:
    send_ts = time.time()
    pkt = struct.pack(HEADER_FORMAT, seq, send_ts)
    pkt = pkt.ljust(PACKET_SIZE, b"x")
    sock.send(pkt)

    send_times[seq] = send_ts
    packets_sent += 1
    seq += 1

    try:
        data = sock.recv(1500)
        recv_ts = time.time()

        if len(data) >= HEADER_SIZE:
            rseq, echoed_ts = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
            packets_received += 1

            if last_seq is not None and rseq != last_seq + 1:
                sequence_gaps += abs(rseq - last_seq - 1)
            last_seq = rseq

            if rseq in send_times:
                rtts.append(recv_ts - send_times.pop(rseq))

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

print(f"Starvation windows (>100 ms): {len(starvations)}")
if starvations:
    print(f"Max starvation: {max(starvations)*1000:.2f} ms")

print(f"\nAudio MOS (freeze-aware):  {audio_mos:.2f} / 5.0")
print(f"Video MOS (freeze-aware):  {video_mos:.2f} / 5.0")
print(f"Call Usability Score:      {cus} / 5")

print("\nMeasurement complete.")

