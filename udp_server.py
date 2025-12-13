#!/usr/bin/env python3
import socket, time, struct, selectors, statistics

PORT = 5005
PACKET_SIZE = 100
CLIENT_TIMEOUT = 5.0
STARVATION_THRESHOLD = 0.100

HEADER_FORMAT = "!Id"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)

sel = selectors.DefaultSelector()

def bind_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", PORT))
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ)
    print("IPv4 UDP listening on 0.0.0.0:", PORT)
    return s

def bind_ipv6():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(("::", PORT))
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ)
    print("IPv6 UDP listening on [::]:", PORT)
    return s

sock4 = bind_ipv4()
sock6 = bind_ipv6()

print("Server running...\n")

class ClientSession:
    def __init__(self):
        self.last_heard = time.time()
        self.recv_count = 0
        self.send_count = 0
        self.sequence_gaps = 0
        self.seq_last = None

        self.arrivals = []
        self.ipas = []
        self.jitters = []
        self.starvations = []

    def add_packet(self, seq, recv_ts):
        self.last_heard = recv_ts
        self.recv_count += 1

        if self.seq_last is not None and seq != self.seq_last + 1:
            self.sequence_gaps += abs(seq - self.seq_last - 1)
        self.seq_last = seq

        self.arrivals.append(recv_ts)
        if len(self.arrivals) >= 2:
            ipa = self.arrivals[-1] - self.arrivals[-2]
            self.ipas.append(ipa)
            if ipa > STARVATION_THRESHOLD:
                self.starvations.append(ipa)
            if len(self.ipas) >= 2:
                self.jitters.append(abs(self.ipas[-1] - self.ipas[-2]))

    def print_stats(self, addr):
        true_loss = max(0, self.recv_count - self.send_count)
        loss_pct = (true_loss / self.recv_count) * 100 if self.recv_count else 0.0

        print(f"\n=== SERVER STATS for {addr[0]}:{addr[1]} ===")
        print(f"Packets received:          {self.recv_count}")
        print(f"Packets sent:              {self.send_count}")
        print(f"True packet loss:          {true_loss} ({loss_pct:.2f}%)")
        print(f"Sequence gaps detected:    {self.sequence_gaps}")

        def fmt(name, values):
            if not values:
                return f"{name}: No data"
            return (
                f"{name} (mean/median/max): "
                f"{statistics.mean(values)*1000:.2f} ms / "
                f"{statistics.median(values)*1000:.2f} ms / "
                f"{max(values)*1000:.2f} ms"
            )

        print(fmt("IPA", self.ipas))
        print(fmt("Jitter", self.jitters))
        print(f"Starvation windows (>100 ms): {len(self.starvations)}")
        if self.starvations:
            print(f"Max starvation: {max(self.starvations)*1000:.2f} ms")

clients = {}

while True:
    now = time.time()
    events = sel.select(timeout=0.01)

    for key, _ in events:
        sock = key.fileobj
        data, addr = sock.recvfrom(1500)
        recv_ts = now

        if addr not in clients:
            print(f"[NEW CLIENT] Connected: {addr[0]}:{addr[1]}")
            clients[addr] = ClientSession()

        session = clients[addr]

        if len(data) >= HEADER_SIZE:
            seq, client_ts = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
            session.add_packet(seq, recv_ts)

            reply = struct.pack(HEADER_FORMAT, seq, recv_ts)
            reply = reply.ljust(PACKET_SIZE, b"x")

            if ":" in addr[0]:
                sock6.sendto(reply, addr)
            else:
                sock4.sendto(reply, addr)

            session.send_count += 1

    for addr, session in list(clients.items()):
        if now - session.last_heard > CLIENT_TIMEOUT:
            session.print_stats(addr)
            del clients[addr]

