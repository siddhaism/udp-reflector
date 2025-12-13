# udp-reflector
A UDP based traffic patter emulator and statistics collector for media streaming transport

## TWAMP-style timestamps

Client and server now exchange four timestamps per probe to enable directional latency/jitter without clock sync:

- `T1` client send time (embedded by client)
- `T2` server receive time (stamped by server on receipt)
- `T3` server send time (stamped by server on transmit)
- `T4` client receive time (measured locally on client)

The client reports:

- Uplink OWD: `T2 - T1` and jitter (variation)
- Downlink OWD: `T4 - T3` and jitter (variation)
- TWAMP RTT (excluding server residence time): `(T4 - T1) - (T3 - T2)`
- Reconstructed uplink starvation windows using consecutive `T2` deltas

Note: Absolute one-way latency requires synchronized clocks, but jitter and relative latency trends per direction work without sync.
