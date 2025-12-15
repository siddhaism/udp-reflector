# udp-reflector
A UDP based traffic pattern emulator and statistics collector for media streaming transport

This tool sends paced UDP probes and reports receive-side jitter, loss, RTT, and derived MOS. The client sends a sequence number and client send timestamp; the server echoes the sequence and its receive timestamp.

Modes
- Voice: Constant 20 ms cadence, fixed packet size (default).
- Video: 30/60 fps frames with variable packet sizes and frame bursts (keyframe spikes), plus a simple ABR that adapts target bitrate based on recent loss/starvation.

Client usage examples
- Voice mode (default): `./udp_client.py --server <ip> --port 5005`
- 60 fps video with 2.5 Mbps start: `./udp_client.py --mode video --fps 60 --bitrate-kbps 2500`

Useful options
- `--mode {voice,video}`: traffic pattern
- Voice: `--voice-packet-size`, `--voice-interval-ms`
- Video: `--fps {30,60}`, `--gop <seconds>`, `--keyframe-mult <x>`, `--bitrate-kbps`, `--min-bitrate-kbps`, `--max-bitrate-kbps`, `--pkt-min`, `--pkt-max`, `--burst-gap-ms`, `--abr-interval`
