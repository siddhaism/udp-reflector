//! Wire format: `MAGIC(4) VER(1) MODE(1) SEQ(8) SEND_NS(8)` big-endian, then zero padding.

use thiserror::Error;

pub const MAGIC: [u8; 4] = *b"MTP1";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Audio,
    Video,
}

impl Mode {
    pub fn flag(self) -> u8 {
        match self {
            Mode::Audio => 1,
            Mode::Video => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    /// Raw mode byte; the reflector accepts values it does not know.
    pub mode: u8,
    pub seq: u64,
    pub send_ns: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("packet size {0} is smaller than the {HEADER_LEN}-byte header")]
    SizeTooSmall(usize),
}

/// Build a packet of exactly `size` bytes.
pub fn build_packet(mode: Mode, seq: u64, send_ns: u64, size: usize) -> Result<Vec<u8>, WireError> {
    if size < HEADER_LEN {
        return Err(WireError::SizeTooSmall(size));
    }
    let mut buf = vec![0u8; size];
    buf[..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION;
    buf[5] = mode.flag();
    buf[6..14].copy_from_slice(&seq.to_be_bytes());
    buf[14..22].copy_from_slice(&send_ns.to_be_bytes());
    Ok(buf)
}

/// Parse a datagram; `None` if too short or the magic does not match.
pub fn parse_packet(data: &[u8]) -> Option<Header> {
    if data.len() < HEADER_LEN || data[..4] != MAGIC {
        return None;
    }
    Some(Header {
        version: data[4],
        mode: data[5],
        seq: u64::from_be_bytes(data[6..14].try_into().ok()?),
        send_ns: u64::from_be_bytes(data[14..22].try_into().ok()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = build_packet(Mode::Video, 42, 1_700_000_000_123_456_789, 100).unwrap();
        assert_eq!(p.len(), 100);
        assert!(p[22..].iter().all(|&b| b == 0));
        let h = parse_packet(&p).unwrap();
        assert_eq!(
            h,
            Header { version: 1, mode: 2, seq: 42, send_ns: 1_700_000_000_123_456_789 }
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(build_packet(Mode::Audio, 0, 0, 21), Err(WireError::SizeTooSmall(21)));
        assert!(parse_packet(&[0u8; 21]).is_none());
        let mut p = build_packet(Mode::Audio, 0, 0, 22).unwrap();
        p[0] = b'X';
        assert!(parse_packet(&p).is_none());
    }

    #[test]
    fn matches_python_bytes() {
        // struct.pack(">BBQQ", 1, 1, 7, 1000) after MAGIC
        let p = build_packet(Mode::Audio, 7, 1000, 22).unwrap();
        let expected: [u8; 22] = [
            b'M', b'T', b'P', b'1', 1, 1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0x03, 0xE8,
        ];
        assert_eq!(p, expected);
    }
}
