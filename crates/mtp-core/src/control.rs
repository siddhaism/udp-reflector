//! TCP control messages: one JSON object per line.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    /// "audio" or "video". The server treats anything else as audio.
    pub mode: String,
    #[serde(default)]
    pub client_udp_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloResp {
    pub ok: bool,
    pub mode: String,
    pub server_host_v4: Option<String>,
    pub server_host_v6: Option<String>,
    pub server_udp_port: u16,
    pub audio_port: u16,
    pub video_port: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathUpdate {
    pub client_udp_port: Option<u16>,
}

/// Later control messages, e.g. `{"path_update": {"client_udp_port": 1234}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlMsg {
    #[serde(default)]
    pub path_update: Option<PathUpdate>,
}

/// Serialize as a single newline-terminated JSON line.
pub fn to_line<T: Serialize>(msg: &T) -> serde_json::Result<Vec<u8>> {
    let mut v = serde_json::to_vec(msg)?;
    v.push(b'\n');
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let h = Hello { mode: "video".into(), client_udp_port: Some(50000) };
        let line = to_line(&h).unwrap();
        assert_eq!(*line.last().unwrap(), b'\n');
        assert_eq!(serde_json::from_slice::<Hello>(&line).unwrap(), h);
    }

    #[test]
    fn parses_python_hello_resp() {
        let s = r#"{"ok": true, "mode": "audio", "server_host_v4": "0.0.0.0", "server_host_v6": "::", "server_udp_port": 6000, "audio_port": 6000, "video_port": 6001}"#;
        let r: HelloResp = serde_json::from_str(s).unwrap();
        assert_eq!(r.server_udp_port, 6000);
    }

    #[test]
    fn path_update_parses_and_unknown_is_ignored() {
        let m: ControlMsg = serde_json::from_str(r#"{"path_update":{"client_udp_port":7}}"#).unwrap();
        assert_eq!(m.path_update.unwrap().client_udp_port, Some(7));
        let m: ControlMsg = serde_json::from_str(r#"{"other":1}"#).unwrap();
        assert!(m.path_update.is_none());
    }
}
