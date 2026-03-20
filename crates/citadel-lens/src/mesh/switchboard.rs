//! Any Point of Entry switchboard for Citadel mesh ingress.
//!
//! This is the thin ingress protocol that sits in front of the normal mesh
//! session. A joiner can dial any reachable switchboard, request either "any"
//! peer or a specific peer ID, and then continue on the existing mesh TCP
//! session once the ingress step succeeds.

use std::io;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

pub const SWITCHBOARD_PORT_OFFSET: u16 = 443;

pub fn switchboard_port_for_mesh_port(mesh_port: u16) -> u16 {
    mesh_port.saturating_add(SWITCHBOARD_PORT_OFFSET)
}

fn format_target(host: &str, mesh_port: u16) -> String {
    let port = switchboard_port_for_mesh_port(mesh_port);
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SwitchboardMessage {
    #[serde(rename = "switchboard_hello")]
    SwitchboardHello {
        peer_id: String,
        spiral_slot: Option<u64>,
    },

    #[serde(rename = "peer_request")]
    PeerRequest {
        my_peer_id: String,
        want: String,
    },

    #[serde(rename = "peer_ready")]
    PeerReady { peer_id: String },

    #[serde(rename = "peer_redirect")]
    PeerRedirect {
        target_peer_id: String,
        method: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dial_host: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mesh_port: Option<u16>,
    },
}

impl SwitchboardMessage {
    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }

    pub fn from_line(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s.trim_end())
    }
}

pub enum SwitchboardOutcome {
    Ready(TcpStream, std::net::SocketAddr),
    DirectRedirect {
        target_peer_id: String,
        dial_host: String,
        mesh_port: u16,
    },
    SelfDetected,
}

pub enum SwitchboardControl {
    Pause(oneshot::Sender<()>),
    Resume(oneshot::Sender<()>),
}

pub async fn read_json_line(
    stream: &mut TcpStream,
    timeout: Duration,
) -> io::Result<Option<String>> {
    let mut buf = Vec::with_capacity(256);

    let read_result = tokio::time::timeout(timeout, async {
        loop {
            let mut byte = [0u8; 1];
            match stream.read(&mut byte).await? {
                0 => {
                    return if buf.is_empty() {
                        Ok(None)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "switchboard: partial line before EOF",
                        ))
                    };
                }
                _ => {
                    buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                    if buf.len() > 16 * 1024 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "switchboard: line too large",
                        ));
                    }
                }
            }
        }
        Ok(Some(String::from_utf8(buf).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, e)
        })?))
    })
    .await;

    match read_result {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "switchboard: timed out waiting for line",
        )),
    }
}

pub async fn connect_switchboard(
    host: &str,
    mesh_port: u16,
    our_peer_id: &str,
    want: &str,
) -> io::Result<SwitchboardOutcome> {
    let target = format_target(host, mesh_port);
    let mut stream = TcpStream::connect(&target).await?;
    stream.set_nodelay(true)?;

    let request = SwitchboardMessage::PeerRequest {
        my_peer_id: our_peer_id.to_string(),
        want: want.to_string(),
    };
    stream.write_all(request.to_line()?.as_bytes()).await?;

    let hello_line = match read_json_line(&mut stream, Duration::from_secs(3)).await {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(SwitchboardOutcome::SelfDetected),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            return Ok(SwitchboardOutcome::SelfDetected);
        }
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
            return Ok(SwitchboardOutcome::SelfDetected);
        }
        Err(e) => return Err(e),
    };

    let responder_peer_id = match SwitchboardMessage::from_line(&hello_line)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    {
        SwitchboardMessage::SwitchboardHello { peer_id, .. } => peer_id,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("switchboard: expected SwitchboardHello, got {other:?}"),
            ));
        }
    };

    if responder_peer_id == our_peer_id {
        return Ok(SwitchboardOutcome::SelfDetected);
    }

    let response_line = read_json_line(&mut stream, Duration::from_secs(10))
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "switchboard: EOF"))?;

    match SwitchboardMessage::from_line(&response_line)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    {
        SwitchboardMessage::PeerReady { .. } => {
            let peer_addr = stream.peer_addr()?;
            Ok(SwitchboardOutcome::Ready(stream, peer_addr))
        }
        SwitchboardMessage::PeerRedirect {
            target_peer_id,
            method,
            dial_host,
            mesh_port,
        } => {
            if method != "direct" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("switchboard: unsupported redirect method '{method}'"),
                ));
            }
            let dial_host = dial_host.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "switchboard: missing dial_host")
            })?;
            Ok(SwitchboardOutcome::DirectRedirect {
                target_peer_id,
                dial_host,
                mesh_port: mesh_port.unwrap_or(9000),
            })
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("switchboard: unexpected response {other:?}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switchboard_message_round_trip() {
        let msg = SwitchboardMessage::PeerRedirect {
            target_peer_id: "b3b3/test".into(),
            method: "direct".into(),
            dial_host: Some("66.241.124.53".into()),
            mesh_port: Some(9000),
        };

        let line = msg.to_line().unwrap();
        let decoded = SwitchboardMessage::from_line(&line).unwrap();
        match decoded {
            SwitchboardMessage::PeerRedirect {
                target_peer_id,
                method,
                dial_host,
                mesh_port,
            } => {
                assert_eq!(target_peer_id, "b3b3/test");
                assert_eq!(method, "direct");
                assert_eq!(dial_host.as_deref(), Some("66.241.124.53"));
                assert_eq!(mesh_port, Some(9000));
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn switchboard_port_tracks_mesh_port() {
        assert_eq!(switchboard_port_for_mesh_port(9000), 9443);
        assert_eq!(switchboard_port_for_mesh_port(19000), 19443);
    }
}
