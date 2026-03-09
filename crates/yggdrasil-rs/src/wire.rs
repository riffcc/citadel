//! Ironwood wire framing: uvarint-prefixed messages with typed packet headers.
//!
//! Frame format:
//!   [uvarint: frame_size (includes type byte + payload)]
//!   [u8: packet_type]
//!   [payload: frame_size - 1 bytes]
//!
//! uvarint encoding is Go's `binary.Uvarint` — 7 bits per byte, MSB continuation.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{WireError, MAX_MESSAGE_SIZE};

/// Ironwood wire packet types.
///
/// Stock Yggdrasil sends all of these. We handle KeepAlive and Traffic natively;
/// tree routing types (SigReq/SigRes/Announce/Bloom/Path*) are accepted gracefully
/// but routed via SPIRAL instead of spanning tree.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketType {
    Dummy = 0,
    KeepAlive = 1,
    ProtoSigReq = 2,
    ProtoSigRes = 3,
    ProtoAnnounce = 4,
    ProtoBloomFilter = 5,
    ProtoPathLookup = 6,
    ProtoPathNotify = 7,
    ProtoPathBroken = 8,
    Traffic = 9,
}

impl TryFrom<u8> for PacketType {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Dummy),
            1 => Ok(Self::KeepAlive),
            2 => Ok(Self::ProtoSigReq),
            3 => Ok(Self::ProtoSigRes),
            4 => Ok(Self::ProtoAnnounce),
            5 => Ok(Self::ProtoBloomFilter),
            6 => Ok(Self::ProtoPathLookup),
            7 => Ok(Self::ProtoPathNotify),
            8 => Ok(Self::ProtoPathBroken),
            9 => Ok(Self::Traffic),
            other => Err(WireError::UnknownPacketType(other)),
        }
    }
}

// ── uvarint encoding (Go binary.Uvarint compatible) ──────────────────

/// Encode a u64 as a uvarint (7 bits per byte, MSB = continuation).
pub fn encode_uvarint(mut x: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    while x >= 0x80 {
        buf.push((x as u8) | 0x80);
        x >>= 7;
    }
    buf.push(x as u8);
    buf
}

/// Decode a uvarint from a byte slice. Returns (value, bytes_consumed).
pub fn decode_uvarint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 10 {
            return None; // overflow
        }
        if b < 0x80 {
            // Check for overflow on the last byte
            if i == 9 && b > 1 {
                return None;
            }
            return Some((x | (b as u64) << s, i + 1));
        }
        x |= ((b & 0x7f) as u64) << s;
        s += 7;
    }
    None // incomplete
}

// ── Async frame I/O ──────────────────────────────────────────────────

/// Read one uvarint-framed ironwood message from an async stream.
///
/// Returns (packet_type, payload). Payload does NOT include the type byte.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(PacketType, Vec<u8>), WireError> {
    // Read uvarint: one byte at a time until MSB is clear
    let mut size_buf = [0u8; 10];
    let mut size_len = 0;

    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        size_buf[size_len] = byte[0];
        size_len += 1;

        if byte[0] < 0x80 || size_len >= 10 {
            break;
        }
    }

    let (frame_size, _) =
        decode_uvarint(&size_buf[..size_len]).ok_or(WireError::InvalidUvarint)?;

    if frame_size == 0 {
        return Err(WireError::EmptyFrame);
    }
    if frame_size > MAX_MESSAGE_SIZE {
        return Err(WireError::FrameTooLarge(frame_size));
    }

    // Read frame body: [type:1][payload:frame_size-1]
    let mut body = vec![0u8; frame_size as usize];
    reader.read_exact(&mut body).await?;

    let packet_type = PacketType::try_from(body[0])?;
    let payload = if body.len() > 1 {
        body[1..].to_vec()
    } else {
        Vec::new()
    };

    Ok((packet_type, payload))
}

/// Write one uvarint-framed ironwood message to an async stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet_type: PacketType,
    payload: &[u8],
) -> Result<(), WireError> {
    let frame_size = 1 + payload.len(); // type byte + payload
    let size_bytes = encode_uvarint(frame_size as u64);

    writer.write_all(&size_bytes).await?;
    writer.write_all(&[packet_type as u8]).await?;
    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }
    writer.flush().await?;

    Ok(())
}

/// Write a keepalive frame (type=1, no payload).
pub async fn write_keepalive<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<(), WireError> {
    write_frame(writer, PacketType::KeepAlive, &[]).await
}

// ── Path encoding (used in traffic, lookup, notify packets) ──────────

/// Encode a path as a sequence of uvarint port numbers, zero-terminated.
pub fn encode_path(ports: &[u64]) -> Vec<u8> {
    let mut buf = Vec::new();
    for &port in ports {
        buf.extend(encode_uvarint(port));
    }
    buf.push(0x00); // zero terminator
    buf
}

/// Decode a zero-terminated path of uvarint port numbers.
/// Returns (ports, bytes_consumed).
pub fn decode_path(data: &[u8]) -> Option<(Vec<u64>, usize)> {
    let mut ports = Vec::new();
    let mut offset = 0;

    loop {
        let (value, consumed) = decode_uvarint(&data[offset..])?;
        offset += consumed;
        if value == 0 {
            break; // zero terminator
        }
        ports.push(value);
    }

    Some((ports, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uvarint_roundtrip() {
        for &val in &[0u64, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX / 2] {
            let encoded = encode_uvarint(val);
            let (decoded, consumed) = decode_uvarint(&encoded).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {val}");
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn uvarint_small_values() {
        assert_eq!(encode_uvarint(0), vec![0x00]);
        assert_eq!(encode_uvarint(1), vec![0x01]);
        assert_eq!(encode_uvarint(127), vec![0x7F]);
        assert_eq!(encode_uvarint(128), vec![0x80, 0x01]);
        assert_eq!(encode_uvarint(300), vec![0xAC, 0x02]);
    }

    #[test]
    fn uvarint_go_compatible() {
        // Known Go encoding: 150 = 0x96 0x01
        assert_eq!(encode_uvarint(150), vec![0x96, 0x01]);
        let (val, _) = decode_uvarint(&[0x96, 0x01]).unwrap();
        assert_eq!(val, 150);
    }

    #[test]
    fn packet_type_roundtrip() {
        for i in 0..=9u8 {
            let pt = PacketType::try_from(i).unwrap();
            assert_eq!(pt as u8, i);
        }
    }

    #[test]
    fn unknown_packet_type_rejected() {
        assert!(PacketType::try_from(10u8).is_err());
        assert!(PacketType::try_from(255u8).is_err());
    }

    #[test]
    fn path_roundtrip() {
        let ports = vec![1, 5, 42, 1000];
        let encoded = encode_path(&ports);
        let (decoded, _) = decode_path(&encoded).unwrap();
        assert_eq!(decoded, ports);
    }

    #[test]
    fn empty_path() {
        let encoded = encode_path(&[]);
        assert_eq!(encoded, vec![0x00]); // just the terminator
        let (decoded, consumed) = decode_path(&encoded).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(consumed, 1);
    }

    #[tokio::test]
    async fn frame_roundtrip() {
        let (client, server) = tokio::io::duplex(4096);
        let (mut writer, mut reader) = (client, server);

        let payload = b"hello world";

        let write_handle = tokio::spawn(async move {
            write_frame(&mut writer, PacketType::Traffic, payload)
                .await
                .unwrap();
        });

        let (ptype, data) = read_frame(&mut reader).await.unwrap();
        write_handle.await.unwrap();

        assert_eq!(ptype, PacketType::Traffic);
        assert_eq!(data, payload);
    }

    #[tokio::test]
    async fn keepalive_frame() {
        let (client, server) = tokio::io::duplex(4096);
        let (mut writer, mut reader) = (client, server);

        let write_handle = tokio::spawn(async move {
            write_keepalive(&mut writer).await.unwrap();
        });

        let (ptype, data) = read_frame(&mut reader).await.unwrap();
        write_handle.await.unwrap();

        assert_eq!(ptype, PacketType::KeepAlive);
        assert!(data.is_empty());
    }
}
