//! Yggdrasil "meta" handshake protocol.
//!
//! Wire format:
//!   [4 bytes: "meta"]
//!   [2 bytes: uint16 BE remaining length]
//!   [TLV fields...]
//!   [64 bytes: Ed25519 signature]
//!
//! TLV fields (each: [type:2 BE][length:2 BE][value:length bytes]):
//!   Type 0: metaVersionMajor (uint16 BE) — must be 0
//!   Type 1: metaVersionMinor (uint16 BE) — must be 5
//!   Type 2: metaPublicKey (32 bytes)
//!   Type 3: metaPriority (uint8)
//!
//! Signature: ed25519_sign(privkey, blake2b_512(pubkey, key=password))

use ed25519_dalek::{Signer, Verifier};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::{self, Identity};
use crate::error::MetaError;

/// Current protocol version — must match for peering.
pub const VERSION_MAJOR: u16 = 0;
pub const VERSION_MINOR: u16 = 5;

/// Parsed result of a meta handshake.
#[derive(Debug, Clone)]
pub struct MetaHandshake {
    pub public_key: [u8; 32],
    pub priority: u8,
}

/// Perform the full bidirectional meta handshake.
///
/// Both sides send their meta message simultaneously and then read the peer's.
/// Returns the remote peer's handshake data on success.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    priority: u8,
    password: Option<&[u8]>,
) -> Result<MetaHandshake, MetaError> {
    let our_msg = encode(
        &identity.public_key_bytes,
        &identity.signing_key,
        priority,
        password,
    );

    let (mut reader, mut writer) = tokio::io::split(stream);

    let (write_result, read_result) = tokio::join!(
        async {
            writer.write_all(&our_msg).await?;
            writer.flush().await?;
            Ok::<_, MetaError>(())
        },
        read_from_stream(&mut reader),
    );

    write_result?;
    let their_bytes = read_result?;
    decode(&their_bytes, password)
}

/// Encode a meta handshake message.
pub fn encode(
    pubkey: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    priority: u8,
    password: Option<&[u8]>,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(128);

    // TLV: metaVersionMajor = 0
    body.extend_from_slice(&0u16.to_be_bytes()); // type
    body.extend_from_slice(&2u16.to_be_bytes()); // length
    body.extend_from_slice(&VERSION_MAJOR.to_be_bytes()); // value

    // TLV: metaVersionMinor = 5
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&VERSION_MINOR.to_be_bytes());

    // TLV: metaPublicKey
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&32u16.to_be_bytes());
    body.extend_from_slice(pubkey);

    // TLV: metaPriority
    body.extend_from_slice(&3u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(priority);

    // Signature: ed25519_sign(blake2b_512(pubkey, key=password))
    let hash = crypto::blake2b_hash(pubkey, password);
    let signature = signing_key.sign(&hash);
    body.extend_from_slice(&signature.to_bytes());

    // Build full message: "meta" + uint16_be(body.len()) + body
    let mut msg = Vec::with_capacity(6 + body.len());
    msg.extend_from_slice(b"meta");
    msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
    msg.extend(body);

    msg
}

/// Decode and verify a meta handshake message.
pub fn decode(data: &[u8], password: Option<&[u8]>) -> Result<MetaHandshake, MetaError> {
    if data.len() < 6 || &data[0..4] != b"meta" {
        return Err(MetaError::InvalidPreamble);
    }

    let remaining_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    if data.len() < 6 + remaining_len {
        return Err(MetaError::Truncated);
    }

    let body = &data[6..6 + remaining_len];

    // Signature is the last 64 bytes
    if body.len() < 64 {
        return Err(MetaError::NoSignature);
    }
    let sig_bytes = &body[body.len() - 64..];
    let tlv_bytes = &body[..body.len() - 64];

    // Parse TLV fields
    let mut version_major = None;
    let mut version_minor = None;
    let mut public_key = None;
    let mut priority = 0u8;

    let mut pos = 0;
    while pos + 4 <= tlv_bytes.len() {
        let typ = u16::from_be_bytes([tlv_bytes[pos], tlv_bytes[pos + 1]]);
        let len = u16::from_be_bytes([tlv_bytes[pos + 2], tlv_bytes[pos + 3]]) as usize;
        pos += 4;

        if pos + len > tlv_bytes.len() {
            return Err(MetaError::TruncatedTlv);
        }

        let value = &tlv_bytes[pos..pos + len];
        match (typ, len) {
            (0, 2) => version_major = Some(u16::from_be_bytes([value[0], value[1]])),
            (1, 2) => version_minor = Some(u16::from_be_bytes([value[0], value[1]])),
            (2, 32) => {
                let mut key = [0u8; 32];
                key.copy_from_slice(value);
                public_key = Some(key);
            }
            (3, 1) => priority = value[0],
            _ => {} // Unknown TLV — ignore for forward compatibility
        }

        pos += len;
    }

    let public_key = public_key.ok_or(MetaError::MissingPublicKey)?;
    let version_major = version_major.ok_or(MetaError::MissingVersion)?;
    let version_minor = version_minor.ok_or(MetaError::MissingVersion)?;

    // Version check — must match exactly
    if version_major != VERSION_MAJOR || version_minor != VERSION_MINOR {
        return Err(MetaError::VersionMismatch {
            major: version_major,
            minor: version_minor,
        });
    }

    // Verify signature
    let hash = crypto::blake2b_hash(&public_key, password);
    let signature = ed25519_dalek::Signature::from_bytes(
        sig_bytes.try_into().map_err(|_| MetaError::NoSignature)?,
    );
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|_| MetaError::InvalidPublicKey)?;
    verifying_key
        .verify(&hash, &signature)
        .map_err(|_| MetaError::InvalidSignature)?;

    Ok(MetaHandshake {
        public_key,
        priority,
    })
}

/// Read a complete meta handshake message from an async stream.
async fn read_from_stream<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, MetaError> {
    // Read preamble: "meta" (4 bytes)
    let mut preamble = [0u8; 4];
    reader.read_exact(&mut preamble).await?;
    if &preamble != b"meta" {
        return Err(MetaError::InvalidPreamble);
    }

    // Read remaining length (uint16 BE)
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let remaining = u16::from_be_bytes(len_buf) as usize;

    // Read body (TLV + signature)
    let mut body = vec![0u8; remaining];
    reader.read_exact(&mut body).await?;

    // Reconstruct full message for decode()
    let mut full = Vec::with_capacity(6 + remaining);
    full.extend_from_slice(b"meta");
    full.extend_from_slice(&len_buf);
    full.extend(body);

    Ok(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let identity = Identity::generate();
        let encoded = encode(
            &identity.public_key_bytes,
            &identity.signing_key,
            42,
            None,
        );
        let decoded = decode(&encoded, None).unwrap();
        assert_eq!(decoded.public_key, identity.public_key_bytes);
        assert_eq!(decoded.priority, 42);
    }

    #[test]
    fn encode_decode_with_password() {
        let identity = Identity::generate();
        let pw = b"secret";
        let encoded = encode(
            &identity.public_key_bytes,
            &identity.signing_key,
            0,
            Some(pw),
        );
        let decoded = decode(&encoded, Some(pw)).unwrap();
        assert_eq!(decoded.public_key, identity.public_key_bytes);
    }

    #[test]
    fn wrong_password_fails_verification() {
        let identity = Identity::generate();
        let encoded = encode(
            &identity.public_key_bytes,
            &identity.signing_key,
            0,
            Some(b"correct"),
        );
        let result = decode(&encoded, Some(b"wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn preamble_is_meta() {
        let identity = Identity::generate();
        let encoded = encode(
            &identity.public_key_bytes,
            &identity.signing_key,
            0,
            None,
        );
        assert_eq!(&encoded[0..4], b"meta");
    }

    #[test]
    fn version_fields_present() {
        let identity = Identity::generate();
        let encoded = encode(
            &identity.public_key_bytes,
            &identity.signing_key,
            0,
            None,
        );
        let decoded = decode(&encoded, None).unwrap();
        // If decode succeeds, version was 0.5 — the check is inside decode()
        assert_eq!(decoded.public_key, identity.public_key_bytes);
    }

    #[test]
    fn rejects_bad_preamble() {
        let result = decode(b"nope\x00\x00", None);
        assert!(matches!(result, Err(MetaError::InvalidPreamble)));
    }

    #[test]
    fn rejects_truncated_message() {
        let result = decode(b"meta\x00\xFF", None);
        assert!(matches!(result, Err(MetaError::Truncated)));
    }

    #[tokio::test]
    async fn async_handshake_roundtrip() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let (client, server) = tokio::io::duplex(4096);
        let (mut client_stream, mut server_stream) = (client, server);

        let (a_result, b_result) = tokio::join!(
            handshake(&mut client_stream, &id_a, 1, None),
            handshake(&mut server_stream, &id_b, 2, None),
        );

        let a_got = a_result.unwrap();
        let b_got = b_result.unwrap();

        // A sees B's key
        assert_eq!(a_got.public_key, id_b.public_key_bytes);
        assert_eq!(a_got.priority, 2);

        // B sees A's key
        assert_eq!(b_got.public_key, id_a.public_key_bytes);
        assert_eq!(b_got.priority, 1);
    }
}
