//! Yggdrasil cryptographic identity and address derivation.
//!
//! An Yggdrasil address is deterministically derived from an Ed25519 public key:
//!   1. Invert all bits of the public key
//!   2. Count leading ones in the inverted key ("strength")
//!   3. Skip (ones + 1) bits
//!   4. Address = [0x02, ones_count, remaining_112_bits...]
//!
//! This produces a unique IPv6 address in the 200::/7 range.

use std::net::Ipv6Addr;

use ed25519_dalek::{SigningKey, VerifyingKey};

/// A complete Yggdrasil node identity: Ed25519 keypair + derived addresses.
#[derive(Clone)]
pub struct Identity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub public_key_bytes: [u8; 32],
    pub address: Ipv6Addr,
    pub subnet: Ipv6Addr,
}

impl Identity {
    /// Create an identity from a 64-byte Go-format private key (seed:32 + pubkey:32).
    pub fn from_privkey_bytes(privkey: &[u8; 64]) -> Self {
        let seed: [u8; 32] = privkey[..32].try_into().unwrap();
        Self::from_seed(&seed)
    }

    /// Create an identity from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();
        let address = address_for_key(&public_key_bytes);
        let subnet = subnet_for_key(&public_key_bytes);
        Self { signing_key, verifying_key, public_key_bytes, address, subnet }
    }

    /// Generate a new random identity.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();
        let address = address_for_key(&public_key_bytes);
        let subnet = subnet_for_key(&public_key_bytes);
        Self { signing_key, verifying_key, public_key_bytes, address, subnet }
    }

    /// The "strength" of this key — number of leading zeros in the raw public key.
    /// Higher means more brute-force effort was needed to generate it.
    pub fn strength(&self) -> u32 {
        let inverted = invert_bytes(&self.public_key_bytes);
        leading_ones(&inverted)
    }

    /// Public key as lowercase hex string (64 characters).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes)
    }
}

/// Derive the Yggdrasil IPv6 address (200::/7) from an Ed25519 public key.
pub fn address_for_key(pubkey: &[u8; 32]) -> Ipv6Addr {
    let inverted = invert_bytes(pubkey);
    let ones = leading_ones(&inverted);
    let remaining = strip_leading_bits(&inverted, ones as usize + 1);

    let mut addr = [0u8; 16];
    addr[0] = 0x02; // 200::/7 prefix, address variant (bit 0 clear)
    addr[1] = ones as u8;
    let copy_len = remaining.len().min(14);
    addr[2..2 + copy_len].copy_from_slice(&remaining[..copy_len]);

    Ipv6Addr::from(addr)
}

/// Derive the Yggdrasil subnet (300::/7) from an Ed25519 public key.
pub fn subnet_for_key(pubkey: &[u8; 32]) -> Ipv6Addr {
    let inverted = invert_bytes(pubkey);
    let ones = leading_ones(&inverted);
    let remaining = strip_leading_bits(&inverted, ones as usize + 1);

    let mut addr = [0u8; 16];
    addr[0] = 0x03; // 300::/7 prefix, subnet variant (bit 0 set)
    addr[1] = ones as u8;
    let copy_len = remaining.len().min(14);
    addr[2..2 + copy_len].copy_from_slice(&remaining[..copy_len]);

    Ipv6Addr::from(addr)
}

/// Check if an IPv6 address is in the Yggdrasil 200::/7 range.
pub fn is_yggdrasil_addr(addr: &Ipv6Addr) -> bool {
    let octets = addr.octets();
    // 200::/7 means the first 7 bits are 0000_001x, so first byte & 0xFE == 0x02
    octets[0] & 0xFE == 0x02
}

/// Compute the Blake2b-512 hash used in the meta handshake signature.
///
/// If a password is provided, it's used as the Blake2b key (MAC mode).
/// Otherwise, unkeyed Blake2b-512 is used.
pub fn blake2b_hash(pubkey: &[u8; 32], password: Option<&[u8]>) -> [u8; 64] {
    let mut result = [0u8; 64];
    match password.filter(|p| !p.is_empty()) {
        Some(pw) => {
            use blake2::digest::{consts::U64, Mac};
            let mut mac = blake2::Blake2bMac::<U64>::new_from_slice(pw)
                .expect("blake2b accepts any key length");
            Mac::update(&mut mac, pubkey);
            result.copy_from_slice(&mac.finalize().into_bytes());
        }
        None => {
            use blake2::Digest;
            result.copy_from_slice(&blake2::Blake2b512::digest(pubkey));
        }
    }
    result
}

// ── Internal helpers ──────────────────────────────────────────────────

/// Bitwise NOT every byte.
fn invert_bytes(input: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (o, &i) in out.iter_mut().zip(input.iter()) {
        *o = !i;
    }
    out
}

/// Count the number of leading one-bits in a byte slice.
fn leading_ones(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in bytes {
        let lo = byte.leading_ones();
        count += lo;
        if lo < 8 {
            break;
        }
    }
    count
}

/// Strip `n` leading bits from a byte slice, returning the remainder.
fn strip_leading_bits(bytes: &[u8], n: usize) -> Vec<u8> {
    let byte_offset = n / 8;
    let bit_offset = n % 8;

    if byte_offset >= bytes.len() {
        return vec![0; bytes.len()];
    }

    let remaining = &bytes[byte_offset..];
    let mut result = Vec::with_capacity(remaining.len());

    for i in 0..remaining.len() {
        let mut byte = remaining[i] << bit_offset;
        if bit_offset > 0 && i + 1 < remaining.len() {
            byte |= remaining[i + 1] >> (8 - bit_offset);
        }
        result.push(byte);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_address() {
        let seed = [42u8; 32];
        let id1 = Identity::from_seed(&seed);
        let id2 = Identity::from_seed(&seed);
        assert_eq!(id1.address, id2.address);
        assert_eq!(id1.public_key_bytes, id2.public_key_bytes);
    }

    #[test]
    fn address_in_200_range() {
        let id = Identity::generate();
        assert!(is_yggdrasil_addr(&id.address), "address {:?} not in 200::/7", id.address);
    }

    #[test]
    fn subnet_in_300_range() {
        let id = Identity::generate();
        let octets = id.subnet.octets();
        assert_eq!(octets[0] & 0xFE, 0x02);
        assert_eq!(octets[0] & 0x01, 0x01); // subnet bit set
    }

    #[test]
    fn different_keys_different_addresses() {
        let id1 = Identity::from_seed(&[1u8; 32]);
        let id2 = Identity::from_seed(&[2u8; 32]);
        assert_ne!(id1.address, id2.address);
    }

    #[test]
    fn from_privkey_bytes_matches_seed() {
        let seed = [7u8; 32];
        let id_seed = Identity::from_seed(&seed);
        let mut privkey = [0u8; 64];
        privkey[..32].copy_from_slice(&seed);
        privkey[32..].copy_from_slice(&id_seed.public_key_bytes);
        let id_priv = Identity::from_privkey_bytes(&privkey);
        assert_eq!(id_seed.address, id_priv.address);
        assert_eq!(id_seed.public_key_bytes, id_priv.public_key_bytes);
    }

    #[test]
    fn leading_ones_counts() {
        assert_eq!(leading_ones(&[0xFF, 0xFF, 0x00]), 16);
        assert_eq!(leading_ones(&[0xFF, 0xFE, 0x00]), 15);
        assert_eq!(leading_ones(&[0x00]), 0);
        assert_eq!(leading_ones(&[0x80]), 1);
        assert_eq!(leading_ones(&[0xF0]), 4);
    }

    #[test]
    fn strip_bits_basic() {
        let bytes = [0xFF, 0x80]; // 11111111 10000000
        let result = strip_leading_bits(&bytes, 9); // skip 9 bits (8 ones + first zero)
        // Remaining: 0000000 (7 bits from second byte after the leading 1)
        assert_eq!(result[0], 0x00);
    }

    #[test]
    fn blake2b_unkeyed_deterministic() {
        let pubkey = [0u8; 32];
        let h1 = blake2b_hash(&pubkey, None);
        let h2 = blake2b_hash(&pubkey, None);
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake2b_keyed_differs_from_unkeyed() {
        let pubkey = [0u8; 32];
        let unkeyed = blake2b_hash(&pubkey, None);
        let keyed = blake2b_hash(&pubkey, Some(b"password"));
        assert_ne!(unkeyed, keyed);
    }

    #[test]
    fn address_second_byte_is_strength() {
        // The second byte of the address encodes the "ones" count
        let id = Identity::from_seed(&[42u8; 32]);
        let octets = id.address.octets();
        assert_eq!(octets[1] as u32, id.strength());
    }
}
