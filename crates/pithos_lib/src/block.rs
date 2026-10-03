//! Pure current-protocol block transformation and verification.

use crate::crypto::{self, BlockKey};
use crate::error::PithosError;
use crate::format::block::{BlockIndexEntry, ProcessingFlags};
use std::fmt;
use zeroize::Zeroizing;
use zstd::bulk;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub max_stored_bytes: u64,
    pub max_decoded_bytes: u64,
}

pub struct EncodedBlock {
    pub(crate) stored: Zeroizing<Vec<u8>>,
    pub(crate) hash: [u8; 32],
    pub(crate) key: BlockKey,
    pub(crate) flags: ProcessingFlags,
}

impl fmt::Debug for EncodedBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedBlock")
            .field("stored_len", &self.stored.len())
            .field("hash", &self.hash)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

/// Encodes one block. A unique-key block gets a fresh random key on every call.
pub fn encode(
    plaintext: &[u8],
    requested_flags: ProcessingFlags,
    nonce: [u8; 12],
) -> Result<EncodedBlock, PithosError> {
    let key = if requested_flags.is_unique_key() {
        crypto::random_block_key()
    } else {
        crypto::derive_block_key(plaintext)
    };
    encode_with_key(plaintext, requested_flags, key, nonce)
}

fn encode_with_key(
    plaintext: &[u8],
    requested_flags: ProcessingFlags,
    key: BlockKey,
    nonce: [u8; 12],
) -> Result<EncodedBlock, PithosError> {
    if requested_flags.0 & ProcessingFlags::VERSION_1_1_MASK != 0 && !requested_flags.is_encrypted()
    {
        return Err(PithosError::ProcessingRequiresEncryption(requested_flags.0));
    }
    let hash = block_hash(requested_flags, &key, plaintext);
    let mut flags = requested_flags;
    let compression_level = zstd_level(flags);
    let mut stored = Zeroizing::new(
        if compression_level > 0 && probe_ratio(plaintext, compression_level)? < 0.85 {
            compress(plaintext, compression_level)?
        } else {
            flags.set_compression_level(0);
            plaintext.to_vec()
        },
    );
    if flags.is_aes_256_gcm() {
        stored = Zeroizing::new(crypto::seal_block_aes_with_nonce(&key, &stored, nonce)?);
    } else if flags.is_encrypted() {
        stored = Zeroizing::new(crypto::seal_block_with_nonce(&key, &stored, nonce)?);
    }
    Ok(EncodedBlock {
        stored,
        hash,
        key,
        flags,
    })
}

pub(crate) fn verify(
    stored: impl Into<Zeroizing<Vec<u8>>>,
    key: &BlockKey,
    expected_hash: [u8; 32],
    meta: &BlockIndexEntry,
    limits: Limits,
) -> Result<Zeroizing<Vec<u8>>, PithosError> {
    let stored = stored.into();
    if meta.stored_size > limits.max_stored_bytes {
        return Err(PithosError::LimitExceeded {
            field: "stored block",
            limit: limits.max_stored_bytes,
            actual: meta.stored_size,
        });
    }
    if meta.original_size > limits.max_decoded_bytes {
        return Err(PithosError::LimitExceeded {
            field: "decoded block",
            limit: limits.max_decoded_bytes,
            actual: meta.original_size,
        });
    }
    if stored.len() as u64 != meta.stored_size {
        return Err(PithosError::BlockSizeMismatch {
            expected: meta.stored_size,
            actual: stored.len() as u64,
        });
    }
    let mut plaintext = if meta.flags.is_aes_256_gcm() {
        crypto::open_block_aes(key, &stored)?
    } else if meta.flags.is_encrypted() {
        crypto::open_block(key, &stored)?
    } else {
        stored
    };
    if meta.flags.get_compression_level() > 0 {
        plaintext = Zeroizing::new(decompress(&plaintext, meta.original_size)?);
    }
    if plaintext.len() as u64 != meta.original_size {
        return Err(PithosError::BlockSizeMismatch {
            expected: meta.original_size,
            actual: plaintext.len() as u64,
        });
    }
    let actual_hash = block_hash(meta.flags, key, &plaintext);
    if actual_hash != expected_hash {
        return Err(PithosError::BlockHashMismatch {
            expected: expected_hash,
            actual: actual_hash,
        });
    }
    Ok(plaintext)
}

/// The block hash: plain BLAKE3, or the keyed identity of a unique-key block.
fn block_hash(flags: ProcessingFlags, key: &BlockKey, plaintext: &[u8]) -> [u8; 32] {
    if flags.is_unique_key() {
        crypto::keyed_block_hash(key, plaintext)
    } else {
        crypto::block_hash(plaintext)
    }
}

pub(crate) fn zstd_level(flags: ProcessingFlags) -> i32 {
    match flags.get_compression_level() {
        0 => 0,
        1 => 1,
        2 => 4,
        3 => 8,
        4 => 11,
        5 => 15,
        6 => 18,
        _ => 22,
    }
}

fn probe_ratio(input: &[u8], level: i32) -> Result<f64, PithosError> {
    if input.is_empty() {
        return Ok(1.0);
    }
    let sample = &input[..input.len().min(4096)];
    let compressed = Zeroizing::new(compress(sample, level)?);
    Ok(compressed.len() as f64 / sample.len() as f64)
}

fn compress(input: &[u8], level: i32) -> Result<Vec<u8>, PithosError> {
    bulk::compress(input, level).map_err(|source| PithosError::Compression {
        operation: "compress block",
        source,
    })
}

fn decompress(input: &[u8], expected_size: u64) -> Result<Vec<u8>, PithosError> {
    let size = usize::try_from(expected_size).map_err(|_| PithosError::InvalidDirectoryRange {
        operation: "convert decoded block size",
    })?;
    bulk::decompress(input, size).map_err(|source| PithosError::Compression {
        operation: "decompress block",
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::block::BlockLocation;

    fn descriptor(encoded: &EncodedBlock, original_size: usize) -> BlockIndexEntry {
        BlockIndexEntry {
            offset: 0,
            stored_size: encoded.stored.len() as u64,
            original_size: original_size as u64,
            flags: encoded.flags,
            location: BlockLocation::Local,
        }
    }

    #[test]
    fn controlled_nonce_vector_round_trips_without_changing_the_protocol_shape() {
        let plain = b"current protocol vector";
        let encoded = encode(plain, ProcessingFlags::new(true, Some(2)), [7; 12]).unwrap();
        assert_eq!(encoded.hash, *blake3::hash(plain).as_bytes());
        assert_eq!(&encoded.stored[..12], &[7; 12]);
        assert_eq!(
            &*verify(
                encoded.stored,
                &encoded.key,
                encoded.hash,
                &descriptor(
                    &encode(plain, ProcessingFlags::new(true, Some(2)), [7; 12]).unwrap(),
                    plain.len()
                ),
                Limits {
                    max_stored_bytes: 1024,
                    max_decoded_bytes: 1024
                },
            )
            .unwrap(),
            plain
        );
    }

    fn limits() -> Limits {
        Limits {
            max_stored_bytes: 1024,
            max_decoded_bytes: 1024,
        }
    }

    fn unique_flags(compression_level: u8) -> ProcessingFlags {
        let mut flags = ProcessingFlags::new(true, Some(compression_level));
        flags.set_unique_key(true);
        flags
    }

    #[test]
    fn unique_key_vector_matches_the_specification() {
        let key = BlockKey::from_bytes(std::array::from_fn(|index| index as u8));
        let nonce = std::array::from_fn(|index| 0xa0 + index as u8);
        let encoded = encode_with_key(b"hello", unique_flags(0), key, nonce).unwrap();
        assert_eq!(encoded.flags.0, 0x18);
        // PV-UNIQUE-KEY-HELLO in Appendix B.
        assert_eq!(
            blake3::Hash::from(encoded.hash).to_hex().as_str(),
            "ca2bb927d0c0ac7196480fdf9c5101615bd8bc349663ffd9c3fef37228675a62"
        );
        assert_eq!(
            &encoded.stored[12..],
            [
                0x64, 0xce, 0x14, 0x33, 0x22, 0xbc, 0x47, 0xc9, 0xe5, 0xcc, 0xec, 0xe2, 0xdd, 0x29,
                0xf5, 0xe4, 0x22, 0xc2, 0xe7, 0xbc, 0xd2
            ]
        );
        let meta = descriptor(&encoded, 5);
        let plain = verify(
            encoded.stored.clone(),
            &encoded.key,
            encoded.hash,
            &meta,
            limits(),
        )
        .unwrap();
        assert_eq!(&*plain, b"hello");

        // Without bit 4 the reader expects the plain BLAKE3 digest instead.
        let mut convergent = meta.clone();
        convergent.flags.set_unique_key(false);
        assert!(matches!(
            verify(
                encoded.stored,
                &encoded.key,
                encoded.hash,
                &convergent,
                limits()
            ),
            Err(PithosError::BlockHashMismatch { .. })
        ));
    }

    #[test]
    fn aes_256_gcm_vector_matches_the_specification() {
        let nonce = std::array::from_fn(|index| 0xb0 + index as u8);
        let key = crypto::derive_block_key(b"hello");
        let encoded = encode_with_key(b"hello", ProcessingFlags(0x28), key, nonce).unwrap();
        // PV-AES-GCM-HELLO in Appendix B.
        assert_eq!(encoded.hash, crypto::block_hash(b"hello"));
        assert_eq!(
            &encoded.stored[12..],
            [
                0x37, 0x8d, 0x6e, 0x4e, 0x73, 0xd7, 0xd5, 0xba, 0x27, 0x60, 0x8f, 0xef, 0x88, 0xed,
                0x83, 0x96, 0x88, 0x2e, 0x54, 0xd5, 0xcd
            ]
        );
        let meta = descriptor(&encoded, 5);
        let plain = verify(
            encoded.stored.clone(),
            &encoded.key,
            encoded.hash,
            &meta,
            limits(),
        )
        .unwrap();
        assert_eq!(&*plain, b"hello");

        // The same key opens neither cipher's payload as the other.
        let mut chacha = meta.clone();
        chacha.flags.set_aes_256_gcm(false);
        assert!(matches!(
            verify(
                encoded.stored,
                &encoded.key,
                encoded.hash,
                &chacha,
                limits()
            ),
            Err(PithosError::Crypt(_))
        ));
        assert!(matches!(
            encode(b"hello", ProcessingFlags(0x20), [0; 12]),
            Err(PithosError::ProcessingRequiresEncryption(0x20))
        ));
    }

    #[test]
    fn unique_keys_and_aes_256_gcm_combine() {
        let plain = b"unique key sealed with AES-256-GCM";
        let mut flags = unique_flags(0);
        flags.set_aes_256_gcm(true);
        let encoded = encode(plain, flags, [3; 12]).unwrap();
        assert_eq!(encoded.flags.0, 0x38);
        assert_eq!(encoded.hash, crypto::keyed_block_hash(&encoded.key, plain));
        let meta = descriptor(&encoded, plain.len());
        let output = verify(
            encoded.stored.clone(),
            &encoded.key,
            encoded.hash,
            &meta,
            limits(),
        )
        .unwrap();
        assert_eq!(&*output, plain);
        let mut corrupt = encoded.stored;
        corrupt[20] ^= 1;
        assert!(matches!(
            verify(corrupt, &encoded.key, encoded.hash, &meta, limits()),
            Err(PithosError::Crypt(_))
        ));
    }

    #[test]
    fn every_unique_key_encoding_has_a_fresh_key_and_identity() {
        let plain = b"the same plaintext block";
        let first = encode(plain, unique_flags(3), [1; 12]).unwrap();
        let second = encode(plain, unique_flags(3), [1; 12]).unwrap();
        assert_ne!(
            first.key.expose_for_protocol(),
            second.key.expose_for_protocol()
        );
        assert_ne!(first.hash, second.hash);
        assert_ne!(first.hash, crypto::block_hash(plain));
        let meta = descriptor(&second, plain.len());
        assert!(matches!(
            verify(
                second.stored.clone(),
                &first.key,
                second.hash,
                &meta,
                limits()
            ),
            Err(PithosError::Crypt(_))
        ));
        assert!(matches!(
            verify(second.stored, &second.key, first.hash, &meta, limits()),
            Err(PithosError::BlockHashMismatch { .. })
        ));
        assert!(matches!(
            encode(plain, ProcessingFlags(0x10), [0; 12]),
            Err(PithosError::ProcessingRequiresEncryption(0x10))
        ));
    }

    #[test]
    fn corruption_never_returns_unverified_plaintext() {
        let plain = b"compressible ".repeat(1024);
        let encoded = encode(&plain, ProcessingFlags::new(true, Some(3)), [9; 12]).unwrap();
        let meta = descriptor(&encoded, plain.len());
        for byte in [0, 12, encoded.stored.len() - 1] {
            let mut corrupt = encoded.stored.clone();
            corrupt[byte] ^= 1;
            assert!(
                verify(
                    corrupt,
                    &BlockKey::from_bytes(*encoded.key.expose_for_protocol()),
                    encoded.hash,
                    &meta,
                    Limits {
                        max_stored_bytes: 1024 * 1024,
                        max_decoded_bytes: 1024 * 1024
                    },
                )
                .is_err()
            );
        }
        let compressed = encode(&plain, ProcessingFlags::new(false, Some(3)), [0; 12]).unwrap();
        let compressed_meta = descriptor(&compressed, plain.len());
        let mut corrupt_compressed = compressed.stored.clone();
        corrupt_compressed[0] ^= 1;
        assert!(
            verify(
                corrupt_compressed,
                &compressed.key,
                compressed.hash,
                &compressed_meta,
                Limits {
                    max_stored_bytes: 1024 * 1024,
                    max_decoded_bytes: 1024 * 1024
                },
            )
            .is_err()
        );
        let mut wrong_size = meta.clone();
        wrong_size.original_size -= 1;
        assert!(
            verify(
                encoded.stored.clone(),
                &BlockKey::from_bytes(*encoded.key.expose_for_protocol()),
                encoded.hash,
                &wrong_size,
                Limits {
                    max_stored_bytes: 1024 * 1024,
                    max_decoded_bytes: 1024 * 1024
                },
            )
            .is_err()
        );
        assert!(
            verify(
                encoded.stored,
                &encoded.key,
                [0; 32],
                &meta,
                Limits {
                    max_stored_bytes: 1024 * 1024,
                    max_decoded_bytes: 1024 * 1024
                },
            )
            .is_err()
        );
    }
}
