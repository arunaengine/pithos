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

pub fn encode(
    plaintext: &[u8],
    requested_flags: ProcessingFlags,
    nonce: [u8; 12],
) -> Result<EncodedBlock, PithosError> {
    let hash = crypto::block_hash(plaintext);
    let key = crypto::derive_block_key(plaintext);
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
    if flags.is_encrypted() {
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
    let mut plaintext = if meta.flags.is_encrypted() {
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
    let actual_hash = crypto::block_hash(&plaintext);
    if actual_hash != expected_hash {
        return Err(PithosError::BlockHashMismatch {
            expected: expected_hash,
            actual: actual_hash,
        });
    }
    Ok(plaintext)
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
