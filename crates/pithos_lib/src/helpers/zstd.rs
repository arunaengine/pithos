use crate::model::structs::ProcessingFlags;
use thiserror::Error;
use zstd::bulk;

/// Custom error type for zstd compression operations
#[derive(Error, Debug)]
pub enum ZstdError {
    /// Invalid input data
    #[error("Invalid input data: {0}")]
    InvalidInput(String),
    /// Compression failure
    #[error("Compression error: {0}")]
    CompressionError(String),
    /// Compression failure
    #[error("Decompression error: {0}")]
    DecompressionError(String),
}

const ZSTD_MAGIC_NUMBER: u32 = 0xFD2FB528; // 4 Bytes, little-endian format

pub fn map_to_zstd_level(flags: &ProcessingFlags) -> i32 {
    match flags.get_compression_level() {
        1 => 1,
        2 => 4,
        3 => 8,
        4 => 11,
        5 => 15,
        6 => 18,
        7 => 22,
        _ => 22, // Everything above is just max compression
    }
}

/// Compresses a chunk of data with zstd and returns the compression ratio.
pub fn probe_compression_ratio(input: &[u8], level: Option<i32>) -> Result<f64, ZstdError> {
    let compressed = bulk::compress(input, level.unwrap_or_default())
        .map_err(|e| ZstdError::CompressionError(e.to_string()))?;
    let orig_len = input.len();
    let comp_len = compressed.len();

    Ok(if orig_len == 0 {
        1.0
    } else {
        comp_len as f64 / orig_len as f64
    })
}

pub fn compress_data(input: &[u8], level: Option<i32>) -> Result<Vec<u8>, ZstdError> {
    bulk::compress(input, level.unwrap_or_default())
        .map_err(|e| ZstdError::CompressionError(e.to_string()))
}

pub fn decompress_data(input: &[u8], decompressed_size: u64) -> Result<Vec<u8>, ZstdError> {
    bulk::decompress(input, decompressed_size as usize)
        .map_err(|e| ZstdError::DecompressionError(e.to_string()))
}
