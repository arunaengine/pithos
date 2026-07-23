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
    #[error("decompressed size does not fit platform: {0}")]
    SizeOverflow(u64),
}

const _ZSTD_MAGIC_NUMBER: u32 = 0xFD2FB528; // 4 Bytes, little-endian format

#[tracing::instrument(level = "trace", skip(flags))]
pub fn map_to_zstd_level(flags: &ProcessingFlags) -> i32 {
    match flags.get_compression_level() {
        0 => 0,
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
#[tracing::instrument(level = "trace", skip(input))]
pub fn probe_compression_ratio(input: &[u8], level: Option<i32>) -> Result<f64, ZstdError> {
    if input.is_empty() {
        return Ok(1.0);
    }

    let orig_len = input.len();
    let probe_size = if orig_len > 4096 { 4096 } else { orig_len };
    let compressed = if orig_len > 4096 {
        bulk::compress(&input[..probe_size], level.unwrap_or_default())
            .map_err(|e| ZstdError::CompressionError(e.to_string()))?
    } else {
        bulk::compress(input, level.unwrap_or_default())
            .map_err(|e| ZstdError::CompressionError(e.to_string()))?
    };

    Ok(compressed.len() as f64 / probe_size as f64)
}

#[tracing::instrument(level = "trace", skip(input, level))]
pub fn compress_data(input: &[u8], level: Option<i32>) -> Result<Vec<u8>, ZstdError> {
    bulk::compress(input, level.unwrap_or_default())
        .map_err(|e| ZstdError::CompressionError(e.to_string()))
}

#[tracing::instrument(level = "trace", skip(input, decompressed_size))]
pub fn decompress_data(input: &[u8], decompressed_size: u64) -> Result<Vec<u8>, ZstdError> {
    let size = usize::try_from(decompressed_size)
        .map_err(|_| ZstdError::SizeOverflow(decompressed_size))?;
    bulk::decompress(input, size).map_err(|e| ZstdError::DecompressionError(e.to_string()))
}
