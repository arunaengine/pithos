//! Narrow byte-oriented entry points for standalone fuzzing.
//!
//! This module is feature-gated so normal library consumers cannot depend on
//! raw format parsing as an API.

use crate::archive::{Archive, OpenOptions};
use crate::error::PithosError;
use crate::format::limits::DeserializationLimits;
use crate::source::MemorySource;
use std::io::Cursor;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FuzzErrorCategory {
    Archive,
    Authentication,
    Deserialization,
    Limit,
    Source,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FuzzOutcome {
    Accepted,
    Rejected(FuzzErrorCategory),
}

pub fn decode_header(data: &[u8]) -> FuzzOutcome {
    match crate::format::header::decode_header(&mut Cursor::new(data)) {
        Ok(_) => FuzzOutcome::Accepted,
        Err(_) => FuzzOutcome::Rejected(FuzzErrorCategory::Deserialization),
    }
}

pub fn decode_directory(data: &[u8]) -> FuzzOutcome {
    let limits = DeserializationLimits::default();
    let mut remaining_block_references = limits.max_block_references;
    match crate::archive::decode_validated_directory(data, &limits, &mut remaining_block_references)
    {
        Ok(_) => FuzzOutcome::Accepted,
        Err(error) => FuzzOutcome::Rejected(classify_archive_error(&error)),
    }
}

pub fn validate_archive(data: &[u8]) -> FuzzOutcome {
    match Archive::open(
        MemorySource::new(Arc::<[u8]>::from(data)),
        OpenOptions::default(),
    ) {
        Ok(_) => FuzzOutcome::Accepted,
        Err(error) => FuzzOutcome::Rejected(classify_archive_error(&error)),
    }
}

/// Exercises the private Crypt4GH header parser without exposing its records.
pub fn decode_crypt4gh_header(data: &[u8]) -> FuzzOutcome {
    match crate::adapters::crypt4gh::Crypt4GHHeader::try_from(data) {
        Ok(_) => FuzzOutcome::Accepted,
        Err(_) => FuzzOutcome::Rejected(FuzzErrorCategory::Deserialization),
    }
}

fn classify_archive_error(error: &PithosError) -> FuzzErrorCategory {
    match error {
        PithosError::Crypt(_) => FuzzErrorCategory::Authentication,
        PithosError::Deserialization(_) => FuzzErrorCategory::Deserialization,
        PithosError::LimitExceeded { .. } | PithosError::AllocationFailed { .. } => {
            FuzzErrorCategory::Limit
        }
        PithosError::Source(_) => FuzzErrorCategory::Source,
        _ => FuzzErrorCategory::Archive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_DIRECTORY: [u8; 25] = [
        0x50, 0x49, 0x54, 0x48, 0x4f, 0x53, 0x44, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xb1, 0x67, 0x40, 0x81,
    ];

    #[test]
    fn directory_fuzz_boundary_validates_complete_framing() {
        assert_eq!(decode_directory(&MINIMAL_DIRECTORY), FuzzOutcome::Accepted);
        let mut corrupt_crc = MINIMAL_DIRECTORY;
        *corrupt_crc.last_mut().unwrap() ^= 1;
        assert!(matches!(
            decode_directory(&corrupt_crc),
            FuzzOutcome::Rejected(FuzzErrorCategory::Archive)
        ));
        assert!(matches!(
            decode_directory(&MINIMAL_DIRECTORY[..MINIMAL_DIRECTORY.len() - 12]),
            FuzzOutcome::Rejected(FuzzErrorCategory::Archive)
        ));
    }
}
