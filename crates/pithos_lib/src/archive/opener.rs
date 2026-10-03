use super::access::ResolvedAccess;
use super::index::build_effective_index;
use super::reader::{
    AccessKeys, DecodedDirectoryCounts, OpenLimits, OpenOptions, classify_content_availability,
    remaining_deserialization_limits, resolve_block_lists, resolve_recipients,
    validate_directory_len, validate_piece_keys,
};
use super::types::{FileId, Span, ValidatedSegment};
use super::validation::IndexLimits;
use super::view::ArchiveView;
use super::{decode_validated_directory, validated_segment_from_directory};
use crate::error::PithosError;
use crate::format::directory::Directory;
use crate::format::header::{FileHeader, FormatVersion};
use std::collections::{HashMap, HashSet};

/// One exact byte range the opener needs next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    offset: u64,
    len: u64,
    sequence: u64,
}

impl ReadRequest {
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The open settings that matter for metadata. External resolution is a read-time concern.
pub(super) struct OpenSettings {
    pub(super) limits: OpenLimits,
    pub(super) keys: AccessKeys,
    pub(super) expected_metadata_digest: Option<[u8; 32]>,
    pub(super) external_enabled: bool,
}

/// Opens an archive without performing I/O.
///
/// The opener hands out one read request at a time: the header, the footer, then each
/// directory from the terminal one back to the base. The caller reads exactly the requested
/// bytes and passes them to [`ArchiveOpener::feed`]. Limits are checked before a request is
/// issued. Opening validates metadata only; block markers are checked when a block is read.
///
/// ```no_run
/// # fn read(offset: u64, len: u64) -> Vec<u8> { unimplemented!() }
/// # fn main() -> Result<(), pithos_lib::error::PithosError> {
/// use pithos_lib::archive::{ArchiveOpener, OpenOptions};
///
/// let mut opener = ArchiveOpener::new(4096, OpenOptions::default())?;
/// while let Some(request) = opener.request() {
///     let bytes = read(request.offset(), request.len());
///     opener.feed(request, &bytes)?;
/// }
/// let view = opener.finish()?;
/// # let _ = view;
/// # Ok(())
/// # }
/// ```
pub struct ArchiveOpener {
    archive_len: u64,
    settings: OpenSettings,
    next_sequence: u64,
    pending: Option<ReadRequest>,
    phase: Phase,
}

enum Phase {
    Header,
    Footer(FormatVersion),
    Directories(Box<Chain>),
    Opened(Box<ArchiveView>),
    Failed,
}

/// Directories decoded so far, from the terminal one back toward the base.
struct DecodedChain {
    version: FormatVersion,
    terminal: Span,
    raw: Vec<(Directory, Span)>,
    remaining_block_references: u64,
    directory_hashes: Vec<[u8; 32]>,
}

/// A decoded chain plus the bookkeeping for the next directory request.
struct Chain {
    decoded_chain: DecodedChain,
    pending: Span,
    total_directory_bytes: u64,
    child_start: u64,
    visited: HashSet<Span>,
    decoded: DecodedDirectoryCounts,
}

impl ArchiveOpener {
    /// Starts opening an archive of `archive_len` bytes. Only the keys, limits and expected
    /// metadata digest of `options` are used, plus whether external resolution is enabled.
    pub fn new<E>(archive_len: u64, options: OpenOptions<E>) -> Result<Self, PithosError> {
        let (settings, _, _) = options.into_parts();
        Self::with_settings(archive_len, settings)
    }

    pub(super) fn with_settings(
        archive_len: u64,
        settings: OpenSettings,
    ) -> Result<Self, PithosError> {
        if archive_len < FileHeader::ENCODED_LEN as u64 {
            return Err(PithosError::InvalidDirectoryRange {
                operation: "read file header",
            });
        }
        let mut opener = Self {
            archive_len,
            settings,
            next_sequence: 0,
            pending: None,
            phase: Phase::Header,
        };
        opener.issue(0, FileHeader::ENCODED_LEN as u64);
        Ok(opener)
    }

    /// The outstanding request, or `None` once the archive is opened or opening failed.
    pub fn request(&self) -> Option<ReadRequest> {
        self.pending
    }

    /// Accepts the bytes for the outstanding request.
    ///
    /// A response to another request or of the wrong length is rejected and the request stays
    /// outstanding. Any other error ends the open.
    pub fn feed(&mut self, request: ReadRequest, response: &[u8]) -> Result<(), PithosError> {
        if self.pending != Some(request) {
            return Err(PithosError::UnexpectedReadResponse);
        }
        if response.len() as u64 != request.len {
            return Err(PithosError::ReadResponseLength {
                expected: request.len,
                actual: response.len() as u64,
            });
        }
        self.pending = None;
        let phase = std::mem::replace(&mut self.phase, Phase::Failed);
        match self.advance(phase, response) {
            Ok(phase) => {
                self.phase = phase;
                Ok(())
            }
            Err(error) => {
                self.pending = None;
                Err(error)
            }
        }
    }

    /// Returns the opened view once every request has been answered.
    pub fn finish(self) -> Result<ArchiveView, PithosError> {
        match self.phase {
            Phase::Opened(view) => Ok(*view),
            _ => Err(PithosError::OpenIncomplete),
        }
    }

    fn issue(&mut self, offset: u64, len: u64) {
        self.pending = Some(ReadRequest {
            offset,
            len,
            sequence: self.next_sequence,
        });
        self.next_sequence += 1;
    }

    fn advance(&mut self, phase: Phase, response: &[u8]) -> Result<Phase, PithosError> {
        match phase {
            Phase::Header => {
                let header = crate::format::header::decode_header(&mut &response[..])?;
                let version = FormatVersion::from_wire(header.version).ok_or(
                    PithosError::UnsupportedFileVersion {
                        supported: FormatVersion::CURRENT.wire(),
                        actual: header.version,
                    },
                )?;
                let footer =
                    self.archive_len
                        .checked_sub(12)
                        .ok_or(PithosError::InvalidDirectoryRange {
                            operation: "read directory footer",
                        })?;
                self.issue(footer, 12);
                Ok(Phase::Footer(version))
            }
            Phase::Footer(version) => {
                let len = u64::from_be_bytes(response[..8].try_into().expect("12-byte footer"));
                validate_directory_len(len, self.settings.limits)?;
                let start = self.archive_len.checked_sub(len).ok_or(
                    PithosError::InvalidDirectoryRange {
                        operation: "validate terminal directory",
                    },
                )?;
                let terminal = Span::new(start, len)?;
                let mut chain = Box::new(Chain {
                    decoded_chain: DecodedChain {
                        version,
                        terminal,
                        raw: Vec::new(),
                        remaining_block_references: self
                            .settings
                            .limits
                            .max_accessible_block_references,
                        directory_hashes: Vec::new(),
                    },
                    pending: terminal,
                    total_directory_bytes: 0,
                    child_start: self.archive_len,
                    visited: HashSet::new(),
                    decoded: DecodedDirectoryCounts::default(),
                });
                chain.admit(terminal, self.settings.limits)?;
                self.issue(start, len);
                Ok(Phase::Directories(chain))
            }
            Phase::Directories(mut chain) => {
                let limits = remaining_deserialization_limits(self.settings.limits, &chain.decoded);
                let decoded_chain = &mut chain.decoded_chain;
                let hash = blake3::hash(response);
                decoded_chain.directory_hashes.push(*hash.as_bytes());
                let directory = decode_validated_directory(
                    response,
                    &limits,
                    &mut decoded_chain.remaining_block_references,
                )?;
                let next = directory.parent_directory_offset;
                let span = chain.pending;
                chain.decoded.record(&directory);
                chain.decoded_chain.raw.push((directory, span));
                chain.child_start = span.start();
                match next {
                    Some((start, len)) => {
                        let span = Span::new(start, len)?;
                        chain.admit(span, self.settings.limits)?;
                        self.issue(start, len);
                        Ok(Phase::Directories(chain))
                    }
                    None => {
                        let view = complete_open(
                            self.archive_len,
                            &mut self.settings,
                            chain.decoded_chain,
                        )?;
                        Ok(Phase::Opened(Box::new(view)))
                    }
                }
            }
            Phase::Opened(_) | Phase::Failed => Err(PithosError::UnexpectedReadResponse),
        }
    }
}

impl Chain {
    /// Checks a directory against the chain rules and limits before it is requested.
    fn admit(&mut self, span: Span, limits: OpenLimits) -> Result<(), PithosError> {
        validate_directory_len(span.len(), limits)?;
        if self.decoded_chain.raw.len() as u64 > limits.max_parent_directories {
            return Err(PithosError::LimitExceeded {
                field: "parent directories",
                limit: limits.max_parent_directories,
                actual: self.decoded_chain.raw.len() as u64,
            });
        }
        if span.end() > self.child_start || !self.visited.insert(span) {
            return Err(PithosError::InvalidDirectoryChain {
                operation: "validate parent ordering",
            });
        }
        self.total_directory_bytes = self.total_directory_bytes.checked_add(span.len()).ok_or(
            PithosError::LimitExceeded {
                field: "total directory bytes",
                limit: limits.max_total_directory_bytes,
                actual: u64::MAX,
            },
        )?;
        if self.total_directory_bytes > limits.max_total_directory_bytes {
            return Err(PithosError::LimitExceeded {
                field: "total directory bytes",
                limit: limits.max_total_directory_bytes,
                actual: self.total_directory_bytes,
            });
        }
        self.pending = span;
        Ok(())
    }
}

/// Runs every metadata check after the whole chain is decoded and builds the view.
fn complete_open(
    archive_len: u64,
    settings: &mut OpenSettings,
    chain: DecodedChain,
) -> Result<ArchiveView, PithosError> {
    let DecodedChain {
        version,
        terminal,
        mut raw,
        mut remaining_block_references,
        mut directory_hashes,
    } = chain;
    let limits = settings.limits;
    raw.reverse();
    directory_hashes.reverse();
    let metadata_digest = crate::archive::metadata_digest(&directory_hashes);
    if settings
        .expected_metadata_digest
        .is_some_and(|expected| expected != metadata_digest)
    {
        return Err(PithosError::MetadataDigestMismatch);
    }
    let maximum_piece_key = validate_piece_keys(version, &raw)?;

    let mut first_grants = HashMap::new();
    for (directory, _) in &raw {
        for (sender, section) in &directory.encryption {
            for (recipient, recipient_section) in &section.recipients {
                let pair = (*sender, *recipient);
                if let Some(first) = first_grants.get(&pair)
                    && *first != &recipient_section.recipient_data
                {
                    return Err(PithosError::ConflictingRecipientGrant);
                }
                first_grants
                    .entry(pair)
                    .or_insert(&recipient_section.recipient_data);
            }
        }
    }

    let mut access = ResolvedAccess::new();
    let mut recovery_order = 0usize;
    for (segment, (directory, _)) in raw.iter().enumerate() {
        resolve_recipients(
            version,
            directory,
            &settings.keys,
            segment,
            &mut recovery_order,
            &mut access,
            limits,
        )?;
    }

    let mut segments: Vec<ValidatedSegment> = Vec::new();
    for (segment_index, (directory, span)) in raw.into_iter().enumerate() {
        let mut directory = directory;
        resolve_block_lists(
            &mut directory,
            &mut access,
            &mut remaining_block_references,
            limits,
        )?;
        let parent = segment_index
            .checked_sub(1)
            .map(|index| segments[index].span);
        segments.push(validated_segment_from_directory(
            version, &directory, span, parent,
        )?);
    }
    let index_limits = IndexLimits {
        max_entries: limits.max_entries,
        max_descriptors: limits.max_descriptors,
        max_references: limits.max_references,
        max_relationships: limits.max_relationships,
        max_segments: limits.max_parent_directories.saturating_add(1),
    };
    let mut index = build_effective_index(&segments, archive_len, index_limits)?;
    index.cover_piece_keys(maximum_piece_key.map(FileId));
    let content_availability = classify_content_availability(&index, settings.external_enabled)?;
    Ok(ArchiveView {
        archive_len,
        version,
        metadata_digest,
        terminal_directory: terminal,
        index,
        segments,
        index_limits,
        access,
        #[cfg(feature = "crypt4gh")]
        access_keys: std::mem::take(&mut settings.keys),
        limits,
        content_availability,
    })
}
