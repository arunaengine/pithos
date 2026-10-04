//! Validated, immutable archive state.
//!
//! This module deliberately has no filesystem, adapter, or writer-input
//! dependency. `Archive` is the public reader boundary; internal format types and
//! recovered access material remain crate-private.

mod access;
mod append;
#[cfg(feature = "async")]
mod async_reader;
#[cfg(feature = "async")]
mod async_stream;
mod content_tree;
mod index;
mod opener;
mod path_validation;
mod pieces;
mod planning;
mod reader;
#[cfg(test)]
mod reader_private_tests;
mod snapshot;
mod types;
mod validation;
mod view;
mod writer;

pub(crate) use access::{AccessProvenance, ResolvedAccess};
pub use append::{AppendDurability, AppendObservation, AppendOptions};
#[cfg(feature = "async")]
pub use async_reader::{AsyncArchive, AsyncExternalBlockResolver, BlockingHook, InlineBlocking};
#[cfg(feature = "async")]
pub use async_stream::{OwnedRangeStream, RangeStream, ReadLimits};
pub use opener::{ArchiveOpener, ReadRequest};
pub(crate) use path_validation::{
    validate_directory_entries, validate_new_candidate, validate_symlink_target,
};
pub use pieces::{Composition, Piece, PieceEncoder, compose};
pub use planning::{
    BlockBatch, BlockBatches, BlockRequest, MAX_BATCH_BLOCKS, PlannedBlock, ReadPlan,
};
#[cfg(feature = "crypt4gh")]
pub(crate) use reader::ContentOperationError;
pub use reader::{
    AccessKeys, Archive, ArchiveEntry, ArchiveFeature, ArchiveReference, EntryKind,
    ExternalBlockAccessPolicy, ExternalBlockResolver, NoExternalBlocks, OpenLimits, OpenOptions,
};
pub(crate) use snapshot::AppendSnapshot;
pub use types::{ArchivePath, ExternalLocation};
pub(crate) use types::{FileId, Span};
pub(crate) use validation::validated_segment_from_directory;
pub use view::ArchiveView;

/// The metadata digest: BLAKE3 over each directory's BLAKE3 hash, from base to terminal.
pub(crate) fn metadata_digest(directory_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for hash in directory_hashes {
        hasher.update(hash);
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn decode_validated_directory(
    bytes: &[u8],
    limits: &crate::format::limits::DeserializationLimits,
    remaining_block_references: &mut u64,
    blocks: &mut impl crate::format::directory::BlockSink,
) -> Result<crate::format::directory::Directory, crate::error::PithosError> {
    crate::format::directory::decode_complete_directory_with_validation_and_budget(
        bytes,
        limits,
        remaining_block_references,
        blocks,
        |directory| validate_directory_entries(&directory.files),
    )
}
pub use writer::{
    ArchiveWriter, BlockKeyMode, CdcConfig, Chunking, CreateError, EntryMetadata, EntryReference,
    FinishError, IncompleteWriter, PayloadCipher, ProcessingOptions, WriteOptions, WriterError,
    WrittenEntry,
};

#[cfg(test)]
mod tests {
    use super::access::{AccessProvenance, ResolvedAccess};
    use super::index::{self, build_effective_index};
    use super::planning::{BlockBatch, BlockRequest, PlannedBlock, ReadPlan};
    use super::types::*;
    use super::validation::IndexLimits;
    use crate::error::PithosError;
    use crate::format::header::FormatVersion;
    use proptest::prelude::*;
    use std::sync::Arc;

    fn metadata() -> EntryMetadata {
        EntryMetadata {
            created: 1,
            modified: 2,
            permissions: 0o644,
            references: Vec::new(),
        }
    }

    fn descriptor(size: u64) -> BlockDescriptor {
        BlockDescriptor {
            stored_size: size,
            original_size: size,
            processing: Processing::from_byte(0, FormatVersion::V1_1).unwrap(),
            location: BlockLocation::External(ExternalLocation::new("opaque")),
        }
    }

    fn test_limits() -> crate::block::Limits {
        crate::block::Limits {
            max_stored_bytes: 1024,
            max_decoded_bytes: 1024,
        }
    }

    fn local_descriptor(span: Span) -> BlockDescriptor {
        BlockDescriptor {
            stored_size: span.len().saturating_sub(4),
            original_size: 1,
            processing: Processing::from_byte(0, FormatVersion::V1_1).unwrap(),
            location: BlockLocation::Local(span),
        }
    }

    fn segment(entries: Vec<SegmentEntry>) -> ValidatedSegment {
        segment_at(100, None, entries)
    }

    fn segment_at(
        start: u64,
        parent: Option<Span>,
        entries: Vec<SegmentEntry>,
    ) -> ValidatedSegment {
        ValidatedSegment {
            span: Span::new(start, 10).unwrap(),
            parent,
            entries,
            descriptors: Vec::new(),
            relationships: Vec::new(),
            recipient_pairs: Vec::new(),
        }
    }

    #[test]
    fn processing_flags_follow_the_version_and_encryption_rules() {
        for version in [FormatVersion::V1_0, FormatVersion::V1_1] {
            assert_eq!(
                Processing::from_byte(0x0b, version).unwrap().to_byte(),
                0x0b
            );
            assert!(matches!(
                Processing::from_byte(0x40, version),
                Err(PithosError::ReservedProcessingBits(0x40))
            ));
        }
        for flags in [0x1b, 0x2b, 0x3b] {
            assert_eq!(
                Processing::from_byte(flags, FormatVersion::V1_1)
                    .unwrap()
                    .to_byte(),
                flags
            );
            assert!(matches!(
                Processing::from_byte(flags, FormatVersion::V1_0),
                Err(PithosError::UnsupportedProcessingFlags(actual)) if actual == flags
            ));
            let plain = flags & !0x08;
            assert!(matches!(
                Processing::from_byte(plain, FormatVersion::V1_1),
                Err(PithosError::ProcessingRequiresEncryption(actual)) if actual == plain
            ));
        }
    }

    #[test]
    fn index_preserves_segment_entry_order_and_component_hierarchy() {
        let entries = vec![
            SegmentEntry {
                id: FileId(7),
                path: ArchivePath::new("a!").unwrap(),
                entry: Entry::File(ContentEntry {
                    metadata: metadata(),
                    size: 0,
                    content: ContentState::Available(BlockReferences::new(Vec::new())),
                }),
            },
            SegmentEntry {
                id: FileId(3),
                path: ArchivePath::new("a").unwrap(),
                entry: Entry::Directory(metadata()),
            },
            SegmentEntry {
                id: FileId(4),
                path: ArchivePath::new("a/child").unwrap(),
                entry: Entry::File(ContentEntry {
                    metadata: metadata(),
                    size: 0,
                    content: ContentState::Available(BlockReferences::new(Vec::new())),
                }),
            },
        ];
        let index =
            build_effective_index(vec![segment(entries)], 1_000, IndexLimits::default()).unwrap();
        assert_eq!(
            index.entries().map(|entry| entry.id.0).collect::<Vec<_>>(),
            [7, 3, 4]
        );
        assert_eq!(
            index
                .hierarchy()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["a", "a/child", "a!"]
        );
        let path = ArchivePath::new("a/child").unwrap();
        assert_eq!(index.entry_at_path(&path).unwrap().id, FileId(4));
        assert_eq!(index.maximum_id(), Some(FileId(7)));
    }

    #[test]
    fn merge_is_pure_and_earliest_compatible_descriptor_wins() {
        let hash = BlockHash([9; 32]);
        let older = ValidatedSegment {
            span: Span::new(10, 5).unwrap(),
            parent: None,
            entries: Vec::new(),
            descriptors: vec![(hash, descriptor(4))],
            relationships: Vec::new(),
            recipient_pairs: Vec::new(),
        };
        let mut newer_descriptor = descriptor(4);
        newer_descriptor.stored_size = 99;
        let newer = ValidatedSegment {
            span: Span::new(20, 5).unwrap(),
            parent: Some(older.span),
            entries: Vec::new(),
            descriptors: vec![(hash, newer_descriptor)],
            relationships: Vec::new(),
            recipient_pairs: Vec::new(),
        };
        let older_before = older.clone();
        let newer_before = newer.clone();
        let index = build_effective_index(
            vec![older.clone(), newer.clone()],
            1_000,
            IndexLimits::default(),
        )
        .unwrap();
        assert_eq!(index.descriptor(hash).unwrap().stored_size, 4);
        assert_eq!(older, older_before);
        assert_eq!(newer, newer_before);

        let mut conflicting = newer.clone();
        conflicting.descriptors[0].1.original_size = 5;
        let conflicting_before = conflicting.clone();
        assert!(
            build_effective_index(
                vec![older.clone(), conflicting.clone()],
                1_000,
                IndexLimits::default()
            )
            .is_err()
        );
        assert_eq!(older, older_before);
        assert_eq!(conflicting, conflicting_before);
    }

    #[test]
    fn non_winning_compatible_descriptors_do_not_impose_extent_checks() {
        let hash = BlockHash([9; 32]);
        let older = ValidatedSegment {
            span: Span::new(10, 5).unwrap(),
            parent: None,
            entries: Vec::new(),
            descriptors: vec![(hash, descriptor(4))],
            relationships: Vec::new(),
            recipient_pairs: Vec::new(),
        };
        for invalid_span in [Span::new(995, 10).unwrap(), Span::new(20, 5).unwrap()] {
            let mut later = descriptor(4);
            later.location = BlockLocation::Local(invalid_span);
            let newer = ValidatedSegment {
                span: Span::new(20, 5).unwrap(),
                parent: Some(older.span),
                entries: Vec::new(),
                descriptors: vec![(hash, later)],
                relationships: Vec::new(),
                recipient_pairs: Vec::new(),
            };

            let index =
                build_effective_index(vec![older.clone(), newer], 1_000, IndexLimits::default())
                    .unwrap();
            assert_eq!(index.descriptor(hash), Some(&older.descriptors[0].1));
        }
    }

    #[test]
    fn local_descriptors_must_stay_in_their_declaring_segment_region() {
        let cases = [
            (
                "base descriptor begins before the header ends",
                vec![ValidatedSegment {
                    span: Span::new(20, 10).unwrap(),
                    parent: None,
                    entries: Vec::new(),
                    descriptors: vec![(
                        BlockHash([1; 32]),
                        local_descriptor(Span::new(5, 4).unwrap()),
                    )],
                    relationships: Vec::new(),
                    recipient_pairs: Vec::new(),
                }],
            ),
            (
                "base descriptor extends into its directory",
                vec![ValidatedSegment {
                    span: Span::new(20, 10).unwrap(),
                    parent: None,
                    entries: Vec::new(),
                    descriptors: vec![(
                        BlockHash([1; 32]),
                        local_descriptor(Span::new(10, 11).unwrap()),
                    )],
                    relationships: Vec::new(),
                    recipient_pairs: Vec::new(),
                }],
            ),
            (
                "appended descriptor points into the base block region",
                vec![
                    segment_at(20, None, Vec::new()),
                    ValidatedSegment {
                        span: Span::new(60, 10).unwrap(),
                        parent: Some(Span::new(20, 10).unwrap()),
                        entries: Vec::new(),
                        descriptors: vec![(
                            BlockHash([1; 32]),
                            local_descriptor(Span::new(10, 4).unwrap()),
                        )],
                        relationships: Vec::new(),
                        recipient_pairs: Vec::new(),
                    },
                ],
            ),
            (
                "appended descriptor extends into its own directory",
                vec![
                    segment_at(20, None, Vec::new()),
                    ValidatedSegment {
                        span: Span::new(60, 10).unwrap(),
                        parent: Some(Span::new(20, 10).unwrap()),
                        entries: Vec::new(),
                        descriptors: vec![(
                            BlockHash([1; 32]),
                            local_descriptor(Span::new(50, 11).unwrap()),
                        )],
                        relationships: Vec::new(),
                        recipient_pairs: Vec::new(),
                    },
                ],
            ),
        ];

        for (case, segments) in cases {
            assert!(
                build_effective_index(segments, 100, IndexLimits::default()).is_err(),
                "accepted {case}"
            );
        }
    }

    #[test]
    fn overlapping_effective_local_descriptors_are_rejected() {
        let mut value = segment_at(30, None, Vec::new());
        value.descriptors = vec![
            (
                BlockHash([1; 32]),
                local_descriptor(Span::new(6, 10).unwrap()),
            ),
            (
                BlockHash([2; 32]),
                local_descriptor(Span::new(12, 10).unwrap()),
            ),
        ];

        assert!(build_effective_index(vec![value], 40, IndexLimits::default()).is_err());
    }

    #[test]
    fn adjacent_effective_local_descriptors_are_valid() {
        let first = Span::new(6, 10).unwrap();
        let second = Span::new(16, 14).unwrap();
        let mut value = segment_at(30, None, Vec::new());
        value.descriptors = vec![
            (BlockHash([1; 32]), local_descriptor(first)),
            (BlockHash([2; 32]), local_descriptor(second)),
        ];

        let index = build_effective_index(vec![value], 40, IndexLimits::default()).unwrap();
        assert_eq!(
            index.descriptor(BlockHash([1; 32])).unwrap().location,
            BlockLocation::Local(first)
        );
        assert_eq!(
            index.descriptor(BlockHash([2; 32])).unwrap().location,
            BlockLocation::Local(second)
        );
    }

    #[test]
    fn unavailable_content_is_visible_but_cannot_plan_reads() {
        let entry = SegmentEntry {
            id: FileId(1),
            path: ArchivePath::new("locked").unwrap(),
            entry: Entry::File(ContentEntry {
                metadata: metadata(),
                size: 10,
                content: ContentState::Unavailable,
            }),
        };
        let index =
            build_effective_index(vec![segment(vec![entry])], 1_000, IndexLimits::default())
                .unwrap();
        assert!(matches!(
            index.entry(FileId(1)).unwrap().entry,
            Entry::File(_)
        ));
        assert!(matches!(
            ReadPlan::new(
                &index,
                FileId(1),
                ReadRange::new(0..10, 10).unwrap(),
                test_limits()
            ),
            Err(crate::error::PithosError::ContentUnavailable)
        ));
    }

    #[test]
    fn plans_include_whole_intersecting_blocks_and_output_slices() {
        let first = BlockHash([1; 32]);
        let second = BlockHash([2; 32]);
        let mut value = segment(vec![SegmentEntry {
            id: FileId(1),
            path: ArchivePath::new("data").unwrap(),
            entry: Entry::File(ContentEntry {
                metadata: metadata(),
                size: 20,
                content: ContentState::Available(BlockReferences::new(vec![
                    first, second, second, first,
                ])),
            }),
        }]);
        value.descriptors = vec![(first, descriptor(4)), (second, descriptor(6))];
        let index = build_effective_index(vec![value], 1_000, IndexLimits::default()).unwrap();
        let range = ReadRange::new(3..7, 10).unwrap();
        let plan = ReadPlan::new(&index, FileId(1), range, test_limits())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].output(), 3..4);
        assert_eq!(plan[1].output(), 0..3);
    }

    /// One file over `count` contiguous local blocks of one plaintext byte, read in `order`.
    fn local_file(count: usize, order: &[usize]) -> index::ArchiveIndex {
        let hash = |block: usize| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(block as u64).to_be_bytes());
            BlockHash(bytes)
        };
        let start = 6 + 5 * count as u64;
        let mut value = segment_at(
            start,
            None,
            vec![SegmentEntry {
                id: FileId(1),
                path: ArchivePath::new("data").unwrap(),
                entry: Entry::File(ContentEntry {
                    metadata: metadata(),
                    size: order.len() as u64,
                    content: ContentState::Available(BlockReferences::new(
                        order.iter().map(|block| hash(*block)).collect(),
                    )),
                }),
            }],
        );
        value.descriptors = (0..count)
            .map(|block| {
                let span = Span::new(6 + 5 * block as u64, 5).unwrap();
                (hash(block), local_descriptor(span))
            })
            .collect();
        build_effective_index(vec![value], start + 10, IndexLimits::default()).unwrap()
    }

    #[test]
    fn plans_start_at_the_offset_checkpoint_before_the_range() {
        let index = local_file(1, &[0; 3_000]);
        for (start, first_position) in [(0, 0), (1_023, 0), (1_024, 1_024), (2_999, 2_048)] {
            let range = ReadRange::new(start..start + 1, 3_000).unwrap();
            let plan = ReadPlan::new(&index, FileId(1), range, test_limits()).unwrap();
            assert_eq!(plan.first_position, first_position);
            let blocks = plan.collect::<Result<Vec<_>, _>>().unwrap();
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0].position, start as usize);
        }
    }

    fn local_offsets(blocks: &[PlannedBlock]) -> Vec<u64> {
        blocks
            .iter()
            .map(|block| match block.request() {
                BlockRequest::Local { offset, len: 5 } => offset,
                request => panic!("unexpected request {request:?}"),
            })
            .collect()
    }

    #[test]
    fn lazy_plans_yield_only_the_blocks_of_a_range_over_many_blocks() {
        let count = 10_000;
        let index = local_file(count, &(0..count).collect::<Vec<_>>());
        let size = count as u64;
        let mut whole = ReadPlan::new(
            &index,
            FileId(1),
            ReadRange::new(0..size, size).unwrap(),
            test_limits(),
        )
        .unwrap();
        let first = whole.next().unwrap().unwrap();
        assert_eq!(local_offsets(&[first]), [6]);
        assert_eq!(whole.count(), count - 1);

        let range = ReadRange::new(4_000..4_003, size).unwrap();
        let blocks = ReadPlan::new(&index, FileId(1), range, test_limits())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(local_offsets(&blocks), [20_006, 20_011, 20_016]);
        assert!(blocks.iter().all(|block| block.output() == (0..1)));
        let empty = ReadRange::new(5..5, size).unwrap();
        assert_eq!(
            ReadPlan::new(&index, FileId(1), empty, test_limits())
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn plans_check_block_limits_before_yielding_a_block() {
        let index = local_file(3, &[0, 1, 2]);
        let limits = crate::block::Limits {
            max_stored_bytes: 0,
            max_decoded_bytes: 1024,
        };
        let range = ReadRange::new(1..3, 3).unwrap();
        let mut plan = ReadPlan::new(&index, FileId(1), range, limits).unwrap();
        assert!(matches!(
            plan.next(),
            Some(Err(PithosError::LimitExceeded {
                field: "stored block",
                ..
            }))
        ));
        assert!(plan.next().is_none());
    }

    #[test]
    fn batches_join_contiguous_local_spans_up_to_the_byte_bound() {
        let index = local_file(5, &[0, 1, 2, 3, 4]);
        let range = ReadRange::new(0..5, 5).unwrap();
        let plan = ReadPlan::new(&index, FileId(1), range, test_limits()).unwrap();
        let batches = plan.batches(12).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(
            batches.iter().map(BlockBatch::request).collect::<Vec<_>>(),
            [
                BlockRequest::Local { offset: 6, len: 10 },
                BlockRequest::Local {
                    offset: 16,
                    len: 10
                },
                BlockRequest::Local { offset: 26, len: 5 },
            ]
        );
        let response = (0..10).collect::<Vec<u8>>();
        let parts = batches[0].split(&response).unwrap().collect::<Vec<_>>();
        assert_eq!(parts[0].1, &response[..5]);
        assert_eq!(parts[1].1, &response[5..]);
        assert_eq!(parts[1].0, &batches[0].blocks()[1]);
        assert!(matches!(
            batches[0].split(&response[1..]),
            Err(PithosError::BlockSizeMismatch {
                expected: 10,
                actual: 9
            })
        ));
        let single = ReadPlan::new(&index, FileId(1), range, test_limits()).unwrap();
        assert_eq!(single.batches(4).count(), 5);
    }

    #[test]
    fn shared_blocks_keep_file_order_and_only_join_contiguous_spans() {
        let index = local_file(3, &[2, 0, 1, 2, 2]);
        let range = ReadRange::new(0..5, 5).unwrap();
        let blocks = ReadPlan::new(&index, FileId(1), range, test_limits())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(local_offsets(&blocks), [16, 6, 11, 16, 16]);
        let plan = ReadPlan::new(&index, FileId(1), range, test_limits()).unwrap();
        let batches = plan
            .batches(u64::MAX)
            .map(|batch| batch.unwrap().request())
            .collect::<Vec<_>>();
        // The last block repeats the span before it, so it joins that batch without a request.
        assert_eq!(
            batches,
            [
                BlockRequest::Local { offset: 16, len: 5 },
                BlockRequest::Local { offset: 6, len: 15 },
            ]
        );
    }

    #[test]
    fn external_blocks_join_a_batch_only_when_repeated() {
        let first = BlockHash([1; 32]);
        let second = BlockHash([2; 32]);
        let mut value = segment(vec![SegmentEntry {
            id: FileId(1),
            path: ArchivePath::new("data").unwrap(),
            entry: Entry::File(ContentEntry {
                metadata: metadata(),
                size: 20,
                content: ContentState::Available(BlockReferences::new(vec![
                    first, second, second, first,
                ])),
            }),
        }]);
        value.descriptors = vec![(first, descriptor(4)), (second, descriptor(6))];
        let index = build_effective_index(vec![value], 1_000, IndexLimits::default()).unwrap();
        let range = ReadRange::new(0..20, 20).unwrap();
        let plan = ReadPlan::new(&index, FileId(1), range, test_limits()).unwrap();
        let batches = plan
            .batches(u64::MAX)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let external = |len| BlockRequest::External {
            location: ExternalLocation::new("opaque"),
            len,
        };
        // Only the repeated block joins the batch before it; equal locations alone do not.
        assert_eq!(
            batches.iter().map(BlockBatch::request).collect::<Vec<_>>(),
            [external(8), external(10), external(8)]
        );
        assert_eq!(batches[1].blocks().len(), 2);
        let response = (0..10).collect::<Vec<u8>>();
        let parts = batches[1].split(&response).unwrap().collect::<Vec<_>>();
        assert!(parts.iter().all(|(_, stored)| *stored == &response[..]));
        assert!(batches[1].split(&[0; 20]).is_err());
    }

    #[test]
    fn resolved_access_rejects_conflicts_and_keeps_deterministic_provenance() {
        let mut access = ResolvedAccess::new();
        let later = AccessProvenance {
            segment: 2,
            recovery_order: 2,
            access_key: 0,
            sender_section: 0,
            recipient_section: 0,
        };
        let earlier = AccessProvenance {
            segment: 1,
            recovery_order: 1,
            access_key: 0,
            sender_section: 0,
            recipient_section: 0,
        };
        access.insert(FileId(2), &[3; 32], later).unwrap();
        access.insert(FileId(2), &[3; 32], earlier).unwrap();
        assert_eq!(
            access.key(FileId(2)).map(|key| key.expose_for_protocol()),
            Some(&[3; 32])
        );
        assert!(matches!(
            access.insert(FileId(2), &[4; 32], later),
            Err(crate::error::PithosError::ConflictingRecoveredFileKey)
        ));
    }

    proptest! {
        #[test]
        fn path_and_checked_range_properties(parts in proptest::collection::vec("[a-z]{1,8}", 1..8), start in 0u16..128, end in 0u16..128) {
            let path = parts.join("/");
            let validated = ArchivePath::new(&path).unwrap();
            prop_assert_eq!(validated.as_str(), path);
            let range = ReadRange::new(u64::from(start)..u64::from(end), 127);
            prop_assert_eq!(range.is_ok(), start <= end && end <= 127);
        }
    }

    #[test]
    fn checked_spans_reject_overflow_and_symlink_escape() {
        assert!(Span::new(u64::MAX, 1).is_err());
        assert!(ArchivePath::new("a//b").is_err());
        let link = SegmentEntry {
            id: FileId(0),
            path: ArchivePath::new("link").unwrap(),
            entry: Entry::Symlink {
                metadata: metadata(),
                target: Arc::from("../outside"),
            },
        };
        assert!(
            build_effective_index(vec![segment(vec![link])], 1_000, IndexLimits::default())
                .is_err()
        );
    }

    #[test]
    fn hierarchy_conflicts_are_order_independent_and_component_aware() {
        let file = || {
            Entry::File(ContentEntry {
                metadata: metadata(),
                size: 0,
                content: ContentState::Available(BlockReferences::new(Vec::new())),
            })
        };
        for reverse in [false, true] {
            let mut conflicting = vec![
                SegmentEntry {
                    id: FileId(1),
                    path: ArchivePath::new("a").unwrap(),
                    entry: file(),
                },
                SegmentEntry {
                    id: FileId(2),
                    path: ArchivePath::new("a/child").unwrap(),
                    entry: file(),
                },
            ];
            if reverse {
                conflicting.reverse();
            }
            assert!(
                build_effective_index(vec![segment(conflicting)], 1_000, IndexLimits::default())
                    .is_err()
            );
        }
        let adjacent = vec![
            SegmentEntry {
                id: FileId(1),
                path: ArchivePath::new("a").unwrap(),
                entry: file(),
            },
            SegmentEntry {
                id: FileId(2),
                path: ArchivePath::new("a!").unwrap(),
                entry: file(),
            },
        ];
        assert!(
            build_effective_index(vec![segment(adjacent)], 1_000, IndexLimits::default()).is_ok()
        );
    }

    #[test]
    fn hierarchy_requires_earlier_directory_ancestors_across_segments() {
        let directory = |id, path: &str| SegmentEntry {
            id: FileId(id),
            path: ArchivePath::new(path).unwrap(),
            entry: Entry::Directory(metadata()),
        };
        let file = |id, path: &str| SegmentEntry {
            id: FileId(id),
            path: ArchivePath::new(path).unwrap(),
            entry: Entry::File(ContentEntry {
                metadata: metadata(),
                size: 0,
                content: ContentState::Available(BlockReferences::new(Vec::new())),
            }),
        };

        for entries in [
            vec![file(1, "parent/child")],
            vec![file(1, "top/middle/child")],
            vec![file(1, "parent"), file(2, "parent/child")],
            vec![directory(2, "parent/child"), directory(1, "parent")],
        ] {
            assert!(
                build_effective_index(vec![segment(entries)], 1_000, IndexLimits::default())
                    .is_err()
            );
        }

        assert!(
            build_effective_index(
                vec![segment(vec![
                    directory(1, "parent"),
                    file(2, "parent/child"),
                ])],
                1_000,
                IndexLimits::default(),
            )
            .is_ok()
        );

        let base = segment_at(100, None, vec![directory(1, "parent")]);
        let child = segment_at(200, Some(base.span), vec![file(2, "parent/child")]);
        assert!(build_effective_index(vec![base, child], 1_000, IndexLimits::default()).is_ok());

        let early_child = segment_at(100, None, vec![file(2, "parent/child")]);
        let late_parent = segment_at(200, Some(early_child.span), vec![directory(1, "parent")]);
        assert!(
            build_effective_index(
                vec![early_child, late_parent],
                1_000,
                IndexLimits::default(),
            )
            .is_err()
        );
    }

    proptest! {
        #[test]
        fn component_ancestor_conflicts_ignore_adjacent_prefixes(
            prefix in "[a-z]{1,8}",
            child in "[a-z]{1,8}",
            reverse in any::<bool>(),
        ) {
            let file = || Entry::File(ContentEntry {
                metadata: metadata(),
                size: 0,
                content: ContentState::Available(BlockReferences::new(Vec::new())),
            });
            let mut conflicting = vec![
                SegmentEntry { id: FileId(1), path: ArchivePath::new(&prefix).unwrap(), entry: file() },
                SegmentEntry { id: FileId(2), path: ArchivePath::new(format!("{prefix}/{child}")).unwrap(), entry: file() },
            ];
            if reverse {
                conflicting.reverse();
            }
            prop_assert!(build_effective_index(vec![segment(conflicting)], 1_000, IndexLimits::default()).is_err());
            let adjacent = vec![
                SegmentEntry { id: FileId(1), path: ArchivePath::new(&prefix).unwrap(), entry: file() },
                SegmentEntry { id: FileId(2), path: ArchivePath::new(format!("{prefix}!")).unwrap(), entry: file() },
            ];
            prop_assert!(build_effective_index(vec![segment(adjacent)], 1_000, IndexLimits::default()).is_ok());
        }
    }
}
