//! Validated, immutable archive state.
//!
//! This module deliberately has no filesystem, adapter, or writer-input
//! dependency. `Archive` is the public reader boundary; wire records and
//! recovered access material remain crate-private.

mod access;
mod append;
mod index;
mod path_validation;
mod planning;
mod reader;
#[cfg(test)]
mod reader_private_tests;
mod snapshot;
mod types;
mod validation;
mod writer;

pub(crate) use access::{AccessProvenance, ResolvedAccess};
pub use append::{AppendDurability, AppendObservation, AppendOptions};
pub(crate) use index::build_effective_index;
pub(crate) use path_validation::{
    validate_new_candidate, validate_symlink_target, validate_wire_map,
};
pub(crate) use reader::ContentOperationError;
pub use reader::{
    AccessKeys, Archive, ArchiveEntry, ArchiveReference, EntryKind, ExternalBlockResolver,
    NoExternalBlocks, OpenLimits, OpenOptions,
};
pub(crate) use snapshot::AppendSnapshot;
pub use types::{ArchivePath, ExternalLocation};
pub(crate) use types::{FileId, Span};
pub(crate) use validation::segment_from_wire;
pub use writer::{
    ArchiveWriter, CdcConfig, CreateError, EntryMetadata, EntryReference, FinishError,
    IncompleteWriter, ProcessingOptions, WriteOptions, WriterError, WrittenEntry,
};

#[cfg(test)]
mod tests {
    use super::access::{AccessProvenance, ResolvedAccess};
    use super::index::build_effective_index;
    use super::types::*;
    use super::validation::IndexLimits;
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
            processing: Processing::from_byte(0).unwrap(),
            location: BlockLocation::External(ExternalLocation::new("opaque")),
        }
    }

    fn local_descriptor(span: Span) -> BlockDescriptor {
        BlockDescriptor {
            stored_size: span.len().saturating_sub(4),
            original_size: 1,
            processing: Processing::from_byte(0).unwrap(),
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
        }
    }

    #[test]
    fn index_preserves_wire_order_and_component_hierarchy() {
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
            build_effective_index(&[segment(entries)], 1_000, IndexLimits::default()).unwrap();
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
        };
        let mut newer_descriptor = descriptor(4);
        newer_descriptor.stored_size = 99;
        let newer = ValidatedSegment {
            span: Span::new(20, 5).unwrap(),
            parent: Some(older.span),
            entries: Vec::new(),
            descriptors: vec![(hash, newer_descriptor)],
            relationships: Vec::new(),
        };
        let older_before = older.clone();
        let newer_before = newer.clone();
        let index = build_effective_index(
            &[older.clone(), newer.clone()],
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
                &[older.clone(), conflicting.clone()],
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
            };

            let index =
                build_effective_index(&[older.clone(), newer], 1_000, IndexLimits::default())
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
                    },
                ],
            ),
        ];

        for (case, segments) in cases {
            assert!(
                build_effective_index(&segments, 100, IndexLimits::default()).is_err(),
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

        assert!(build_effective_index(&[value], 40, IndexLimits::default()).is_err());
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

        let index = build_effective_index(&[value], 40, IndexLimits::default()).unwrap();
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
            build_effective_index(&[segment(vec![entry])], 1_000, IndexLimits::default()).unwrap();
        assert!(matches!(
            index.entry(FileId(1)).unwrap().entry,
            Entry::File(_)
        ));
        assert!(matches!(
            index.full_file_plan(FileId(1)),
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
                size: 10,
                content: ContentState::Available(BlockReferences::new(vec![first, second])),
            }),
        }]);
        value.descriptors = vec![(first, descriptor(4)), (second, descriptor(6))];
        let index = build_effective_index(&[value], 1_000, IndexLimits::default()).unwrap();
        let range = ReadRange::new(3..7, 10).unwrap();
        let plan = index.range_plan(FileId(1), range).unwrap();
        assert_eq!(plan.blocks.len(), 2);
        assert_eq!(plan.blocks[0].output, 3..4);
        assert_eq!(plan.blocks[1].output, 0..3);
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
            build_effective_index(&[segment(vec![link])], 1_000, IndexLimits::default()).is_err()
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
                build_effective_index(&[segment(conflicting)], 1_000, IndexLimits::default())
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
        assert!(build_effective_index(&[segment(adjacent)], 1_000, IndexLimits::default()).is_ok());
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
                build_effective_index(&[segment(entries)], 1_000, IndexLimits::default()).is_err()
            );
        }

        assert!(
            build_effective_index(
                &[segment(vec![
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
        assert!(build_effective_index(&[base, child], 1_000, IndexLimits::default()).is_ok());

        let early_child = segment_at(100, None, vec![file(2, "parent/child")]);
        let late_parent = segment_at(200, Some(early_child.span), vec![directory(1, "parent")]);
        assert!(
            build_effective_index(&[early_child, late_parent], 1_000, IndexLimits::default(),)
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
            prop_assert!(build_effective_index(&[segment(conflicting)], 1_000, IndexLimits::default()).is_err());
            let adjacent = vec![
                SegmentEntry { id: FileId(1), path: ArchivePath::new(&prefix).unwrap(), entry: file() },
                SegmentEntry { id: FileId(2), path: ArchivePath::new(format!("{prefix}!")).unwrap(), entry: file() },
            ];
            prop_assert!(build_effective_index(&[segment(adjacent)], 1_000, IndexLimits::default()).is_ok());
        }
    }
}
