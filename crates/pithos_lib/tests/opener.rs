mod common;

use common::append::append_fixture;
use common::util::{fixture, private_key};
use pithos_lib::archive::{
    AccessKeys, Archive, ArchiveOpener, ArchivePath, ArchiveView, ArchiveWriter, BlockRequest,
    Chunking, EntryMetadata, OpenLimits, OpenOptions, ProcessingOptions, WriteOptions,
};
use pithos_lib::error::PithosError;
use pithos_lib::source::{ArchiveSource, MemorySource, SourceError};
use std::sync::{Arc, Mutex};

fn recipient() -> OpenOptions {
    OpenOptions::default().with_access_keys(AccessKeys::new().with_key(private_key("recipient1")))
}

/// Drives an opener over `bytes` and records every request.
fn drive(
    bytes: &[u8],
    options: OpenOptions,
) -> (Result<ArchiveView, PithosError>, Vec<(u64, u64)>) {
    let mut requests = Vec::new();
    let result = ArchiveOpener::new(bytes.len() as u64, options).and_then(|mut opener| {
        while let Some(request) = opener.request() {
            requests.push((request.offset(), request.len()));
            let start = request.offset() as usize;
            opener.feed(
                request,
                bytes[start..start + request.len() as usize].to_vec(),
            )?;
        }
        opener.finish()
    });
    (result, requests)
}

fn terminal_len(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap())
}

#[test]
fn a_single_segment_archive_requests_header_footer_and_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let bytes = std::fs::read(fixture(&temporary, "recipient1")).unwrap();
    let len = bytes.len() as u64;
    let (view, requests) = drive(&bytes, recipient());
    let directory = terminal_len(&bytes);
    assert_eq!(
        requests,
        [(0, 6), (len - 12, 12), (len - directory, directory)]
    );
    let view = view.unwrap();
    assert_eq!(view.version(), 0x0101);
    assert_eq!(view.entries().len(), 1);
    assert!(view.entry("data").unwrap().is_some());
}

#[test]
fn an_appended_archive_requests_each_directory_from_terminal_to_base() {
    let temporary = tempfile::tempdir().unwrap();
    let bytes = std::fs::read(append_fixture(&temporary).archive).unwrap();
    let len = bytes.len() as u64;
    let (view, requests) = drive(&bytes, recipient());
    let terminal = terminal_len(&bytes);
    assert_eq!(requests.len(), 4);
    assert_eq!(
        &requests[..3],
        [(0, 6), (len - 12, 12), (len - terminal, terminal)]
    );
    let (parent_start, parent_len) = requests[3];
    assert!(parent_start + parent_len <= len - terminal);
    let view = view.unwrap();
    assert_eq!(view.entries().len(), 5);
    let archive = Archive::open(MemorySource::new(bytes), recipient()).unwrap();
    assert_eq!(view.metadata_digest(), archive.metadata_digest());
}

#[test]
fn feed_rejects_wrong_lengths_unknown_and_repeated_responses() {
    let temporary = tempfile::tempdir().unwrap();
    let bytes = std::fs::read(fixture(&temporary, "recipient1")).unwrap();
    let len = bytes.len() as u64;
    let mut opener = ArchiveOpener::new(len, recipient()).unwrap();
    let header = opener.request().unwrap();
    assert!(matches!(
        opener.feed(header, bytes[..5].to_vec()),
        Err(PithosError::ReadResponseLength {
            expected: 6,
            actual: 5
        })
    ));
    assert!(matches!(
        opener.feed(header, bytes[..7].to_vec()),
        Err(PithosError::ReadResponseLength { .. })
    ));
    assert_eq!(opener.request(), Some(header));
    opener.feed(header, bytes[..6].to_vec()).unwrap();
    assert!(matches!(
        opener.feed(header, bytes[..6].to_vec()),
        Err(PithosError::UnexpectedReadResponse)
    ));

    let mut other = ArchiveOpener::new(len + 1, OpenOptions::default()).unwrap();
    let other_header = other.request().unwrap();
    other.feed(other_header, bytes[..6].to_vec()).unwrap();
    let foreign = other.request().unwrap();
    assert!(matches!(
        opener.feed(foreign, bytes[..12].to_vec()),
        Err(PithosError::UnexpectedReadResponse)
    ));
    let footer = opener.request().unwrap();
    assert_eq!((footer.offset(), footer.len()), (len - 12, 12));
    let unfinished = ArchiveOpener::new(len, OpenOptions::default()).unwrap();
    assert!(matches!(
        unfinished.finish(),
        Err(PithosError::OpenIncomplete)
    ));

    opener
        .feed(footer, bytes[bytes.len() - 12..].to_vec())
        .unwrap();
    let directory = opener.request().unwrap();
    let start = directory.offset() as usize;
    opener.feed(directory, bytes[start..].to_vec()).unwrap();
    assert_eq!(opener.request(), None);
    assert!(matches!(
        opener.feed(directory, bytes[start..].to_vec()),
        Err(PithosError::UnexpectedReadResponse)
    ));
    assert_eq!(opener.finish().unwrap().entries().len(), 1);
}

#[test]
fn feed_rejects_header_and_same_span_footer_requests_of_other_openers() {
    let temporary = tempfile::tempdir().unwrap();
    let bytes = std::fs::read(fixture(&temporary, "recipient1")).unwrap();
    let len = bytes.len() as u64;
    let mut opener = ArchiveOpener::new(len, recipient()).unwrap();
    let mut other = ArchiveOpener::new(len, recipient()).unwrap();
    let header = opener.request().unwrap();
    let foreign_header = other.request().unwrap();
    assert_eq!(
        (foreign_header.offset(), foreign_header.len()),
        (header.offset(), header.len())
    );
    assert!(matches!(
        opener.feed(foreign_header, bytes[..6].to_vec()),
        Err(PithosError::UnexpectedReadResponse)
    ));
    opener.feed(header, bytes[..6].to_vec()).unwrap();
    other.feed(foreign_header, bytes[..6].to_vec()).unwrap();

    let footer = opener.request().unwrap();
    let foreign_footer = other.request().unwrap();
    assert_eq!(
        (foreign_footer.offset(), foreign_footer.len()),
        (footer.offset(), footer.len())
    );
    let tail = bytes[bytes.len() - 12..].to_vec();
    assert!(matches!(
        opener.feed(foreign_footer, tail.clone()),
        Err(PithosError::UnexpectedReadResponse)
    ));
    assert_eq!(opener.request(), Some(footer));
    opener.feed(footer, tail).unwrap();
}

#[test]
fn limits_are_checked_before_a_directory_is_requested() {
    let temporary = tempfile::tempdir().unwrap();
    let bytes = std::fs::read(append_fixture(&temporary).archive).unwrap();
    let terminal = terminal_len(&bytes);
    let cases = [
        (
            OpenLimits {
                max_directory_bytes: terminal - 1,
                ..OpenLimits::default()
            },
            2,
            "directory",
        ),
        (
            OpenLimits {
                max_total_directory_bytes: terminal,
                ..OpenLimits::default()
            },
            3,
            "total directory bytes",
        ),
        (
            OpenLimits {
                max_parent_directories: 0,
                ..OpenLimits::default()
            },
            3,
            "parent directories",
        ),
    ];
    for (limits, issued, expected) in cases {
        let (result, requests) = drive(&bytes, recipient().with_limits(limits));
        assert!(
            matches!(result, Err(PithosError::LimitExceeded { field, .. }) if field == expected),
            "{expected}"
        );
        assert_eq!(requests.len(), issued, "{expected}");
    }
    assert!(matches!(
        ArchiveOpener::new(5, OpenOptions::default()),
        Err(PithosError::InvalidDirectoryRange { .. })
    ));
}

struct RecordingSource {
    bytes: Arc<[u8]>,
    reads: Arc<Mutex<Vec<(u64, usize)>>>,
}

impl ArchiveSource for RecordingSource {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), SourceError> {
        self.reads.lock().unwrap().push((offset, output.len()));
        MemorySource::new(Arc::clone(&self.bytes)).read_exact_at(offset, output)
    }
}

/// An archive with `count` distinct 16-byte blocks in one file.
fn many_blocks(count: usize) -> Vec<u8> {
    let content = (0..count as u64)
        .flat_map(|block| [block.to_be_bytes(), (!block).to_be_bytes()])
        .flatten()
        .collect::<Vec<u8>>();
    let sender = private_key("sender");
    let options = WriteOptions::new(sender.duplicate(), vec![sender.public_key()])
        .with_chunking(Chunking::Fixed(16));
    let mut writer = ArchiveWriter::create(Vec::new(), options).unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            Some(content.len() as u64),
            std::io::Cursor::new(content),
        )
        .unwrap();
    writer.finish().unwrap()
}

#[test]
fn open_reads_do_not_depend_on_the_block_count_and_reads_fetch_each_block_once() {
    let count = 1_000;
    let bytes = Arc::<[u8]>::from(many_blocks(count));
    let reads = Arc::new(Mutex::new(Vec::new()));
    let archive = Archive::open(
        RecordingSource {
            bytes: Arc::clone(&bytes),
            reads: Arc::clone(&reads),
        },
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(private_key("sender"))),
    )
    .unwrap();
    assert_eq!(reads.lock().unwrap().len(), 3);

    let mut output = Vec::new();
    archive.copy_range_to("data", 32..48, &mut output).unwrap();
    assert_eq!(output, [2u64.to_be_bytes(), (!2u64).to_be_bytes()].concat());
    assert_eq!(reads.lock().unwrap().len(), 4);
    assert_eq!(reads.lock().unwrap()[3].1, 4 + 16);

    archive.copy_to("data", &mut Vec::new()).unwrap();
    assert_eq!(reads.lock().unwrap().len(), 4 + count);
}

#[test]
fn a_view_decodes_blocks_from_bytes_the_caller_fetched() {
    let bytes = many_blocks(64);
    let (view, _) = drive(
        &bytes,
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(private_key("sender"))),
    );
    let view = view.unwrap();
    let fetch = |request: BlockRequest| match request {
        BlockRequest::Local { offset, len } => &bytes[offset as usize..(offset + len) as usize],
        BlockRequest::External { .. } => panic!("unexpected external block"),
    };
    let mut output = Vec::new();
    for batch in view.plan_range("data", 8..40).unwrap().batches(1024) {
        let batch = batch.unwrap();
        assert_eq!(batch.blocks().len(), 3);
        for (block, stored) in batch.split(fetch(batch.request())).unwrap() {
            output.extend_from_slice(&view.decode_block(block, stored).unwrap()[block.output()]);
        }
    }
    let content = (0..3u64)
        .flat_map(|block| [block.to_be_bytes(), (!block).to_be_bytes()])
        .flatten()
        .collect::<Vec<u8>>();
    assert_eq!(output, &content[8..40]);

    let block = view
        .plan_range("data", 0..1)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let mut stored = fetch(block.request()).to_vec();
    assert!(matches!(
        view.decode_block(&block, &stored[1..]),
        Err(PithosError::BlockSizeMismatch { .. })
    ));
    stored[0] ^= 1;
    let error = view.decode_block(&block, &stored).unwrap_err();
    assert!(error.to_string().contains("block marker"), "{error}");
}

#[test]
fn a_view_checks_its_own_block_limits_for_blocks_planned_by_another_view() {
    let bytes = many_blocks(4);
    let keys = || AccessKeys::new().with_key(private_key("sender"));
    let open = |limits: OpenLimits| {
        drive(
            &bytes,
            OpenOptions::default()
                .with_access_keys(keys())
                .with_limits(limits),
        )
        .0
        .unwrap()
    };
    let permissive = open(OpenLimits::default());
    let block = permissive
        .plan_range("data", 0..1)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let BlockRequest::Local { offset, len } = block.request() else {
        panic!("unexpected external block");
    };
    let stored = &bytes[offset as usize..(offset + len) as usize];
    assert_eq!(permissive.decode_block(&block, stored).unwrap().len(), 16);

    for (limits, field) in [
        (
            OpenLimits {
                max_stored_block_bytes: 15,
                ..OpenLimits::default()
            },
            "stored block",
        ),
        (
            OpenLimits {
                max_decoded_block_bytes: 15,
                ..OpenLimits::default()
            },
            "decoded block",
        ),
    ] {
        let restrictive = open(limits);
        // A short response proves that the limits are checked before the stored bytes.
        for response in [stored, &stored[1..]] {
            let error = restrictive.decode_block(&block, response).unwrap_err();
            assert!(
                matches!(
                    error,
                    PithosError::LimitExceeded { field: name, limit: 15, actual: 16 }
                        if name == field
                ),
                "{error:?}"
            );
        }
    }
}
