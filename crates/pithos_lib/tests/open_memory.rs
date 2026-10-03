//! Peak memory while opening a composed file. This target holds a single test, so the counting
//! allocator sees no concurrent allocations from other tests.

mod common;

use common::util::{private_key, public_key};
use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, EntryMetadata, OpenOptions, PieceEncoder, ProcessingOptions,
    compose,
};
use pithos_lib::source::MemorySource;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(bytes: usize) {
    let now = CURRENT.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            // A moving reallocation briefly holds both buffers.
            grow(new_size);
            CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// One composed file of `pieces` pieces with `blocks` 4-byte blocks each. The blocks are
/// distinct, or one block repeated. Returns the archive, its content and its directory size.
fn composed(pieces: u32, blocks: u32, distinct: bool) -> (Vec<u8>, Vec<u8>, usize) {
    let processing = ProcessingOptions::new(true, 0).unwrap();
    let mut stored = Vec::new();
    let mut content = Vec::new();
    let mut sealed = Vec::new();
    for key_id in 1..=pieces {
        let mut encoder =
            PieceEncoder::new(key_id.into(), vec![public_key("recipient1")], processing).unwrap();
        for block in 0..blocks {
            let plaintext = if distinct {
                (key_id * blocks + block).to_be_bytes()
            } else {
                *b"same"
            };
            stored.extend(encoder.push(&plaintext).unwrap());
            content.extend_from_slice(&plaintext);
        }
        sealed.push(encoder.finish().unwrap());
    }
    let composition = compose(
        ArchivePath::new("object").unwrap(),
        EntryMetadata::new(0, 0, 0o644),
        &sealed,
    )
    .unwrap();
    let mut archive = composition.header().to_vec();
    archive.extend_from_slice(&stored);
    archive.extend_from_slice(composition.directory());
    (archive, content, composition.directory().len())
}

/// Opens `archive` and returns the peak bytes allocated while opening.
fn open_peak(archive: Vec<u8>, content: &[u8]) -> usize {
    let source = MemorySource::new(archive);
    let options = OpenOptions::default()
        .with_access_keys(AccessKeys::new().with_key(private_key("recipient1")));
    let baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let archive = Archive::open(source, options).unwrap();
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    let mut output = Vec::new();
    archive.copy_to("object", &mut output).unwrap();
    assert!(
        output == content,
        "the opened archive returned other content"
    );
    peak
}

/// Opening holds about two copies of the directory at most: the encoded directory with its
/// decoded form, then the decoded form with the index and the recovered keys. Converting the
/// directory, copying it into the index and copying the keys into a map needed 4.6 copies.
#[test]
fn opening_pieces_holds_about_two_copies_of_the_directory() {
    for (pieces, blocks, distinct) in [(4, 25_000, true), (1, 100_000, false)] {
        let (archive, content, directory) = composed(pieces, blocks, distinct);
        let peak = open_peak(archive, &content);
        assert!(
            2 * peak <= 5 * directory,
            "peak {peak} bytes for a {directory}-byte directory"
        );
    }
}
