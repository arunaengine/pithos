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

/// One composed file in a single piece that references one 4-byte block `references` times.
/// Its block list is far larger than everything else in the directory.
fn one_piece(references: u32) -> Vec<u8> {
    let processing = ProcessingOptions::new(true, 0).unwrap();
    let mut encoder = PieceEncoder::new(1, vec![public_key("recipient1")], processing).unwrap();
    let mut stored = Vec::new();
    for _ in 0..references {
        stored.extend(encoder.push(b"same").unwrap());
    }
    let piece = encoder.finish().unwrap();
    let composition = compose(
        ArchivePath::new("object").unwrap(),
        EntryMetadata::new(0, 0, 0o644),
        &[piece],
    )
    .unwrap();
    let mut archive = composition.header().to_vec();
    archive.extend_from_slice(&stored);
    archive.extend_from_slice(composition.directory());
    archive
}

/// Opening holds the directory response plus at most two lists at once: the sealed list and its
/// plaintext, then the plaintext and the decoded list. That is about three list sizes. Decoding
/// into a separate list, copying it into an aggregate list and collecting the keys into a map
/// through a sorted copy needed more than five.
#[test]
fn opening_one_large_piece_holds_no_extra_copies_of_its_block_list() {
    let references = 100_000;
    let source = MemorySource::new(one_piece(references));
    let options = OpenOptions::default()
        .with_access_keys(AccessKeys::new().with_key(private_key("recipient1")));
    let baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let archive = Archive::open(source, options).unwrap();
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    let list = references as usize * 64;
    assert_eq!(archive.entries().len(), 1);
    assert!(
        2 * peak < 7 * list,
        "peak {peak} bytes for a {list}-byte list"
    );
}
