//! Checks that secret buffers are wiped before their allocations are freed.
//!
//! The unit-test binary uses an allocator that inspects freed blocks only while the current
//! thread watches, so other tests running in parallel are not affected. It reads only blocks
//! whose bytes are known to be initialized: blocks it filled itself and buffers the test names.

use crate::format::encryption::decode_decrypted_recipient_list;
use crate::format::limits::DeserializationLimits;
use crate::format::primitives::reserve_secret;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use zeroize::Zeroizing;

const SECRET: [u8; 32] = {
    let mut bytes = [0; 32];
    let mut index = 0;
    while index < 32 {
        bytes[index] = (index as u8).wrapping_mul(37) ^ 0xA5;
        index += 1;
    }
    bytes
};

/// Most blocks one watch can track; the tests allocate far fewer.
const TRACKED_CAPACITY: usize = 64;
/// Fill byte for blocks allocated while watching, so every inspected byte is initialized.
const FILL: u8 = 0xEE;

thread_local! {
    static WATCHED_SIZE: Cell<Option<usize>> = const { Cell::new(None) };
    static ZEROED_FREES: Cell<usize> = const { Cell::new(0) };
    static SECRET_FREES: Cell<usize> = const { Cell::new(0) };
    static TRACKED: Cell<[usize; TRACKED_CAPACITY]> = const { Cell::new([0; TRACKED_CAPACITY]) };
    static TRACKING_FULL: Cell<bool> = const { Cell::new(false) };
}

struct Inspecting;

impl Inspecting {
    fn watching() -> bool {
        WATCHED_SIZE.try_with(Cell::get).ok().flatten().is_some()
    }

    fn track(pointer: *mut u8) {
        let _ = TRACKED.try_with(|tracked| {
            let mut slots = tracked.get();
            match slots.iter_mut().find(|slot| **slot == 0) {
                Some(slot) => {
                    *slot = pointer as usize;
                    tracked.set(slots);
                }
                // A skipped block could hide a leak, so `watch` fails the test instead.
                None => TRACKING_FULL.set(true),
            }
        });
    }

    /// Removes `pointer` from the tracked blocks and reports whether it was tracked.
    fn untrack(pointer: *mut u8) -> bool {
        TRACKED
            .try_with(|tracked| {
                let mut slots = tracked.get();
                let found = slots.iter_mut().find(|slot| **slot == pointer as usize);
                let was_tracked = found.map(|slot| *slot = 0).is_some();
                tracked.set(slots);
                was_tracked
            })
            .unwrap_or(false)
    }

    /// Records whether a tracked block about to be freed is wiped or still holds the secret.
    unsafe fn inspect(pointer: *mut u8, layout: Layout) {
        let Ok(Some(size)) = WATCHED_SIZE.try_with(Cell::get) else {
            return;
        };
        if !Self::untrack(pointer) {
            return;
        }
        // Tracked blocks were filled at allocation or named by the test as fully initialized.
        let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
        if layout.size() == size && bytes.iter().all(|byte| *byte == 0) {
            ZEROED_FREES.set(ZEROED_FREES.get() + 1);
        }
        if bytes.windows(SECRET.len()).any(|window| window == SECRET) {
            SECRET_FREES.set(SECRET_FREES.get() + 1);
        }
    }
}

unsafe impl GlobalAlloc for Inspecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if Self::watching() && !pointer.is_null() {
            unsafe { std::ptr::write_bytes(pointer, FILL, layout.size()) };
            Self::track(pointer);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe {
            Self::inspect(pointer, layout);
            System.dealloc(pointer, layout);
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !Self::watching() {
            return unsafe { System.realloc(pointer, layout, new_size) };
        }
        // While watching, a reallocation frees the old block through `dealloc`. The copy keeps
        // any uninitialized bytes of the old block, so the new block is tracked only when the
        // old block was known to be fully initialized.
        let old_tracked = TRACKED
            .try_with(|tracked| tracked.get().contains(&(pointer as usize)))
            .unwrap_or(false);
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let moved = unsafe { System.alloc(new_layout) };
        if !moved.is_null() {
            unsafe {
                std::ptr::write_bytes(moved, FILL, new_size);
                std::ptr::copy_nonoverlapping(pointer, moved, layout.size().min(new_size));
            }
            if old_tracked {
                Self::track(moved);
            }
            unsafe { self.dealloc(pointer, layout) };
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Inspecting = Inspecting;

/// Runs `action` while watching freed blocks of `size` bytes. `initialized` names existing
/// buffers whose whole allocation is initialized; blocks allocated during the watch count too.
/// Returns the number of wiped blocks of that size and of freed blocks that held the secret.
fn watch<T>(
    size: usize,
    initialized: &[*const u8],
    action: impl FnOnce() -> T,
) -> (T, usize, usize) {
    ZEROED_FREES.set(0);
    SECRET_FREES.set(0);
    TRACKED.set([0; TRACKED_CAPACITY]);
    TRACKING_FULL.set(false);
    for pointer in initialized {
        Inspecting::track(pointer.cast_mut());
    }
    WATCHED_SIZE.set(Some(size));
    let result = action();
    WATCHED_SIZE.set(None);
    TRACKED.set([0; TRACKED_CAPACITY]);
    assert!(
        !TRACKING_FULL.get(),
        "the watch tracked more blocks than it can hold"
    );
    (result, ZEROED_FREES.get(), SECRET_FREES.get())
}

#[test]
fn secret_growth_and_drop_wipe_freed_buffers() {
    // `vec![SECRET]` has no spare capacity, so its whole allocation is initialized.
    let mut secrets = Zeroizing::new(vec![SECRET]);
    let initialized = [secrets.as_ptr().cast::<u8>()];
    let (grown, zeroed, leaked) = watch(32, &initialized, || {
        reserve_secret(&mut secrets, 3, "secrets")
    });
    grown.unwrap();
    assert_eq!((zeroed, leaked), (1, 0));
    assert_eq!(secrets.as_slice(), &[SECRET]);
    let capacity = secrets.capacity();
    assert!(capacity >= 4);

    // The grown buffer was allocated, and so filled, while the first watch ran.
    let initialized = [secrets.as_ptr().cast::<u8>()];
    let ((), zeroed, leaked) = watch(capacity * 32, &initialized, || drop(secrets));
    assert_eq!((zeroed, leaked), (1, 0));
}

#[test]
fn ordinary_growth_is_detected() {
    let mut plain = vec![SECRET];
    let initialized = [plain.as_ptr().cast::<u8>()];
    let ((), _, leaked) = watch(32, &initialized, || plain.reserve_exact(7));
    assert_eq!(leaked, 1);
}

#[test]
fn decode_error_wipes_partial_secrets() {
    let mut bytes = vec![2];
    bytes.push(1);
    bytes.extend_from_slice(&SECRET);
    bytes.push(1);
    bytes.extend_from_slice(&[0; 32]);
    let limits = DeserializationLimits::default();
    let (decoded, zeroed, leaked) = watch(2 * size_of::<(u64, [u8; 32])>(), &[], || {
        decode_decrypted_recipient_list(&bytes, &limits).map(|_| ())
    });
    assert!(decoded.is_err());
    assert_eq!((zeroed, leaked), (1, 0));
}

#[test]
fn untracked_buffers_with_spare_capacity_are_never_read() {
    // Spare capacity is uninitialized, so neither this block nor its grown copy may be read.
    let mut partial = Vec::with_capacity(8);
    partial.push(SECRET);
    let ((), zeroed, leaked) = watch(32, &[], || {
        partial.reserve_exact(64);
        drop(std::mem::take(&mut partial));
    });
    assert_eq!((zeroed, leaked), (0, 0));
}
