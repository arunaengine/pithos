//! Checks that secret buffers are wiped before their allocations are freed.
//!
//! The unit-test binary uses an allocator that inspects freed blocks only while the current
//! thread watches, so other tests running in parallel are not affected.

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

thread_local! {
    static WATCHED_SIZE: Cell<Option<usize>> = const { Cell::new(None) };
    static ZEROED_FREES: Cell<usize> = const { Cell::new(0) };
    static SECRET_FREES: Cell<usize> = const { Cell::new(0) };
}

struct Inspecting;

impl Inspecting {
    fn watching() -> bool {
        WATCHED_SIZE.try_with(Cell::get).ok().flatten().is_some()
    }

    /// Records whether a block about to be freed is wiped or still holds the secret.
    unsafe fn inspect(pointer: *mut u8, layout: Layout) {
        let Ok(Some(size)) = WATCHED_SIZE.try_with(Cell::get) else {
            return;
        };
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
        unsafe { System.alloc(layout) }
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
        // While watching, a reallocation frees the old block through `dealloc`.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let moved = unsafe { self.alloc(new_layout) };
        if !moved.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(pointer, moved, layout.size().min(new_size));
                self.dealloc(pointer, layout);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Inspecting = Inspecting;

/// Runs `action` while watching freed blocks of `size` bytes. Returns the number of wiped
/// blocks of that size and the number of freed blocks of any size that held the secret.
fn watch<T>(size: usize, action: impl FnOnce() -> T) -> (T, usize, usize) {
    ZEROED_FREES.set(0);
    SECRET_FREES.set(0);
    WATCHED_SIZE.set(Some(size));
    let result = action();
    WATCHED_SIZE.set(None);
    (result, ZEROED_FREES.get(), SECRET_FREES.get())
}

#[test]
fn secret_growth_and_drop_wipe_freed_buffers() {
    let mut secrets = Zeroizing::new(vec![SECRET]);
    let (grown, zeroed, leaked) = watch(32, || reserve_secret(&mut secrets, 3, "secrets"));
    grown.unwrap();
    assert_eq!((zeroed, leaked), (1, 0));
    assert_eq!(secrets.as_slice(), &[SECRET]);
    let capacity = secrets.capacity();
    assert!(capacity >= 4);

    let ((), zeroed, leaked) = watch(capacity * 32, || drop(secrets));
    assert_eq!((zeroed, leaked), (1, 0));
}

#[test]
fn ordinary_growth_is_detected() {
    let mut plain = vec![SECRET];
    let ((), _, leaked) = watch(32, || plain.reserve_exact(7));
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
    let (decoded, zeroed, leaked) = watch(2 * size_of::<(u64, [u8; 32])>(), || {
        decode_decrypted_recipient_list(&bytes, &limits).map(|_| ())
    });
    assert!(decoded.is_err());
    assert_eq!((zeroed, leaked), (1, 0));
}
