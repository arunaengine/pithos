//! BLAKE3 subtree chaining values that let separately encoded pieces yield the file hash.

use blake3::hazmat::{
    ChainingValue, HasherExt, Mode, left_subtree_len, max_subtree_len, merge_subtrees_non_root,
    merge_subtrees_root,
};
use blake3::{CHUNK_LEN, Hasher};
use zeroize::Zeroizing;

const CHUNK: u64 = CHUNK_LEN as u64;
/// Largest subtree hashed in one call. Larger subtrees are merged from these.
const UNIT_LEN: u64 = 64 * CHUNK;

/// One subtree of the file's BLAKE3 tree, at an absolute plaintext offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Subtree {
    pub(crate) offset: u64,
    pub(crate) len: u64,
    pub(crate) value: ChainingValue,
}

/// The aligned subtrees that cover one piece's plaintext, in order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentTree {
    pub(crate) offset: u64,
    pub(crate) subtrees: Vec<Subtree>,
    /// BLAKE3 of the piece alone. Kept only for a piece at offset 0.
    pub(crate) root: Option<[u8; 32]>,
}

impl ContentTree {
    /// Checks that the subtrees are aligned and exactly cover `len` bytes from the offset.
    /// Only the last subtree may be a short chunk.
    pub(crate) fn is_valid(&self, len: u64) -> bool {
        if !self.offset.is_multiple_of(CHUNK) || self.root.is_some() != (self.offset == 0) {
            return false;
        }
        let mut next = self.offset;
        for (index, subtree) in self.subtrees.iter().enumerate() {
            let last = index + 1 == self.subtrees.len();
            let aligned = subtree.len >= CHUNK
                && subtree.len.is_power_of_two()
                && subtree.offset.is_multiple_of(subtree.len);
            let short = last && subtree.len > 0 && subtree.len < CHUNK;
            if subtree.offset != next || !(aligned || short) {
                return false;
            }
            let Some(end) = next.checked_add(subtree.len) else {
                return false;
            };
            next = end;
        }
        self.offset.checked_add(len) == Some(next)
    }
}

/// Records the subtrees of plaintext that starts at a fixed absolute offset.
pub(crate) struct TreeHasher {
    offset: u64,
    next: u64,
    pending: Zeroizing<Vec<u8>>,
    subtrees: Vec<Subtree>,
    root: Option<Hasher>,
}

impl TreeHasher {
    /// `offset` must be a multiple of the 1024-byte BLAKE3 chunk length.
    pub(crate) fn new(offset: u64) -> Self {
        debug_assert!(offset.is_multiple_of(CHUNK));
        Self {
            offset,
            next: offset,
            pending: Zeroizing::new(Vec::new()),
            subtrees: Vec::new(),
            root: (offset == 0).then(Hasher::new),
        }
    }

    pub(crate) fn update(&mut self, mut bytes: &[u8]) {
        if let Some(root) = &mut self.root {
            root.update(bytes);
        }
        while !bytes.is_empty() {
            // A subtree starting at `next` may hold at most `max_subtree_len(next)` bytes.
            let unit = max_subtree_len(self.next).map_or(UNIT_LEN, |max| max.min(UNIT_LEN));
            let unit = unit as usize;
            if self.pending.is_empty() && bytes.len() >= unit {
                let (subtree, rest) = bytes.split_at(unit);
                self.push(subtree);
                bytes = rest;
                continue;
            }
            let take = (unit - self.pending.len()).min(bytes.len());
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.pending.len() == unit {
                let pending = std::mem::take(&mut self.pending);
                self.push(&pending);
                self.pending = pending;
                self.pending.clear();
            }
        }
    }

    /// Splits the buffered tail into the largest aligned subtrees, ending in one short chunk.
    pub(crate) fn finish(mut self) -> ContentTree {
        let pending = std::mem::take(&mut self.pending);
        let mut rest = pending.as_slice();
        while !rest.is_empty() {
            let len = if rest.len() < CHUNK_LEN {
                rest.len()
            } else {
                1 << rest.len().ilog2()
            };
            let (subtree, tail) = rest.split_at(len);
            self.push(subtree);
            rest = tail;
        }
        ContentTree {
            offset: self.offset,
            subtrees: self.subtrees,
            root: self.root.map(|root| *root.finalize().as_bytes()),
        }
    }

    /// Hashes one aligned subtree and merges equal aligned neighbours into their parent.
    fn push(&mut self, bytes: &[u8]) {
        let len = bytes.len() as u64;
        let value = Hasher::new()
            .set_input_offset(self.next)
            .update(bytes)
            .finalize_non_root();
        self.subtrees.push(Subtree {
            offset: self.next,
            len,
            value,
        });
        self.next += len;
        while let [.., left, right] = self.subtrees.as_slice() {
            let Some(parent_len) = left.len.checked_mul(2) else {
                break;
            };
            if left.len != right.len || !left.offset.is_multiple_of(parent_len) {
                break;
            }
            let parent = Subtree {
                offset: left.offset,
                len: parent_len,
                value: merge_subtrees_non_root(&left.value, &right.value, Mode::Hash),
            };
            self.subtrees.truncate(self.subtrees.len() - 2);
            self.subtrees.push(parent);
        }
    }
}

/// Returns the BLAKE3 of the whole file when every piece has a tree, the trees start at the
/// running sum of the piece sizes from 0, and each tree exactly covers its piece.
pub(crate) fn file_hash<'a>(
    pieces: impl IntoIterator<Item = (Option<&'a ContentTree>, u64)>,
) -> Option<[u8; 32]> {
    let mut subtrees = Vec::new();
    let mut total = 0u64;
    let mut nonempty = Vec::new();
    for (tree, len) in pieces {
        let tree = tree?;
        if tree.offset != total || !tree.is_valid(len) {
            return None;
        }
        if len > 0 {
            nonempty.push(tree);
        }
        subtrees.extend_from_slice(&tree.subtrees);
        total = total.checked_add(len)?;
    }
    match nonempty.as_slice() {
        [] => return Some(*blake3::hash(&[]).as_bytes()),
        // One piece holds the whole file, so its own hash is the file hash.
        [tree] => return tree.root,
        _ if total <= CHUNK => return None,
        _ => {}
    }
    let left = left_subtree_len(total);
    let left_value = resolve(&subtrees, 0, left)?;
    let right_value = resolve(&subtrees, left, total - left)?;
    Some(*merge_subtrees_root(&left_value, &right_value, Mode::Hash).as_bytes())
}

/// Finds or merges the chaining value of the tree node covering `len` bytes at `offset`.
fn resolve(subtrees: &[Subtree], offset: u64, len: u64) -> Option<ChainingValue> {
    let index = subtrees
        .partition_point(|subtree| subtree.offset <= offset)
        .checked_sub(1)?;
    let found = &subtrees[index];
    if found.offset == offset && found.len == len {
        return Some(found.value);
    }
    if found.offset != offset || found.len > len || len <= CHUNK {
        return None;
    }
    let left = left_subtree_len(len);
    let left_value = resolve(subtrees, offset, left)?;
    let right_value = resolve(subtrees, offset + left, len - left)?;
    Some(merge_subtrees_non_root(
        &left_value,
        &right_value,
        Mode::Hash,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(offset: u64, content: &[u8], fragment: usize) -> ContentTree {
        let mut hasher = TreeHasher::new(offset);
        for part in content.chunks(fragment.max(1)) {
            hasher.update(part);
        }
        hasher.finish()
    }

    #[test]
    fn split_trees_merge_to_the_plain_hash_at_every_boundary() {
        let content = (0..300_000u32)
            .map(|index| (index * 31 % 251) as u8)
            .collect::<Vec<_>>();
        let lengths = [0, 1, 1023, 1024, 1025, 2048, 3072, 65_536, 66_560, 200_000];
        for len in lengths {
            for split in [0, 1024, 3072, 65_536, 70_656] {
                let split = split.min(len / 1024 * 1024);
                let first = tree(0, &content[..split], 7);
                let second = tree(split as u64, &content[split..len], 4096);
                assert!(first.is_valid(split as u64) && second.is_valid((len - split) as u64));
                let pieces = [
                    (Some(&first), split as u64),
                    (Some(&second), (len - split) as u64),
                ];
                assert_eq!(
                    file_hash(pieces),
                    Some(*blake3::hash(&content[..len]).as_bytes()),
                    "length {len}, split {split}"
                );
            }
        }
    }

    #[test]
    fn invalid_trees_are_detected() {
        let content = vec![7u8; 5000];
        let valid = tree(0, &content, 5000);
        assert!(valid.is_valid(5000));
        assert!(!valid.is_valid(4999));
        let mut short_inside = valid.clone();
        short_inside.subtrees[0].len = 100;
        assert!(!short_inside.is_valid(5000));
        let mut misaligned = tree(1024, &content, 5000);
        misaligned.subtrees[1].offset += 1024;
        assert!(!misaligned.is_valid(5000));
        let mut rootless = valid;
        rootless.root = None;
        assert!(!rootless.is_valid(5000));
    }
}
