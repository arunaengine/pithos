use crate::error::PithosError;
use crate::model::structs::FileEntry;
use indexmap::IndexMap;
use indexmap::map::Entry;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;

/// Values used as keys in a Map, e.g. `HashMap<Key, _>`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Key {
    id: u64,
    path: Arc<str>,
}

impl Key {
    pub fn new(id: u64, path: impl Into<String>) -> Key {
        Key {
            id,
            path: Arc::from(path.into()),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn id_mut(&mut self) -> &mut u64 {
        &mut self.id
    }

    pub fn id_query(&self) -> KeyQuery {
        KeyQuery::Id(self.id)
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn path_query(&self) -> KeyQuery {
        KeyQuery::Path(self.path.to_string())
    }
}

/// An archive path ordered by slash-delimited components rather than raw bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ArchivePathKey(Arc<str>);

impl Ord for ArchivePathKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.split('/').cmp(other.0.split('/'))
    }
}

impl PartialOrd for ArchivePathKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Different ways to look up a value in a Map keyed by `Key`.
///
/// Each variant must constitute a unique index.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum KeyQuery {
    Id(u64),
    Path(String),
}

impl Display for KeyQuery {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            KeyQuery::Id(id) => f.write_str(&format!("key query for id {}", id)),
            KeyQuery::Path(path) => f.write_str(&format!("key query for path {}", path)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEntryMap {
    id_map: IndexMap<u64, usize>,
    path_map: IndexMap<Arc<str>, usize>,
    ordered_path_map: BTreeMap<ArchivePathKey, usize>,
    values: Vec<FileEntry>,
    current_max_id: u64,
}

impl FileEntryMap {
    pub fn new() -> Self {
        Self {
            id_map: IndexMap::new(),
            path_map: IndexMap::new(),
            ordered_path_map: BTreeMap::new(),
            values: Vec::new(),
            current_max_id: 0,
        }
    }

    pub fn new_with_max(max_id: u64) -> Self {
        Self {
            id_map: IndexMap::new(),
            path_map: IndexMap::new(),
            ordered_path_map: BTreeMap::new(),
            values: Vec::new(),
            current_max_id: max_id,
        }
    }

    pub fn get_ids_ref(&self) -> &IndexMap<u64, usize> {
        &self.id_map
    }

    pub fn get_paths_ref(&self) -> impl Iterator<Item = &str> {
        self.path_map.keys().map(|path| path.as_ref())
    }

    pub fn get_id_by_path(&self, path: &str) -> Option<u64> {
        if let Some(idx) = self.path_map.get(path) {
            if let Some((id, _)) = self.id_map.get_index(*idx) {
                Some(*id)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub(crate) fn get_by_path(&self, path: &str) -> Option<&FileEntry> {
        self.path_map
            .get(path)
            .and_then(|idx| self.values.get(*idx))
    }

    pub(crate) fn first_path_after(&self, path: &str) -> Option<&str> {
        let query = self
            .path_map
            .get_key_value(path)
            .map(|(stored, _)| ArchivePathKey(Arc::clone(stored)))
            .unwrap_or_else(|| ArchivePathKey(Arc::from(path)));
        self.ordered_path_map
            .range((Excluded(query), Unbounded))
            .next()
            .map(|(path, _)| path.0.as_ref())
    }

    pub(crate) fn iter_ordered(&self) -> impl Iterator<Item = (&str, &FileEntry)> {
        self.ordered_path_map.iter().map(|(path, idx)| {
            (
                path.0.as_ref(),
                self.values
                    .get(*idx)
                    .expect("ordered path index must reference an entry"),
            )
        })
    }

    pub fn get_path_by_id(&self, id: &u64) -> Option<&str> {
        if let Some(idx) = self.id_map.get(id) {
            if let Some((path, _)) = self.path_map.get_index(*idx) {
                Some(path)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn extend(&mut self, other: FileEntryMap) -> Result<(), PithosError> {
        for (id, path, entry) in other {
            self.insert(Key::new(id, path), entry)?
        }
        Ok(())
    }

    pub fn retain_mut<F>(&mut self, mut f: F) -> Result<(), PithosError>
    where
        F: FnMut(u64, &str, &mut FileEntry) -> bool,
    {
        let current_max_id = self.current_max_id;
        let existing = std::mem::take(self);
        let mut retained = FileEntryMap::new_with_max(current_max_id);

        for (id, path, mut entry) in existing {
            if f(id, &path, &mut entry) {
                retained.insert(Key::new(id, path), entry)?;
            }
        }

        *self = retained;
        Ok(())
    }

    /// Returns an iterator over references to the entries in the map.
    ///
    /// The iterator yields tuples of `(id, path, &FileEntry)`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let map = FileEntryMap::new();
    /// // ... insert some entries ...
    ///
    /// for (id, path, entry) in map.iter() {
    ///     println!("ID: {}, Path: {}, Entry: {:?}", id, path, entry);
    /// }
    /// ```
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            file_entry_map: self,
            pos: 0,
        }
    }

    /// Returns an iterator over mutable references to the entries in the map.
    ///
    /// The iterator yields tuples of `(id, path, &mut FileEntry)`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut map = FileEntryMap::new();
    /// // ... insert some entries ...
    ///
    /// for (id, path, entry) in map.iter_mut() {
    ///     // Modify the entry
    ///     entry.some_field = new_value;
    ///     println!("ID: {}, Path: {}, Modified Entry: {:?}", id, path, entry);
    /// }
    /// ```
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut {
            id_map: &self.id_map,
            path_map: &self.path_map,
            values: self.values.iter_mut(),
            pos: 0,
        }
    }

    /// Returns the number of entries in the map.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn insert(&mut self, key: Key, value: FileEntry) -> Result<(), PithosError> {
        // Check if id is already occupied
        match self.id_map.entry(key.id) {
            Entry::Occupied(_) => Err(PithosError::DuplicateFileId(format!(
                "File id already occupied: {}",
                key.id
            ))),
            Entry::Vacant(vacant_id_entry) => {
                // Also check if path is occupied
                let path = key.path;
                let ordered_path = ArchivePathKey(path.clone());
                let vacant_path_entry = match self.path_map.entry(path) {
                    Entry::Occupied(entry) => {
                        return Err(PithosError::PathOccupied(format!(
                            "File path already occupied: {}",
                            entry.key()
                        )));
                    }
                    Entry::Vacant(entry) => entry,
                };

                // Insert into maps and vec
                self.values.push(value.clone());
                let idx = self.values.len() - 1;
                vacant_id_entry.insert(idx);
                vacant_path_entry.insert(idx);
                self.ordered_path_map.insert(ordered_path, idx);

                // Set current max
                if key.id > self.current_max_id {
                    self.current_max_id = key.id;
                }

                Ok(())
            }
        }
    }

    pub fn get(&self, kq: &KeyQuery) -> Option<&FileEntry> {
        let idx = match kq {
            KeyQuery::Id(file_id) => self.id_map.get(file_id),
            KeyQuery::Path(file_path) => self.path_map.get(file_path.as_str()),
        };

        match idx {
            Some(idx) => self.values.get(*idx),
            None => None,
        }
    }

    pub fn get_entry(&self, kq: &KeyQuery) -> Option<(Key, &FileEntry)> {
        let entry = self.get(kq)?;

        match kq {
            KeyQuery::Id(id) => {
                if let Some(path) = self.get_path_by_id(id) {
                    let key = Key::new(*id, path);
                    Some((key, entry))
                } else {
                    None
                }
            }
            KeyQuery::Path(path) => {
                if let Some(id) = self.get_id_by_path(path) {
                    Some((Key::new(id, path.clone()), entry))
                } else {
                    None
                }
            }
        }
    }

    pub fn get_current_max_id(&self) -> u64 {
        self.current_max_id
    }

    pub fn next_free_id(&self, has_parent: bool) -> Result<u64, PithosError> {
        if self.current_max_id == 0 && self.values.is_empty() && has_parent {
            Ok(1)
        } else if self.current_max_id == 0 && self.values.is_empty() {
            Ok(0)
        } else {
            self.current_max_id
                .checked_add(1)
                .ok_or(PithosError::FileIdExhausted)
        }
    }
}

impl Default for FileEntryMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator that yields references to (id, path, FileEntry) tuples
pub struct Iter<'a> {
    file_entry_map: &'a FileEntryMap,
    pos: usize,
}

impl<'a> Iterator for Iter<'a> {
    type Item = (u64, &'a str, &'a FileEntry);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.file_entry_map.values.len() {
            return None;
        }

        // Get the id and path from their respective maps at this position
        let (id, _) = self.file_entry_map.id_map.get_index(self.pos)?;
        let (path, _) = self.file_entry_map.path_map.get_index(self.pos)?;
        let value = self.file_entry_map.values.get(self.pos)?;

        self.pos += 1;

        Some((*id, path.as_ref(), value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.file_entry_map.values.len().saturating_sub(self.pos);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {}

/// Iterator that yields mutable references to (id, path, FileEntry) tuples
pub struct IterMut<'a> {
    id_map: &'a IndexMap<u64, usize>,
    path_map: &'a IndexMap<Arc<str>, usize>,
    values: std::slice::IterMut<'a, FileEntry>,
    pos: usize,
}

impl<'a> Iterator for IterMut<'a> {
    type Item = (u64, &'a str, &'a mut FileEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.values.next()?;

        // Get the id and path from their respective maps at this position
        let (id, _) = self.id_map.get_index(self.pos)?;
        let (path, _) = self.path_map.get_index(self.pos)?;

        self.pos += 1;

        Some((*id, path.as_ref(), value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}

impl<'a> ExactSizeIterator for IterMut<'a> {}

/// Iterator that yields owned (id, path, FileEntry) tuples
pub struct IntoIter {
    id_map: IndexMap<u64, usize>,
    path_map: IndexMap<Arc<str>, usize>,
    values: Vec<FileEntry>,
    pos: usize,
}

impl Iterator for IntoIter {
    type Item = (u64, String, FileEntry);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.values.len() {
            return None;
        }

        let (id, _) = self.id_map.get_index(self.pos)?;
        let (path, _) = self.path_map.get_index(self.pos)?;
        let value = self.values.get(self.pos)?.clone();

        self.pos += 1;

        Some((*id, path.to_string(), value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.values.len().saturating_sub(self.pos);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for IntoIter {}

// Implement IntoIterator for owned FileEntryMap
impl IntoIterator for FileEntryMap {
    type Item = (u64, String, FileEntry);
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            id_map: self.id_map,
            path_map: self.path_map,
            values: self.values,
            pos: 0,
        }
    }
}

// Implement IntoIterator for &FileEntryMap
impl<'a> IntoIterator for &'a FileEntryMap {
    type Item = (u64, &'a str, &'a FileEntry);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::structs::{BlockDataState, Directory, FileType};
    use indexmap::IndexMap;

    fn entry() -> FileEntry {
        FileEntry {
            file_type: FileType::Data,
            block_data: BlockDataState::Decrypted(vec![]),
            created: 0,
            modified: 0,
            file_size: 0,
            permissions: 0o644,
            references: vec![],
            symlink_target: None,
        }
    }

    fn assert_indexes_consistent(map: &FileEntryMap) {
        assert_eq!(map.id_map.len(), map.values.len());
        assert_eq!(map.path_map.len(), map.values.len());
        assert_eq!(map.ordered_path_map.len(), map.values.len());
        for (index, ((id, id_index), (path, path_index))) in
            map.id_map.iter().zip(map.path_map.iter()).enumerate()
        {
            assert_eq!(*id, map.get_id_by_path(path).unwrap());
            assert_eq!(index, *id_index);
            assert_eq!(index, *path_index);
        }
        for ordered_index in map.ordered_path_map.values() {
            assert!(map.values.get(*ordered_index).is_some());
        }
    }

    #[test]
    fn file_entry_map_indexes_survive_clone_extend_and_retain() {
        let mut map = FileEntryMap::new();
        for (id, path) in [(4, "a!"), (2, "a/child"), (7, "a")] {
            map.insert(Key::new(id, path), entry()).unwrap();
        }
        assert_indexes_consistent(&map);

        let clone = map.clone();
        assert_indexes_consistent(&clone);

        let mut extended = FileEntryMap::new();
        extended.extend(clone).unwrap();
        assert_indexes_consistent(&extended);
        extended.retain_mut(|id, _, _| id != 2).unwrap();
        assert_indexes_consistent(&extended);
        assert_eq!(
            extended
                .iter()
                .map(|(id, path, _)| (id, path))
                .collect::<Vec<_>>(),
            [(4, "a!"), (7, "a")]
        );
    }

    #[test]
    fn file_entry_map_duplicate_errors_do_not_mutate_indexes() {
        let mut map = FileEntryMap::new();
        map.insert(Key::new(1, "first"), entry()).unwrap();
        let expected = map.clone();

        assert!(matches!(
            map.insert(Key::new(1, "second"), entry()),
            Err(PithosError::DuplicateFileId(_))
        ));
        assert_eq!(map, expected);
        assert!(matches!(
            map.insert(Key::new(2, "first"), entry()),
            Err(PithosError::PathOccupied(_))
        ));
        assert_eq!(map, expected);
        assert_indexes_consistent(&map);
    }

    #[test]
    fn file_entry_map_preserves_insertion_order_and_shares_path_storage() {
        let mut map = FileEntryMap::new();
        for (id, path) in [(3, "third"), (1, "first"), (2, "second")] {
            map.insert(Key::new(id, path), entry()).unwrap();
        }

        assert_eq!(
            map.iter()
                .map(|(id, path, _)| (id, path))
                .collect::<Vec<_>>(),
            [(3, "third"), (1, "first"), (2, "second")]
        );
        let directory = Directory {
            identifier: *b"PITHOSDR",
            parent_directory_offset: None,
            files: map.clone(),
            blocks: IndexMap::new(),
            relations: vec![],
            encryption: IndexMap::new(),
            dir_len: 0,
            crc32: 0,
        };
        let mut serialized = Vec::new();
        directory.serialize(&mut serialized).unwrap();
        let path_position = |path: &[u8]| {
            serialized
                .windows(path.len())
                .position(|window| window == path)
                .unwrap()
        };
        assert!(
            path_position(b"\x05third") < path_position(b"\x05first")
                && path_position(b"\x05first") < path_position(b"\x06second")
        );

        assert_eq!(
            map.clone()
                .into_iter()
                .map(|(id, path, _)| (id, path))
                .collect::<Vec<_>>(),
            [
                (3, "third".to_string()),
                (1, "first".to_string()),
                (2, "second".to_string())
            ]
        );
        for path in map.path_map.keys() {
            let ordered = map
                .ordered_path_map
                .keys()
                .find(|ordered| ordered.0 == *path)
                .unwrap();
            assert!(Arc::ptr_eq(path, &ordered.0));
            assert!(map.get_by_path(path).is_some());
            assert!(map.get_id_by_path(path).is_some());
        }
    }
}
