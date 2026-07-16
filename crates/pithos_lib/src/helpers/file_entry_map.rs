use crate::error::PithosError;
use crate::model::structs::FileEntry;
use indexmap::IndexMap;
use indexmap::map::{Entry, Keys};
use std::fmt::{Debug, Display, Formatter};

/// Values used as keys in a Map, e.g. `HashMap<Key, _>`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Key {
    id: u64,
    path: String,
}

impl Key {
    pub fn new(id: u64, path: impl Into<String>) -> Key {
        Key {
            id,
            path: path.into(),
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
        KeyQuery::Path(self.path.clone())
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
    path_map: IndexMap<String, usize>,
    values: Vec<FileEntry>,
    current_max_id: u64,
}

impl FileEntryMap {
    pub fn new() -> Self {
        Self {
            id_map: IndexMap::new(),
            path_map: IndexMap::new(),
            values: Vec::new(),
            current_max_id: 0,
        }
    }

    pub fn new_with_max(max_id: u64) -> Self {
        Self {
            id_map: IndexMap::new(),
            path_map: IndexMap::new(),
            values: Vec::new(),
            current_max_id: max_id,
        }
    }

    pub fn get_ids_ref(&self) -> &IndexMap<u64, usize> {
        &self.id_map
    }

    pub fn get_paths_ref(&'_ self) -> Keys<'_, String, usize> {
        self.path_map.keys()
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
                let vacant_path_entry = match self.path_map.entry(key.path) {
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
            KeyQuery::Path(file_path) => self.path_map.get(file_path),
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

    pub fn next_free_id(&self, has_parent: bool) -> u64 {
        if self.current_max_id == 0 && self.values.is_empty() && has_parent {
            1
        } else if self.current_max_id == 0 && self.values.is_empty() {
            0
        } else {
            self.current_max_id + 1
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

        Some((*id, path.as_str(), value))
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
    path_map: &'a IndexMap<String, usize>,
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

        Some((*id, path.as_str(), value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}

impl<'a> ExactSizeIterator for IterMut<'a> {}

/// Iterator that yields owned (id, path, FileEntry) tuples
pub struct IntoIter {
    id_map: IndexMap<u64, usize>,
    path_map: IndexMap<String, usize>,
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

        Some((*id, path.clone(), value))
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
