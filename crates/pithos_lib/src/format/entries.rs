use crate::error::PithosError;
use crate::format::wire::FileEntry;
use indexmap::IndexMap;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound::Excluded;
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
struct OrderedPath(Arc<str>);

impl Ord for OrderedPath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.split('/').cmp(other.0.split('/'))
    }
}

impl PartialOrd for OrderedPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WireEntry {
    id: u64,
    path: Arc<str>,
    entry: FileEntry,
}

/// Format-owned file records with stable wire insertion order and private indexes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WireEntries {
    by_id: IndexMap<u64, usize>,
    by_path: IndexMap<Arc<str>, usize>,
    ordered_paths: BTreeMap<OrderedPath, usize>,
    entries: Vec<WireEntry>,
    maximum_id: u64,
}

impl WireEntries {
    pub(crate) fn new() -> Self {
        Self::with_maximum_id(0)
    }

    pub(crate) fn with_maximum_id(maximum_id: u64) -> Self {
        Self {
            by_id: IndexMap::new(),
            by_path: IndexMap::new(),
            ordered_paths: BTreeMap::new(),
            entries: Vec::new(),
            maximum_id,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn get_by_id(&self, id: u64) -> Option<&FileEntry> {
        self.by_id
            .get(&id)
            .and_then(|index| self.entries.get(*index))
            .map(|entry| &entry.entry)
    }

    pub(crate) fn get_by_path(&self, path: &str) -> Option<&FileEntry> {
        self.by_path
            .get(path)
            .and_then(|index| self.entries.get(*index))
            .map(|entry| &entry.entry)
    }

    pub(crate) fn first_path_after(&self, path: &str) -> Option<&str> {
        let query = OrderedPath(Arc::from(path));
        self.ordered_paths
            .range((Excluded(query), std::ops::Bound::Unbounded))
            .next()
            .map(|(path, _)| path.0.as_ref())
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = (u64, &str, &FileEntry)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.id, entry.path.as_ref(), &entry.entry))
    }

    #[cfg(test)]
    pub(crate) fn iter_ordered(&self) -> impl Iterator<Item = (&str, &FileEntry)> + '_ {
        self.ordered_paths
            .iter()
            .map(|(path, index)| (path.0.as_ref(), &self.entries[*index].entry))
    }

    pub(crate) fn try_for_each_mut<E>(
        &mut self,
        mut operation: impl FnMut(u64, &mut FileEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        for entry in &mut self.entries {
            operation(entry.id, &mut entry.entry)?;
        }
        Ok(())
    }

    pub(crate) fn next_free_id(&self, has_parent: bool) -> Result<u64, PithosError> {
        if self.maximum_id == 0 && self.entries.is_empty() {
            Ok(u64::from(has_parent))
        } else {
            self.maximum_id
                .checked_add(1)
                .ok_or(PithosError::FileIdExhausted)
        }
    }

    pub(crate) fn prevalidate_insert(&self, id: u64, path: &str) -> Result<(), PithosError> {
        if self.by_id.contains_key(&id) {
            return Err(PithosError::DuplicateFileId(format!(
                "File id already occupied: {id}"
            )));
        }
        if self.by_path.contains_key(path) {
            return Err(PithosError::PathOccupied(format!(
                "File path already occupied: {path}"
            )));
        }
        Ok(())
    }

    pub(crate) fn reserve_one(&mut self) -> Result<(), PithosError> {
        let size = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(PithosError::AllocationFailed {
                field: "file entries",
                size: u64::MAX,
            })?;
        self.by_id
            .try_reserve(1)
            .map_err(|_| allocation_failed("file entry ids", size))?;
        self.by_path
            .try_reserve(1)
            .map_err(|_| allocation_failed("file entry paths", size))?;
        self.entries
            .try_reserve(1)
            .map_err(|_| allocation_failed("file entries", size))
    }

    /// Insert only after validation and reservation of the vector-backed indexes.
    pub(crate) fn insert_prepared(&mut self, id: u64, path: impl Into<Arc<str>>, entry: FileEntry) {
        let path = path.into();
        debug_assert!(self.prevalidate_insert(id, &path).is_ok());
        let ordered = OrderedPath(Arc::clone(&path));
        let index = self.entries.len();
        self.entries.push(WireEntry {
            id,
            path: Arc::clone(&path),
            entry,
        });
        self.by_id.insert(id, index);
        self.by_path.insert(path, index);
        self.ordered_paths.insert(ordered, index);
        self.maximum_id = self.maximum_id.max(id);
    }

    pub(crate) fn insert(
        &mut self,
        id: u64,
        path: impl Into<Arc<str>>,
        entry: FileEntry,
    ) -> Result<(), PithosError> {
        let path = path.into();
        self.prevalidate_insert(id, &path)?;
        self.reserve_one()?;
        self.insert_prepared(id, path, entry);
        Ok(())
    }
}

fn allocation_failed(field: &'static str, size: usize) -> PithosError {
    PithosError::AllocationFailed {
        field,
        size: u64::try_from(size).unwrap_or(u64::MAX),
    }
}
