//! Core data structures representing RO-Crate components.

use crate::entity::{ContextualEntity, DataEntity, EntityTrait, RootDataEntity};
use crate::metadata::Metadata;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Main RO-Crate structure containing all entities and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ROCrate {
    /// The JSON-LD metadata describing the crate
    metadata: Metadata,

    /// Data entities (files and datasets)
    data_entities: HashMap<String, DataEntity>,

    /// Contextual entities (people, organizations, etc.)
    contextual_entities: HashMap<String, ContextualEntity>,

    /// The root data entity representing the crate itself
    root_data_entity: RootDataEntity,

    /// Base path for file operations (used internally)
    #[serde(skip)]
    pub base_path: Option<PathBuf>,
}

impl ROCrate {
    /// Create a new empty RO-Crate.
    pub fn new() -> Self {
        Self {
            metadata: Metadata::new(),
            data_entities: HashMap::new(),
            contextual_entities: HashMap::new(),
            root_data_entity: RootDataEntity::new(),
            base_path: None,
        }
    }

    /// Get the metadata of this RO-Crate.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Get a mutable reference to the metadata.
    pub fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    /// Get the root data entity.
    pub fn root_data_entity(&self) -> &RootDataEntity {
        &self.root_data_entity
    }

    /// Get a mutable reference to the root data entity.
    pub fn root_data_entity_mut(&mut self) -> &mut RootDataEntity {
        &mut self.root_data_entity
    }

    /// Get all data entities.
    pub fn data_entities(&self) -> &HashMap<String, DataEntity> {
        &self.data_entities
    }

    /// Get a mutable reference to data entities.
    pub fn data_entities_mut(&mut self) -> &mut HashMap<String, DataEntity> {
        &mut self.data_entities
    }

    /// Get all contextual entities.
    pub fn contextual_entities(&self) -> &HashMap<String, ContextualEntity> {
        &self.contextual_entities
    }

    /// Get a mutable reference to contextual entities.
    pub fn contextual_entities_mut(&mut self) -> &mut HashMap<String, ContextualEntity> {
        &mut self.contextual_entities
    }

    /// Add a data entity to the crate.
    pub fn add_data_entity(&mut self, entity: DataEntity) {
        let id = entity.id().to_string();
        self.data_entities.insert(id, entity);
    }

    /// Add a contextual entity to the crate.
    pub fn add_contextual_entity(&mut self, entity: ContextualEntity) {
        let id = entity.id().to_string();
        self.contextual_entities.insert(id, entity);
    }

    /// Get a data entity by ID.
    pub fn get_data_entity(&self, id: &str) -> Option<&DataEntity> {
        self.data_entities.get(id)
    }

    /// Get a contextual entity by ID.
    pub fn get_contextual_entity(&self, id: &str) -> Option<&ContextualEntity> {
        self.contextual_entities.get(id)
    }

    /// Remove a data entity by ID.
    pub fn remove_data_entity(&mut self, id: &str) -> Option<DataEntity> {
        self.data_entities.remove(id)
    }

    /// Remove a contextual entity by ID.
    pub fn remove_contextual_entity(&mut self, id: &str) -> Option<ContextualEntity> {
        self.contextual_entities.remove(id)
    }

    /// Get the total number of entities in the crate.
    pub fn entity_count(&self) -> usize {
        self.data_entities.len() + self.contextual_entities.len() + 1 // +1 for root
    }

    /// Get all entity IDs.
    pub fn entity_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        ids.push(self.root_data_entity.id().to_string());
        ids.extend(self.data_entities.keys().cloned());
        ids.extend(self.contextual_entities.keys().cloned());
        ids
    }

    /// Check if an entity with the given ID exists.
    pub fn has_entity(&self, id: &str) -> bool {
        id == self.root_data_entity.id()
            || self.data_entities.contains_key(id)
            || self.contextual_entities.contains_key(id)
    }

    /// Set the base path for file operations.
    pub(crate) fn set_base_path(&mut self, path: PathBuf) {
        self.base_path = Some(path);
    }

    /// Get the base path for file operations.
    pub(crate) fn _base_path(&self) -> Option<&PathBuf> {
        self.base_path.as_ref()
    }

    /// Get the name of the RO-Crate from the root data entity.
    pub fn name(&self) -> Option<&str> {
        self.root_data_entity.name()
    }

    /// Get the description of the RO-Crate from the root data entity.
    pub fn description(&self) -> Option<&str> {
        self.root_data_entity.description()
    }

    /// Get the date created of the RO-Crate.
    pub fn date_created(&self) -> Option<&str> {
        self.root_data_entity.date_created()
    }

    /// Get the authors of the RO-Crate.
    pub fn authors(&self) -> Vec<String> {
        self.root_data_entity.authors()
    }

    /// Get the license of the RO-Crate.
    pub fn license(&self) -> Option<&str> {
        self.root_data_entity.license()
    }
}

impl Default for ROCrate {
    fn default() -> Self {
        Self::new()
    }
}

/// Loading mode for RO-Crate operations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum LoadingMode {
    /// Load the entire crate into memory
    #[default]
    InMemory,
    /// Stream large files on demand
    Streaming,
    /// Load entities lazily as requested
    Lazy,
}

/// File reference within an RO-Crate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileReference {
    /// Path relative to the crate root
    pub path: PathBuf,
    /// Size in bytes (if known)
    pub size: Option<u64>,
    /// MIME type (if known)
    pub content_type: Option<String>,
    /// Checksum (if available)
    pub checksum: Option<String>,
}

impl FileReference {
    /// Create a new file reference.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            size: None,
            content_type: None,
            checksum: None,
        }
    }

    /// Set the file size.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Set the content type.
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set the checksum.
    pub fn with_checksum(mut self, checksum: impl Into<String>) -> Self {
        self.checksum = Some(checksum.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rocrate_creation() {
        let crate_data = ROCrate::new();
        assert_eq!(crate_data.entity_count(), 1); // Only root entity
        assert!(crate_data.data_entities().is_empty());
        assert!(crate_data.contextual_entities().is_empty());
    }

    #[test]
    fn test_file_reference() {
        let file_ref = FileReference::new("data/file.txt")
            .with_size(1024)
            .with_content_type("text/plain")
            .with_checksum("sha256:abc123");

        assert_eq!(file_ref.path, PathBuf::from("data/file.txt"));
        assert_eq!(file_ref.size, Some(1024));
        assert_eq!(file_ref.content_type, Some("text/plain".to_string()));
        assert_eq!(file_ref.checksum, Some("sha256:abc123".to_string()));
    }
}
