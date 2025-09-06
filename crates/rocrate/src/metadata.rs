//! RO-Crate metadata and JSON-LD context handling.

use crate::entity::{Entity, EntityTrait};
use crate::error::{ROCrateError, ValidationError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Standard RO-Crate 1.2 specification URL.
pub const ROCRATE_1_2: &str = "https://w3id.org/ro/crate/1.2";
/// Standard RO-Crate 1.2 context URL.
const ROCRATE_1_2_CONTEXT: &str = "https://w3id.org/ro/crate/1.2/context";

/// Standard RO-Crate 1.1 specification URL.
const _ROCRATE_1_1: &str = "https://w3id.org/ro/crate/1.1";
/// Standard RO-Crate 1.1 context URL.
const ROCRATE_1_1_CONTEXT: &str = "https://w3id.org/ro/crate/1.1/context";

/// Workflow RO-Crate profile.
pub const WORKFLOW_ROCRATE: &str = "https://w3id.org/workflowhub/workflow-ro-crate/1.0";
/// Data Package profile.
pub const DATA_PACKAGE: &str = "https://specs.frictionlessdata.io/data-package/";

/// JSON-LD context for RO-Crate metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Context {
    /// Simple string context URL
    String(String),
    /// Array of context URLs and objects
    Array(Vec<ContextItem>),
    /// Single context object
    Object(Map<String, Value>),
}

/// Item in a JSON-LD context array.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ContextItem {
    /// String URL
    String(String),
    /// Context object
    Object(Map<String, Value>),
}

impl Context {
    /// Create the default RO-Crate context.
    pub fn default_rocrate() -> Self {
        Context::String(ROCRATE_1_2_CONTEXT.to_string())
    }

    /// Create a context with RO-Crate and additional contexts.
    pub fn with_additional(additional: Vec<String>) -> Self {
        let mut items = vec![ContextItem::String(ROCRATE_1_2_CONTEXT.to_string())];
        items.extend(additional.into_iter().map(ContextItem::String));
        Context::Array(items)
    }

    /// Check if this context includes the RO-Crate context.
    pub fn has_rocrate_context(&self) -> bool {
        let ctxs = [ROCRATE_1_2_CONTEXT, ROCRATE_1_1_CONTEXT];

        match self {
            Context::String(s) => ctxs.contains(&s.as_str()),
            Context::Array(items) => items.iter().any(|item| match item {
                ContextItem::String(s) => ctxs.contains(&s.as_str()),
                _ => false,
            }),
            Context::Object(_) => false, // Would need to check the object contents
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::default_rocrate()
    }
}

/// RO-Crate metadata file structure (ro-crate-metadata.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: Context,

    /// JSON-LD graph containing all entities
    #[serde(rename = "@graph")]
    pub graph: Vec<Entity>,
}

impl Metadata {
    /// Create new metadata with default context.
    pub fn new() -> Self {
        Self {
            context: Context::default_rocrate(),
            graph: Vec::new(),
        }
    }

    /// Create metadata with a custom context.
    pub fn with_context(context: Context) -> Self {
        Self {
            context,
            graph: Vec::new(),
        }
    }

    /// Add an entity to the graph.
    pub fn add_entity(&mut self, entity: Entity) {
        self.graph.push(entity);
    }

    /// Remove an entity from the graph by ID.
    pub fn remove_entity(&mut self, id: &str) -> Option<Entity> {
        if let Some(pos) = self.graph.iter().position(|e| e.id == id) {
            Some(self.graph.remove(pos))
        } else {
            None
        }
    }

    /// Get an entity by ID.
    pub fn get_entity(&self, id: &str) -> Option<&Entity> {
        self.graph.iter().find(|e| e.id == id)
    }

    /// Get a mutable reference to an entity by ID.
    pub fn get_entity_mut(&mut self, id: &str) -> Option<&mut Entity> {
        self.graph.iter_mut().find(|e| e.id == id)
    }

    /// Get all entities of a specific type.
    pub fn get_entities_by_type(&self, entity_type: &str) -> Vec<&Entity> {
        self.graph
            .iter()
            .filter(|e| e.has_type(entity_type))
            .collect()
    }

    /// Get the root data entity (should have ID "./").
    pub fn get_root_entity(&self) -> Option<&Entity> {
        self.get_entity("./")
    }

    /// Get the metadata file descriptor entity.
    pub fn get_metadata_descriptor(&self) -> Option<&Entity> {
        self.get_entity("ro-crate-metadata.json")
    }

    /// Validate the basic structure of the metadata.
    pub fn validate_structure(&self) -> Result<(), ValidationError> {
        let mut errors = Vec::new();

        // Check for RO-Crate context
        if !self.context.has_rocrate_context() {
            errors.push(ValidationError::ContextResolution(
                "Missing RO-Crate context in @context".to_string(),
            ));
        }

        // Check for root data entity
        if self.get_root_entity().is_none() {
            errors.push(ValidationError::MissingEntity {
                entity_id: "./".to_string(),
            });
        }

        // Check for metadata file descriptor
        if self.get_metadata_descriptor().is_none() {
            errors.push(ValidationError::MissingEntity {
                entity_id: "ro-crate-metadata.json".to_string(),
            });
        }

        // Validate root entity type
        if let Some(root) = self.get_root_entity()
            && !root.has_type("Dataset")
        {
            errors.push(ValidationError::InvalidEntityType {
                entity_id: "./".to_string(),
                entity_type: root.entity_type.join(", "),
                reason: "Root data entity must have type 'Dataset'".to_string(),
            });
        }

        // Validate metadata descriptor type
        if let Some(descriptor) = self.get_metadata_descriptor()
            && !descriptor.has_type("CreativeWork")
        {
            errors.push(ValidationError::InvalidEntityType {
                entity_id: "ro-crate-metadata.json".to_string(),
                entity_type: descriptor.entity_type.join(", "),
                reason: "Metadata descriptor must have type 'CreativeWork'".to_string(),
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::Multiple(errors))
        }
    }

    /// Get the conformsTo property from the metadata descriptor.
    pub fn conforms_to(&self) -> Option<Vec<String>> {
        self.get_metadata_descriptor()?
            .get_property("conformsTo")
            .and_then(|v| match v {
                Value::Array(arr) => Some(
                    arr.iter()
                        .filter_map(|item| {
                            item.get("@id")
                                .and_then(|id| id.as_str())
                                .map(|s| s.to_string())
                        })
                        .collect(),
                ),
                Value::Object(obj) => obj
                    .get("@id")
                    .and_then(|id| id.as_str())
                    .map(|s| vec![s.to_string()]),
                _ => None,
            })
    }

    /// Set the conformsTo property in the metadata descriptor.
    pub fn set_conforms_to(&mut self, specifications: Vec<String>) {
        if let Some(descriptor) = self.get_entity_mut("ro-crate-metadata.json") {
            let conforms_to = specifications
                .into_iter()
                .map(|spec| serde_json::json!({"@id": spec}))
                .collect::<Vec<_>>();

            descriptor.set_property("conformsTo".to_string(), Value::Array(conforms_to));
        }
    }

    /// Create a complete metadata structure with required entities.
    pub fn create_complete() -> Self {
        let mut metadata = Self::new();

        // Create root data entity
        let mut root = Entity::new("./", "Dataset");
        root.add_type("CreativeWork");
        metadata.add_entity(root);

        // Create metadata file descriptor
        let mut descriptor = Entity::new("ro-crate-metadata.json", "CreativeWork");
        descriptor.set_property(
            "conformsTo".to_string(),
            serde_json::json!({
                "@id": ROCRATE_1_2
            }),
        );
        descriptor.set_property(
            "about".to_string(),
            serde_json::json!({
                "@id": "./"
            }),
        );
        metadata.add_entity(descriptor);

        metadata
    }

    /// Convert to JSON string.
    pub fn to_json_string(&self) -> Result<String, ROCrateError> {
        serde_json::to_string_pretty(self).map_err(ROCrateError::Json)
    }

    /// Parse from JSON string.
    pub fn from_json_string(json: &str) -> Result<Self, ROCrateError> {
        serde_json::from_str(json).map_err(ROCrateError::Json)
    }

    /// Get entity count.
    pub fn entity_count(&self) -> usize {
        self.graph.len()
    }

    /// Check if an entity exists.
    pub fn has_entity(&self, id: &str) -> bool {
        self.graph.iter().any(|e| e.id == id)
    }

    /// Get all entity IDs.
    pub fn entity_ids(&self) -> Vec<&str> {
        self.graph.iter().map(|e| e.id.as_str()).collect()
    }

    /// Clear all entities from the graph.
    pub fn clear(&mut self) {
        self.graph.clear();
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper functions for working with RO-Crate profiles and specifications.
pub mod profiles {
    use crate::metadata::{ROCRATE_1_2, WORKFLOW_ROCRATE};

    /// Check if a conformsTo list includes RO-Crate 1.2.
    pub fn includes_rocrate_1_2(conforms_to: &[String]) -> bool {
        conforms_to.iter().any(|spec| spec == ROCRATE_1_2)
    }

    /// Check if a conformsTo list includes Workflow RO-Crate.
    pub fn includes_workflow_rocrate(conforms_to: &[String]) -> bool {
        conforms_to.iter().any(|spec| spec == WORKFLOW_ROCRATE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let context = Context::default_rocrate();
        assert!(context.has_rocrate_context());

        let context = Context::with_additional(vec!["https://example.com/context".to_string()]);
        assert!(context.has_rocrate_context());
    }

    #[test]
    fn test_metadata_creation() {
        let metadata = Metadata::new();
        assert!(metadata.context.has_rocrate_context());
        assert_eq!(metadata.graph.len(), 0);

        let complete = Metadata::create_complete();
        assert_eq!(complete.graph.len(), 2);
        assert!(complete.get_root_entity().is_some());
        assert!(complete.get_metadata_descriptor().is_some());
    }

    #[test]
    fn test_metadata_validation() {
        let metadata = Metadata::new();
        assert!(metadata.validate_structure().is_err());

        let complete = Metadata::create_complete();
        assert!(complete.validate_structure().is_ok());
    }

    #[test]
    fn test_entity_management() {
        let mut metadata = Metadata::new();
        let entity = Entity::new("test-entity", "Thing");

        metadata.add_entity(entity);
        assert_eq!(metadata.entity_count(), 1);
        assert!(metadata.has_entity("test-entity"));

        let removed = metadata.remove_entity("test-entity");
        assert!(removed.is_some());
        assert_eq!(metadata.entity_count(), 0);
    }

    #[test]
    fn test_conforms_to() {
        let mut metadata = Metadata::create_complete();

        metadata.set_conforms_to(vec![ROCRATE_1_2.to_string(), WORKFLOW_ROCRATE.to_string()]);

        let conforms_to = metadata.conforms_to().unwrap();
        assert!(profiles::includes_rocrate_1_2(&conforms_to));
        assert!(profiles::includes_workflow_rocrate(&conforms_to));
    }
}
