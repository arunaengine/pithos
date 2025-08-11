//! Entity types representing different kinds of RO-Crate entities.

use crate::util::marshall;
use crate::util::time::iso8601;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::time::SystemTime;
use url::Url;

/// Base trait for all RO-Crate entities.
pub trait EntityTrait {
    /// Get the entity ID.
    fn id(&self) -> &str;

    /// Get the entity type(s).
    fn entity_type(&self) -> &[String];

    /// Get all properties as a JSON object.
    fn properties(&self) -> &Map<String, Value>;

    /// Get a specific property value.
    fn get_property(&self, key: &str) -> Option<&Value>;

    /// Set a property value.
    fn set_property(&mut self, key: String, value: Value);
}

/// Generic entity that can represent any RO-Crate entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entity {
    #[serde(rename = "@id")]
    pub id: String,

    #[serde(rename = "@type", with = "marshall")]
    pub entity_type: Vec<String>,

    #[serde(flatten)]
    pub properties: Map<String, Value>,
}

impl Entity {
    /// Create a new entity with the given ID and type.
    pub fn new(id: impl Into<String>, entity_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            entity_type: vec![entity_type.into()],
            properties: Map::new(),
        }
    }

    /// Create a new entity with multiple types.
    pub fn with_types(id: impl Into<String>, types: Vec<String>) -> Self {
        Self {
            id: id.into(),
            entity_type: types,
            properties: Map::new(),
        }
    }

    /// Add an additional type to this entity.
    pub fn add_type(&mut self, entity_type: impl Into<String>) {
        self.entity_type.push(entity_type.into());
    }

    /// Check if this entity has a specific type.
    pub fn has_type(&self, entity_type: &str) -> bool {
        self.entity_type.iter().any(|t| t == entity_type)
    }
}

impl EntityTrait for Entity {
    fn id(&self) -> &str {
        &self.id
    }

    fn entity_type(&self) -> &[String] {
        &self.entity_type
    }

    fn properties(&self) -> &Map<String, Value> {
        &self.properties
    }

    fn get_property(&self, key: &str) -> Option<&Value> {
        self.properties.get(key)
    }

    fn set_property(&mut self, key: String, value: Value) {
        self.properties.insert(key, value);
    }
}

/// Root Data Entity representing the RO-Crate itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootDataEntity {
    #[serde(flatten)]
    pub inner: Entity,
}

impl RootDataEntity {
    /// Create a new root data entity.
    pub fn new() -> Self {
        let mut entity = Entity::new("./", "Dataset");
        entity.set_property(
            "datePublished".to_string(),
            Value::String(iso8601(&SystemTime::now())),
        );
        //entity.add_type("CreativeWork");
        Self { inner: entity }
    }

    /// Get the name of the crate.
    pub fn name(&self) -> Option<&str> {
        self.get_property("name").and_then(|v| v.as_str())
    }

    /// Set the name of the crate.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.set_property("name".to_string(), Value::String(name.into()));
    }

    /// Get the description of the crate.
    pub fn description(&self) -> Option<&str> {
        self.get_property("description").and_then(|v| v.as_str())
    }

    /// Set the description of the crate.
    pub fn set_description(&mut self, description: impl Into<String>) {
        self.set_property("description".to_string(), Value::String(description.into()));
    }

    /// Get the date created.
    pub fn date_created(&self) -> Option<&str> {
        self.get_property("dateCreated").and_then(|v| v.as_str())
    }

    /// Set the date created.
    pub fn set_date_created(&mut self, date: impl Into<String>) {
        self.set_property("dateCreated".to_string(), Value::String(date.into()));
    }

    /// Get the authors as a list of entity IDs.
    pub fn authors(&self) -> Vec<String> {
        match self.get_property("author") {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    v.get("@id")
                        .and_then(|id| id.as_str().map(|s| s.to_string()))
                })
                .collect(),
            Some(Value::Object(obj)) => {
                if let Some(id) = obj.get("@id").and_then(|v| v.as_str()) {
                    vec![id.to_string()]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    /// Add an author by entity ID.
    pub fn add_author(&mut self, author_id: impl Into<String>) {
        let author_ref = serde_json::json!({"@id": author_id.into()});

        match self.get_property("author") {
            Some(Value::Array(_)) => {
                if let Some(Value::Array(arr)) = self.inner.properties.get_mut("author") {
                    arr.push(author_ref);
                }
            }
            Some(_) => {
                // Convert existing single author to array
                if let Some(existing) = self.inner.properties.remove("author") {
                    self.set_property(
                        "author".to_string(),
                        Value::Array(vec![existing, author_ref]),
                    );
                }
            }
            None => {
                self.set_property("author".to_string(), author_ref);
            }
        }
    }

    /// Get the license.
    pub fn license(&self) -> Option<&str> {
        self.get_property("license").and_then(|v| v.as_str())
    }

    /// Set the license.
    pub fn set_license(&mut self, license: impl Into<String>) {
        self.set_property("license".to_string(), Value::String(license.into()));
    }

    /// Get the hasPart property (list of data entities).
    pub fn has_part(&self) -> Vec<String> {
        match self.get_property("hasPart") {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    v.get("@id")
                        .and_then(|id| id.as_str().map(|s| s.to_string()))
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Add a data entity to hasPart.
    pub fn add_part(&mut self, entity_id: impl Into<String>) {
        let part_ref = serde_json::json!({"@id": entity_id.into()});

        match self.get_property("hasPart") {
            Some(Value::Array(_)) => {
                if let Some(Value::Array(arr)) = self.inner.properties.get_mut("hasPart") {
                    arr.push(part_ref);
                }
            }
            None => {
                self.set_property("hasPart".to_string(), Value::Array(vec![part_ref]));
            }
            _ => {
                // Replace non-array value
                self.set_property("hasPart".to_string(), Value::Array(vec![part_ref]));
            }
        }
    }
}

impl Default for RootDataEntity {
    fn default() -> Self {
        Self::new()
    }
}

impl EntityTrait for RootDataEntity {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn entity_type(&self) -> &[String] {
        self.inner.entity_type()
    }

    fn properties(&self) -> &Map<String, Value> {
        self.inner.properties()
    }

    fn get_property(&self, key: &str) -> Option<&Value> {
        self.inner.get_property(key)
    }

    fn set_property(&mut self, key: String, value: Value) {
        self.inner.set_property(key, value);
    }
}

/// Data Entity representing files, datasets, and other data objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEntity {
    #[serde(flatten)]
    inner: Entity,
}

impl DataEntity {
    /// Create a new data entity.
    pub fn new(id: impl Into<String>) -> Self {
        let entity = Entity::new(id, "File");
        Self { inner: entity }
    }

    pub fn content_url(&self) -> Option<Result<Url, url::ParseError>> {
        self.get_property("url")
            .and_then(|v| v.as_str())
            .map(|s| Url::parse(s))
    }

    /// Create a new dataset entity.
    pub fn new_dataset(id: impl Into<String>) -> Self {
        let mut entity = Entity::new(id, "Dataset");
        entity.add_type("CreativeWork");
        Self { inner: entity }
    }

    /// Get the name of the data entity.
    pub fn name(&self) -> Option<&str> {
        self.get_property("name").and_then(|v| v.as_str())
    }

    /// Set the name of the data entity.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.set_property("name".to_string(), Value::String(name.into()));
    }

    /// Get the description.
    pub fn description(&self) -> Option<&str> {
        self.get_property("description").and_then(|v| v.as_str())
    }

    /// Set the description.
    pub fn set_description(&mut self, description: impl Into<String>) {
        self.set_property("description".to_string(), Value::String(description.into()));
    }

    /// Get the encoding format (MIME type).
    pub fn encoding_format(&self) -> Option<&str> {
        self.get_property("encodingFormat").and_then(|v| v.as_str())
    }

    /// Set the encoding format.
    pub fn set_encoding_format(&mut self, format: impl Into<String>) {
        self.set_property("encodingFormat".to_string(), Value::String(format.into()));
    }

    /// Get the content size in bytes.
    pub fn content_size(&self) -> Option<u64> {
        self.get_property("contentSize").and_then(|v| v.as_u64())
    }

    /// Set the content size.
    pub fn set_content_size(&mut self, size: u64) {
        self.set_property("contentSize".to_string(), Value::Number(size.into()));
    }

    /// Get the SHA256 hash.
    pub fn sha256(&self) -> Option<&str> {
        self.get_property("sha256").and_then(|v| v.as_str())
    }

    /// Set the SHA256 hash.
    pub fn set_sha256(&mut self, hash: impl Into<String>) {
        self.set_property("sha256".to_string(), Value::String(hash.into()));
    }

    /// Check if this is a file entity.
    pub fn is_file(&self) -> bool {
        self.inner.has_type("File")
    }

    /// Check if this is a dataset entity.
    pub fn is_dataset(&self) -> bool {
        self.inner.has_type("Dataset")
    }
}

impl EntityTrait for DataEntity {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn entity_type(&self) -> &[String] {
        self.inner.entity_type()
    }

    fn properties(&self) -> &Map<String, Value> {
        self.inner.properties()
    }

    fn get_property(&self, key: &str) -> Option<&Value> {
        self.inner.get_property(key)
    }

    fn set_property(&mut self, key: String, value: Value) {
        self.inner.set_property(key, value);
    }
}

/// Contextual Entity representing people, organizations, places, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualEntity {
    #[serde(flatten)]
    inner: Entity,
}

impl ContextualEntity {
    /// Create a generic contextual entity.
    pub fn new(id: impl Into<String>, entity_type: impl Into<String>) -> Self {
        let entity = Entity::new(id, entity_type);
        Self { inner: entity }
    }

    /// Create a new person entity.
    pub fn new_person(id: impl Into<String>) -> Self {
        let entity = Entity::new(id, "Person");
        Self { inner: entity }
    }

    /// Create a new organization entity.
    pub fn new_organization(id: impl Into<String>) -> Self {
        let entity = Entity::new(id, "Organization");
        Self { inner: entity }
    }

    /// Create a new place entity.
    pub fn new_place(id: impl Into<String>) -> Self {
        let entity = Entity::new(id, "Place");
        Self { inner: entity }
    }

    /// Get the name.
    pub fn name(&self) -> Option<&str> {
        self.get_property("name").and_then(|v| v.as_str())
    }

    /// Set the name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.set_property("name".to_string(), Value::String(name.into()));
    }

    /// Get the email (for Person entities).
    pub fn email(&self) -> Option<&str> {
        self.get_property("email").and_then(|v| v.as_str())
    }

    /// Set the email.
    pub fn set_email(&mut self, email: impl Into<String>) {
        self.set_property("email".to_string(), Value::String(email.into()));
    }

    /// Get the URL.
    pub fn url(&self) -> Option<Result<Url, url::ParseError>> {
        self.get_property("url")
            .and_then(|v| v.as_str())
            .map(|s| Url::parse(s))
    }

    /// Set the URL.
    pub fn set_url(&mut self, url: impl Into<String>) {
        self.set_property("url".to_string(), Value::String(url.into()));
    }

    /// Get the affiliation (for Person entities).
    pub fn affiliation(&self) -> Vec<String> {
        match self.get_property("affiliation") {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    v.get("@id")
                        .and_then(|id| id.as_str().map(|s| s.to_string()))
                })
                .collect(),
            Some(Value::Object(obj)) => {
                if let Some(id) = obj.get("@id").and_then(|v| v.as_str()) {
                    vec![id.to_string()]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    /// Add an affiliation.
    pub fn add_affiliation(&mut self, org_id: impl Into<String>) {
        let affiliation_ref = serde_json::json!({"@id": org_id.into()});

        match self.get_property("affiliation") {
            Some(Value::Array(_)) => {
                if let Some(Value::Array(arr)) = self.inner.properties.get_mut("affiliation") {
                    arr.push(affiliation_ref);
                }
            }
            Some(_) => {
                if let Some(existing) = self.inner.properties.remove("affiliation") {
                    self.set_property(
                        "affiliation".to_string(),
                        Value::Array(vec![existing, affiliation_ref]),
                    );
                }
            }
            None => {
                self.set_property("affiliation".to_string(), affiliation_ref);
            }
        }
    }

    /// Check if this is a person entity.
    pub fn is_person(&self) -> bool {
        self.inner.has_type("Person")
    }

    /// Check if this is an organization entity.
    pub fn is_organization(&self) -> bool {
        self.inner.has_type("Organization")
    }

    /// Check if this is a place entity.
    pub fn is_place(&self) -> bool {
        self.inner.has_type("Place")
    }
}

impl EntityTrait for ContextualEntity {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn entity_type(&self) -> &[String] {
        self.inner.entity_type()
    }

    fn properties(&self) -> &Map<String, Value> {
        self.inner.properties()
    }

    fn get_property(&self, key: &str) -> Option<&Value> {
        self.inner.get_property(key)
    }

    fn set_property(&mut self, key: String, value: Value) {
        self.inner.set_property(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_creation() {
        let entity = Entity::new("test-id", "File");
        assert_eq!(entity.id(), "test-id");
        assert_eq!(entity.entity_type(), &["File"]);
        assert!(entity.has_type("File"));
        assert!(!entity.has_type("Dataset"));
    }

    #[test]
    fn test_root_data_entity() {
        let mut root = RootDataEntity::new();
        assert_eq!(root.id(), "./");
        assert!(root.inner.has_type("Dataset"));

        root.set_name("Test Crate");
        assert_eq!(root.name(), Some("Test Crate"));

        root.add_author("person1");
        root.add_author("person2");
        assert_eq!(root.authors(), vec!["person1", "person2"]);
    }

    #[test]
    fn test_data_entity() {
        let mut data = DataEntity::new("data/file.txt");
        assert_eq!(data.id(), "data/file.txt");
        assert!(data.is_file());
        assert!(!data.is_dataset());

        data.set_name("Test File");
        data.set_encoding_format("text/plain");
        data.set_content_size(1024);

        assert_eq!(data.name(), Some("Test File"));
        assert_eq!(data.encoding_format(), Some("text/plain"));
        assert_eq!(data.content_size(), Some(1024));
    }

    #[test]
    fn test_contextual_entity() {
        let mut person = ContextualEntity::new_person("person1");
        assert_eq!(person.id(), "person1");
        assert!(person.is_person());

        person.set_name("John Doe");
        person.set_email("john@example.com");
        person.add_affiliation("org1");

        assert_eq!(person.name(), Some("John Doe"));
        assert_eq!(person.email(), Some("john@example.com"));
        assert_eq!(person.affiliation(), vec!["org1"]);
    }
}
