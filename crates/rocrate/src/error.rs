//! Error types for the RO-Crate library.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Main error type for RO-Crate operations.
#[derive(Error, Debug)]
pub enum ROCrateError {
    /// I/O error during file operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing or serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// ZIP file handling error
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    /// URL parsing error
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Invalid RO-Crate format
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Missing required file
    #[error("Missing required file: {0}")]
    MissingFile(String),

    /// Invalid metadata structure
    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),

    /// Entity reference error
    #[error("Entity reference error: {0}")]
    EntityReference(String),

    /// Unsupported operation
    #[error("Unsupported operation: {0}")]
    Unsupported(String),
}

/// Validation-specific error type with detailed context.
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    /// Missing required property
    #[error("Missing required property '{property}' in entity '{entity_id}'")]
    MissingProperty { entity_id: String, property: String },

    /// Invalid property value
    #[error("Invalid value for property '{property}' in entity '{entity_id}': {reason}")]
    InvalidPropertyValue {
        entity_id: String,
        property: String,
        reason: String,
    },

    /// Invalid entity type
    #[error("Invalid entity type '{entity_type}' for entity '{entity_id}': {reason}")]
    InvalidEntityType {
        entity_id: String,
        entity_type: String,
        reason: String,
    },

    /// Missing required entity
    #[error("Missing required entity: {entity_id}")]
    MissingEntity { entity_id: String },

    /// Invalid entity reference
    #[error("Invalid reference from '{from_entity}' to '{to_entity}': {reason}")]
    InvalidReference {
        from_entity: String,
        to_entity: String,
        reason: String,
    },

    /// JSON-LD structure error
    #[error("JSON-LD structure error: {0}")]
    JsonLdStructure(String),

    /// File system structure error
    #[error("File system structure error: {0}")]
    FileSystemStructure(String),

    /// Context resolution error
    #[error("Context resolution error: {0}")]
    ContextResolution(String),

    /// Multiple errors combined
    #[error("Multiple validation errors: {0:?}")]
    Multiple(Vec<ValidationError>),
}

/// Warning type for non-critical validation issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    pub message: String,
    pub entity_id: Option<String>,
    pub property: Option<String>,
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.entity_id, &self.property) {
            (Some(entity), Some(prop)) => {
                write!(
                    f,
                    "Warning in entity '{}' property '{}': {}",
                    entity, prop, self.message
                )
            }
            (Some(entity), None) => {
                write!(f, "Warning in entity '{}': {}", entity, self.message)
            }
            _ => write!(f, "Warning: {}", self.message),
        }
    }
}

/// Result type alias for validation operations.
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Result type alias for general RO-Crate operations.
pub type ROCrateResult<T> = Result<T, ROCrateError>;

impl ValidationError {
    /// Create a new missing property error.
    pub fn missing_property(entity_id: impl Into<String>, property: impl Into<String>) -> Self {
        Self::MissingProperty {
            entity_id: entity_id.into(),
            property: property.into(),
        }
    }

    /// Create a new invalid property value error.
    pub fn invalid_property_value(
        entity_id: impl Into<String>,
        property: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::InvalidPropertyValue {
            entity_id: entity_id.into(),
            property: property.into(),
            reason: reason.into(),
        }
    }

    /// Create a new invalid entity type error.
    pub fn invalid_entity_type(
        entity_id: impl Into<String>,
        entity_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::InvalidEntityType {
            entity_id: entity_id.into(),
            entity_type: entity_type.into(),
            reason: reason.into(),
        }
    }

    /// Create a new missing entity error.
    pub fn missing_entity(entity_id: impl Into<String>) -> Self {
        Self::MissingEntity {
            entity_id: entity_id.into(),
        }
    }

    /// Create a new invalid reference error.
    pub fn invalid_reference(
        from_entity: impl Into<String>,
        to_entity: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::InvalidReference {
            from_entity: from_entity.into(),
            to_entity: to_entity.into(),
            reason: reason.into(),
        }
    }

    /// Combine multiple validation errors into one.
    pub fn multiple(errors: Vec<ValidationError>) -> Self {
        Self::Multiple(errors)
    }
}

impl ValidationWarning {
    /// Create a new validation warning.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            entity_id: None,
            property: None,
        }
    }

    /// Create a warning for a specific entity.
    pub fn for_entity(message: impl Into<String>, entity_id: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            entity_id: Some(entity_id.into()),
            property: None,
        }
    }

    /// Create a warning for a specific entity property.
    pub fn for_property(
        message: impl Into<String>,
        entity_id: impl Into<String>,
        property: impl Into<String>,
    ) -> Self {
        Self {
            message: message.into(),
            entity_id: Some(entity_id.into()),
            property: Some(property.into()),
        }
    }
}
