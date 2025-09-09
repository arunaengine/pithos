//! RO-Crate validation framework with configurable strictness levels.

use crate::entity::EntityTrait;
use crate::error::{ValidationError, ValidationWarning};
use crate::metadata::Metadata;
use crate::types::ROCrate;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

lazy_static! {
    pub static ref EMAIL_REGEX: Regex =Regex::new(r#"(?im)(?:[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#).expect("Regex must be valid");
}

/// Validation strictness levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationLevel {
    /// Permissive - only warnings for non-critical issues
    Permissive,
    /// Standard - enforce RO-Crate specification compliance
    Standard,
    /// Strict - full specification compliance with no warnings
    Strict,
}

impl Default for ValidationLevel {
    fn default() -> Self {
        Self::Standard
    }
}

/// Validation report containing errors and warnings.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Validation level used
    pub level: ValidationLevel,
    /// List of validation errors
    pub errors: Vec<ValidationError>,
    /// List of validation warnings
    pub warnings: Vec<ValidationWarning>,
    /// Number of entities validated
    pub entity_count: usize,
    /// Whether validation passed
    pub is_valid: bool,
}

impl ValidationReport {
    /// Create a new validation report.
    pub fn new(level: ValidationLevel) -> Self {
        Self {
            level,
            errors: Vec::new(),
            warnings: Vec::new(),
            entity_count: 0,
            is_valid: true,
        }
    }

    /// Add an error to the report.
    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
        self.is_valid = false;
    }

    /// Add a warning to the report.
    pub fn add_warning(&mut self, warning: ValidationWarning) {
        self.warnings.push(warning.clone());

        // In strict mode, warnings become errors
        if self.level == ValidationLevel::Strict {
            self.add_error(ValidationError::JsonLdStructure(warning.message));
        }
    }

    /// Check if validation passed.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Get all errors.
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    /// Get all warnings.
    pub fn warnings(&self) -> &[ValidationWarning] {
        &self.warnings
    }

    /// Get the number of errors.
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Get the number of warnings.
    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }

    /// Merge another report into this one.
    pub fn merge(&mut self, other: ValidationReport) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
        self.entity_count += other.entity_count;
        self.is_valid = self.is_valid && other.is_valid;
    }

    /// Create a summary string of the validation results.
    pub fn summary(&self) -> String {
        if self.is_valid {
            format!(
                "Validation passed: {} entities validated, {} warnings",
                self.entity_count,
                self.warning_count()
            )
        } else {
            format!(
                "Validation failed: {} errors, {} warnings across {} entities",
                self.error_count(),
                self.warning_count(),
                self.entity_count
            )
        }
    }
}

/// Main validator for RO-Crate structures.
pub struct ROCrateValidator {
    level: ValidationLevel,
    report: ValidationReport,
}

impl ROCrateValidator {
    /// Create a new validator with the specified level.
    pub fn new(level: ValidationLevel) -> Self {
        Self {
            level,
            report: ValidationReport::new(level),
        }
    }

    /// Validate a complete RO-Crate.
    pub fn validate(&mut self, crate_data: &ROCrate) -> ValidationReport {
        self.report = ValidationReport::new(self.level);
        self.report.entity_count = crate_data.entity_count();

        // Validate metadata structure
        self.validate_metadata(crate_data.metadata());

        // Validate root data entity
        self.validate_root_entity(crate_data.root_data_entity());

        // Validate data entities
        for entity in crate_data.data_entities().values() {
            self.validate_data_entity(entity);
        }

        // Validate contextual entities
        for entity in crate_data.contextual_entities().values() {
            self.validate_contextual_entity(entity);
        }

        // Validate entity relationships
        self.validate_relationships(crate_data);

        // Validate file references
        self.validate_file_references(crate_data);

        std::mem::take(&mut self.report)
    }

    /// Validate metadata structure and required entities.
    fn validate_metadata(&mut self, metadata: &Metadata) {
        // Validate basic structure
        if let Err(error) = metadata.validate_structure() {
            self.report.add_error(error);
            return;
        }

        // Check conformsTo property
        if let Some(conforms_to) = metadata.conforms_to() {
            if !crate::metadata::profiles::includes_rocrate_1_2(&conforms_to) {
                self.report.add_warning(ValidationWarning::new(
                    "conformsTo does not include RO-Crate 1.2 specification",
                ));
            }
        } else {
            match self.level {
                ValidationLevel::Permissive => {
                    self.report.add_warning(ValidationWarning::for_entity(
                        "Missing conformsTo property",
                        "ro-crate-metadata.json",
                    ));
                }
                ValidationLevel::Standard | ValidationLevel::Strict => {
                    self.report.add_error(ValidationError::missing_property(
                        "ro-crate-metadata.json",
                        "conformsTo",
                    ));
                }
            }
        }

        // Validate metadata descriptor 'about' property
        if let Some(descriptor) = metadata.get_metadata_descriptor() {
            match descriptor.get_property("about") {
                Some(Value::Object(obj)) => {
                    if obj.get("@id").and_then(|v| v.as_str()) != Some("./") {
                        self.report
                            .add_error(ValidationError::invalid_property_value(
                                "ro-crate-metadata.json",
                                "about",
                                "Must reference the root data entity (./)",
                            ));
                    }
                }
                None => {
                    self.report.add_error(ValidationError::missing_property(
                        "ro-crate-metadata.json",
                        "about",
                    ));
                }
                _ => {
                    self.report
                        .add_error(ValidationError::invalid_property_value(
                            "ro-crate-metadata.json",
                            "about",
                            "Must be an object with @id property",
                        ));
                }
            }
        }
    }

    /// Validate the root data entity.
    fn validate_root_entity(&mut self, root: &crate::entity::RootDataEntity) {
        // Check required types
        if !root.inner.has_type("Dataset") {
            self.report.add_error(ValidationError::invalid_entity_type(
                "./",
                root.entity_type().join(", "),
                "Root data entity must have type 'Dataset'",
            ));
        }

        // In strict mode, require name and description
        if self.level == ValidationLevel::Strict {
            if root.name().is_none() {
                self.report
                    .add_error(ValidationError::missing_property("./", "name"));
            }
            if root.description().is_none() {
                self.report
                    .add_error(ValidationError::missing_property("./", "description"));
            }
        } else if self.level == ValidationLevel::Standard && root.name().is_none() {
            self.report.add_warning(ValidationWarning::for_property(
                "Root data entity should have a name",
                "./",
                "name",
            ));
        }

        // Validate dateCreated format if present
        if let Some(date) = root.date_created()
            && !self.is_valid_date_format(date)
        {
            self.report
                .add_error(ValidationError::invalid_property_value(
                    "./",
                    "dateCreated",
                    "Must be in ISO 8601 format",
                ));
        }
    }

    /// Validate a data entity.
    fn validate_data_entity(&mut self, entity: &crate::entity::DataEntity) {
        // File entities should have encoding format
        if entity.is_file() && entity.encoding_format().is_none() {
            match self.level {
                ValidationLevel::Permissive => {
                    self.report.add_warning(ValidationWarning::for_property(
                        "File entity should specify encodingFormat",
                        entity.id(),
                        "encodingFormat",
                    ));
                }
                ValidationLevel::Standard | ValidationLevel::Strict => {
                    self.report.add_error(ValidationError::missing_property(
                        entity.id(),
                        "encodingFormat",
                    ));
                }
            }
        }

        // Check for reasonable content size
        if let Some(size) = entity.content_size()
            && size == 0
        {
            self.report.add_warning(ValidationWarning::for_property(
                "Content size is zero",
                entity.id(),
                "contentSize",
            ));
        }

        // Validate SHA256 format if present
        if let Some(hash) = entity.sha256()
            && !self.is_valid_sha256(hash)
        {
            self.report
                .add_error(ValidationError::invalid_property_value(
                    entity.id(),
                    "sha256",
                    "Must be a valid SHA-256 hash (64 hexadecimal characters)",
                ));
        }
    }

    /// Validate a contextual entity.
    fn validate_contextual_entity(&mut self, entity: &crate::entity::ContextualEntity) {
        // Person entities should have a name
        if entity.is_person() && entity.name().is_none() {
            match self.level {
                ValidationLevel::Permissive => {
                    self.report.add_warning(ValidationWarning::for_property(
                        "Person entity should have a name",
                        entity.id(),
                        "name",
                    ));
                }
                ValidationLevel::Standard | ValidationLevel::Strict => {
                    self.report
                        .add_error(ValidationError::missing_property(entity.id(), "name"));
                }
            }
        }

        // Validate email format if present
        if let Some(email) = entity.email()
            && !self.is_valid_email(email)
        {
            self.report
                .add_error(ValidationError::invalid_property_value(
                    entity.id(),
                    "email",
                    "Must be a valid email address",
                ));
        }

        // Validate URL format if present
        if let Some(url_result) = entity.url()
            && url_result.is_err()
        {
            self.report
                .add_error(ValidationError::invalid_property_value(
                    entity.id(),
                    "url",
                    "Must be a valid URL",
                ));
        }
    }

    /// Validate entity relationships and references.
    fn validate_relationships(&mut self, crate_data: &ROCrate) {
        let all_entity_ids: HashSet<String> = crate_data.entity_ids().into_iter().collect();

        // Validate hasPart references in root entity
        for part_id in crate_data.root_data_entity().has_part() {
            if !all_entity_ids.contains(&part_id) {
                self.report.add_error(ValidationError::invalid_reference(
                    "./",
                    &part_id,
                    "Referenced entity does not exist",
                ));
            }
        }

        // Validate author references in root entity
        for author_id in crate_data.root_data_entity().authors() {
            if !all_entity_ids.contains(&author_id) {
                self.report.add_error(ValidationError::invalid_reference(
                    "./",
                    &author_id,
                    "Referenced author entity does not exist",
                ));
            }
        }

        // Validate affiliation references in person entities
        for entity in crate_data.contextual_entities().values() {
            if entity.is_person() {
                for affiliation_id in entity.affiliation() {
                    if !all_entity_ids.contains(&affiliation_id) {
                        self.report.add_error(ValidationError::invalid_reference(
                            entity.id(),
                            &affiliation_id,
                            "Referenced affiliation entity does not exist",
                        ));
                    }
                }
            }
        }
    }

    /// Validate file references and accessibility.
    fn validate_file_references(&mut self, crate_data: &ROCrate) {
        // In a complete implementation, this would check if files exist
        // For now, we'll just validate that file entities have proper paths

        for entity in crate_data.data_entities().values() {
            if entity.is_file() {
                let file_id = entity.id();

                // Check for absolute paths (should be relative)
                if file_id.starts_with('/') || file_id.contains("..") {
                    self.report
                        .add_error(ValidationError::invalid_property_value(
                            entity.id(),
                            "@id",
                            "File paths should be relative and not contain '..' segments",
                        ));
                }

                // Check for suspicious file paths
                if file_id.contains("ro-crate-metadata.json") && file_id != "ro-crate-metadata.json"
                {
                    self.report.add_warning(ValidationWarning::for_entity(
                        "Suspicious file path containing metadata filename",
                        entity.id(),
                    ));
                }
            }
        }
    }

    /// Validate ISO 8601 date format (simplified).
    fn is_valid_date_format(&self, date: &str) -> bool {
        // Simplified validation - in a real implementation, use a proper date parsing library
        date.len() >= 10 && date.chars().nth(4) == Some('-') && date.chars().nth(7) == Some('-')
    }

    /// Validate SHA-256 hash format.
    fn is_valid_sha256(&self, hash: &str) -> bool {
        hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Validate email format (simplified).
    fn is_valid_email(&self, email: &str) -> bool {
        EMAIL_REGEX.is_match(email)
        //email.contains('@') && email.contains('.') && email.len() > 5
    }
}

/// Convenience function to validate an RO-Crate.
pub fn validate_rocrate(crate_data: &ROCrate, level: ValidationLevel) -> ValidationReport {
    let mut validator = ROCrateValidator::new(level);
    validator.validate(crate_data)
}

/// Validate just the metadata structure.
pub fn validate_metadata(metadata: &Metadata, level: ValidationLevel) -> ValidationReport {
    let mut validator = ROCrateValidator::new(level);
    validator.validate_metadata(metadata);
    validator.report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ROCrateBuilder;
    use crate::entity::DataEntity;

    #[test]
    fn test_validation_levels() {
        let crate_data = ROCrateBuilder::new().build().unwrap();

        let permissive = validate_rocrate(&crate_data, ValidationLevel::Permissive);
        let standard = validate_rocrate(&crate_data, ValidationLevel::Standard);
        let strict = validate_rocrate(&crate_data, ValidationLevel::Strict);

        // Strict should have more issues than standard, standard more than permissive
        assert!(strict.error_count() >= standard.error_count());
        assert!(standard.error_count() >= permissive.error_count());
    }

    #[test]
    fn test_entity_validation() {
        let mut validator = ROCrateValidator::new(ValidationLevel::Standard);

        // Test file entity without encoding format
        let file_entity = DataEntity::new("data/file.txt");
        validator.validate_data_entity(&file_entity);

        assert!(validator.report.error_count() > 0);
    }

    #[test]
    fn test_reference_validation() {
        let mut crate_data = ROCrate::new();
        crate_data
            .root_data_entity_mut()
            .add_author("nonexistent-person");

        let report = validate_rocrate(&crate_data, ValidationLevel::Standard);
        assert!(!report.is_valid());
        assert!(
            report
                .errors()
                .iter()
                .any(|e| matches!(e, ValidationError::InvalidReference { .. }))
        );
    }

    #[test]
    fn test_sha256_validation() {
        let validator = ROCrateValidator::new(ValidationLevel::Standard);

        assert!(
            validator.is_valid_sha256(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
        );
        assert!(!validator.is_valid_sha256("invalid-hash"));
        assert!(
            !validator
                .is_valid_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85")
        ); // too short
    }

    #[test]
    fn test_email_validation() {
        let validator = ROCrateValidator::new(ValidationLevel::Standard);

        assert!(validator.is_valid_email("test@example.com"));
        assert!(!validator.is_valid_email("invalid-email"));
        assert!(!validator.is_valid_email("@example.com"));
    }

    #[test]
    fn test_validation_report() {
        let mut report = ValidationReport::new(ValidationLevel::Standard);

        assert!(report.is_valid());
        assert_eq!(report.error_count(), 0);

        report.add_error(ValidationError::missing_property("entity1", "name"));
        assert!(!report.is_valid());
        assert_eq!(report.error_count(), 1);

        report.add_warning(ValidationWarning::new("Test warning"));
        assert_eq!(report.warning_count(), 1);
    }
}
