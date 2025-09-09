//! Builder for programmatically creating RO-Crates.

use crate::entity::{ContextualEntity, DataEntity, EntityTrait, RootDataEntity};
use crate::error::{ROCrateError, ValidationError};
use crate::metadata::{Metadata, ROCRATE_1_2};
use crate::types::ROCrate;
use crate::validation::{ValidationLevel, validate_rocrate};
use std::collections::HashMap;

/// Builder for creating RO-Crates programmatically.
#[derive(Debug)]
pub struct ROCrateBuilder {
    root_entity: RootDataEntity,
    data_entities: HashMap<String, DataEntity>,
    contextual_entities: HashMap<String, ContextualEntity>,
    validation_level: ValidationLevel,
    conforms_to: Vec<String>,
}

impl ROCrateBuilder {
    /// Create a new RO-Crate builder.
    pub fn new() -> Self {
        Self {
            root_entity: RootDataEntity::new(),
            data_entities: HashMap::new(),
            contextual_entities: HashMap::new(),
            validation_level: ValidationLevel::Standard,
            conforms_to: vec![ROCRATE_1_2.to_string()],
        }
    }

    /// Set the name of the RO-Crate.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.root_entity.set_name(name);
        self
    }

    /// Set the description of the RO-Crate.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.root_entity.set_description(description);
        self
    }

    /// Set the creation date of the RO-Crate.
    pub fn with_date_created(mut self, date: impl Into<String>) -> Self {
        self.root_entity.set_date_created(date);
        self
    }

    /// Set the license of the RO-Crate.
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.root_entity.set_license(license);
        self
    }

    /// Add an author to the RO-Crate.
    pub fn with_author(mut self, author_id: impl Into<String>) -> Self {
        self.root_entity.add_author(author_id);
        self
    }

    /// Add a data entity to the RO-Crate.
    pub fn add_data_entity(mut self, entity: DataEntity) -> Self {
        let id = entity.id().to_string();
        self.root_entity.add_part(&id);
        self.data_entities.insert(id, entity);
        self
    }

    /// Add a contextual entity to the RO-Crate.
    pub fn add_contextual_entity(mut self, entity: ContextualEntity) -> Self {
        let id = entity.id().to_string();
        self.contextual_entities.insert(id, entity);
        self
    }

    /// Add a file entity with the given path.
    pub fn add_file<P: Into<String>>(self, path: P) -> FileEntityBuilder<Self> {
        FileEntityBuilder::new(self, path.into())
    }

    /// Add a dataset entity with the given ID.
    pub fn add_dataset<P: Into<String>>(self, id: P) -> DatasetEntityBuilder<Self> {
        DatasetEntityBuilder::new(self, id.into())
    }

    /// Add a person entity with the given ID.
    pub fn add_person<P: Into<String>>(self, id: P) -> PersonEntityBuilder<Self> {
        PersonEntityBuilder::new(self, id.into())
    }

    /// Add an organization entity with the given ID.
    pub fn add_organization<P: Into<String>>(self, id: P) -> OrganizationEntityBuilder<Self> {
        OrganizationEntityBuilder::new(self, id.into())
    }

    /// Set the validation level for the build process.
    pub fn with_validation_level(mut self, level: ValidationLevel) -> Self {
        self.validation_level = level;
        self
    }

    /// Add a conformsTo specification.
    pub fn add_conforms_to(mut self, spec: impl Into<String>) -> Self {
        self.conforms_to.push(spec.into());
        self
    }

    /// Build the RO-Crate, validating according to the set validation level.
    pub fn build(self) -> Result<ROCrate, ROCrateError> {
        let mut crate_data = ROCrate::new();

        // Set root entity
        *crate_data.root_data_entity_mut() = self.root_entity;

        // Add all entities
        for (_, entity) in self.data_entities {
            crate_data.add_data_entity(entity);
        }

        for (_, entity) in self.contextual_entities {
            crate_data.add_contextual_entity(entity);
        }

        // Create and configure metadata
        let mut metadata = Metadata::create_complete();
        metadata.set_conforms_to(self.conforms_to);
        *crate_data.metadata_mut() = metadata;

        // Validate if not permissive
        if self.validation_level != ValidationLevel::Permissive {
            let report = validate_rocrate(&crate_data, self.validation_level);
            if !report.is_valid() {
                return Err(ROCrateError::Validation(ValidationError::Multiple(
                    report.errors,
                )));
            }
        }

        Ok(crate_data)
    }

    /// Build without validation.
    pub fn build_unchecked(self) -> ROCrate {
        let mut crate_data = ROCrate::new();

        *crate_data.root_data_entity_mut() = self.root_entity;

        for (_, entity) in self.data_entities {
            crate_data.add_data_entity(entity);
        }

        for (_, entity) in self.contextual_entities {
            crate_data.add_contextual_entity(entity);
        }

        let mut metadata = Metadata::create_complete();
        metadata.set_conforms_to(self.conforms_to);
        *crate_data.metadata_mut() = metadata;

        crate_data
    }
}

impl Default for ROCrateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for file entities.
pub struct FileEntityBuilder<T> {
    parent: T,
    entity: DataEntity,
}

impl<T> FileEntityBuilder<T> {
    fn new(parent: T, path: String) -> Self {
        let entity = DataEntity::new(path);
        Self { parent, entity }
    }

    /// Set the name of the file.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.entity.set_name(name);
        self
    }

    /// Set the description of the file.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.entity.set_description(description);
        self
    }

    /// Set the encoding format (MIME type).
    pub fn with_encoding_format(mut self, format: impl Into<String>) -> Self {
        self.entity.set_encoding_format(format);
        self
    }

    /// Set the content size in bytes.
    pub fn with_content_size(mut self, size: u64) -> Self {
        self.entity.set_content_size(size);
        self
    }

    /// Set the SHA-256 hash.
    pub fn with_sha256(mut self, hash: impl Into<String>) -> Self {
        self.entity.set_sha256(hash);
        self
    }
}

impl FileEntityBuilder<ROCrateBuilder> {
    /// Finish building the file entity and return to the crate builder.
    pub fn finish(self) -> ROCrateBuilder {
        self.parent.add_data_entity(self.entity)
    }
}

/// Builder for dataset entities.
pub struct DatasetEntityBuilder<T> {
    parent: T,
    entity: DataEntity,
}

impl<T> DatasetEntityBuilder<T> {
    fn new(parent: T, id: String) -> Self {
        let entity = DataEntity::new_dataset(id);
        Self { parent, entity }
    }

    /// Set the name of the dataset.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.entity.set_name(name);
        self
    }

    /// Set the description of the dataset.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.entity.set_description(description);
        self
    }
}

impl DatasetEntityBuilder<ROCrateBuilder> {
    /// Finish building the dataset entity and return to the crate builder.
    pub fn finish(self) -> ROCrateBuilder {
        self.parent.add_data_entity(self.entity)
    }
}

/// Builder for person entities.
pub struct PersonEntityBuilder<T> {
    parent: T,
    entity: ContextualEntity,
}

impl<T> PersonEntityBuilder<T> {
    fn new(parent: T, id: String) -> Self {
        let entity = ContextualEntity::new_person(id);
        Self { parent, entity }
    }

    /// Set the name of the person.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.entity.set_name(name);
        self
    }

    /// Set the email of the person.
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.entity.set_email(email);
        self
    }

    /// Set the URL/homepage of the person.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.entity.set_url(url);
        self
    }

    /// Add an affiliation.
    pub fn with_affiliation(mut self, org_id: impl Into<String>) -> Self {
        self.entity.add_affiliation(org_id);
        self
    }
}

impl PersonEntityBuilder<ROCrateBuilder> {
    /// Finish building the person entity and return to the crate builder.
    pub fn finish(self) -> ROCrateBuilder {
        self.parent.add_contextual_entity(self.entity)
    }
}

/// Builder for organization entities.
pub struct OrganizationEntityBuilder<T> {
    parent: T,
    entity: ContextualEntity,
}

impl<T> OrganizationEntityBuilder<T> {
    fn new(parent: T, id: String) -> Self {
        let entity = ContextualEntity::new_organization(id);
        Self { parent, entity }
    }

    /// Set the name of the organization.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.entity.set_name(name);
        self
    }

    /// Set the URL of the organization.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.entity.set_url(url);
        self
    }
}

impl OrganizationEntityBuilder<ROCrateBuilder> {
    /// Finish building the organization entity and return to the crate builder.
    pub fn finish(self) -> ROCrateBuilder {
        self.parent.add_contextual_entity(self.entity)
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_builder() {
        let crate_data = ROCrateBuilder::new()
            .with_name("Test Crate")
            .with_description("A test RO-Crate")
            .with_license("MIT")
            .build()
            .unwrap();

        assert_eq!(crate_data.name(), Some("Test Crate"));
        assert_eq!(crate_data.description(), Some("A test RO-Crate"));
        assert_eq!(crate_data.license(), Some("MIT"));
    }

    #[test]
    fn test_builder_with_entities() {
        let crate_data = ROCrateBuilder::new()
            .with_name("Research Data")
            .add_file("data/experiment.csv")
            .with_name("Experiment Results")
            .with_encoding_format("text/csv")
            .with_content_size(1024)
            .finish()
            .add_person("person1")
            .with_name("Alice Smith")
            .with_email("alice@example.com")
            .finish()
            .with_author("person1")
            .build()
            .unwrap();

        assert_eq!(crate_data.data_entities().len(), 1);
        assert_eq!(crate_data.contextual_entities().len(), 1);
        assert_eq!(crate_data.authors(), vec!["person1"]);

        let file = crate_data.get_data_entity("data/experiment.csv").unwrap();
        assert_eq!(file.name(), Some("Experiment Results"));
        assert_eq!(file.encoding_format(), Some("text/csv"));
        assert_eq!(file.content_size(), Some(1024));

        let person = crate_data.get_contextual_entity("person1").unwrap();
        assert_eq!(person.affiliation(), vec!["org1"]);
    }

    #[test]
    fn test_builder_validation() {
        // This should fail validation due to missing required properties
        let result = ROCrateBuilder::new()
            .with_validation_level(ValidationLevel::Strict)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_unchecked() {
        // This should succeed even with invalid data
        let crate_data = ROCrateBuilder::new()
            .build_unchecked();

        assert!(crate_data.entity_count() > 0);
    }

    #[test]
    fn test_complex_builder() {
        let crate_data = ROCrateBuilder::new()
            .with_name("Complex Research Project")
            .with_description("A comprehensive research dataset")
            .with_date_created("2024-01-15")
            .with_license("CC-BY-4.0")
            .add_conforms_to("https://w3id.org/workflowhub/workflow-ro-crate/1.0")
            .add_organization("university")
            .with_name("Research University")
            .with_url("https://research.edu")
            .finish()
            .add_person("researcher1")
            .with_name("Dr. Jane Researcher")
            .with_email("jane@research.edu")
            .with_affiliation("university")
            .finish()
            .add_person("researcher2")
            .with_name("Prof. John Scientist")
            .with_email("john@research.edu")
            .with_affiliation("university")
            .finish()
            .with_author("researcher1")
            .with_author("researcher2")
            .add_dataset("analysis")
            .with_name("Statistical Analysis")
            .with_description("Results of statistical analysis")
            .finish()
            .add_file("data/raw_data.csv")
            .with_name("Raw Experimental Data")
            .with_encoding_format("text/csv")
            .with_content_size(2048)
            .with_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .finish()
            .add_file("results/analysis.pdf")
            .with_name("Analysis Report")
            .with_encoding_format("application/pdf")
            .with_content_size(512000)
            .finish()
            .build()
            .unwrap();

        // Verify the structure
        assert_eq!(crate_data.name(), Some("Complex Research Project"));
        assert_eq!(crate_data.authors().len(), 2);
        assert_eq!(crate_data.data_entities().len(), 3); // 2 files + 1 dataset
        assert_eq!(crate_data.contextual_entities().len(), 3); // 2 people + 1 org

        // Verify relationships
        let researcher1 = crate_data.get_contextual_entity("researcher1").unwrap();
        assert_eq!(researcher1.affiliation(), vec!["university"]);

        let raw_data = crate_data.get_data_entity("data/raw_data.csv").unwrap();
        assert_eq!(raw_data.content_size(), Some(2048));
        assert!(raw_data.sha256().is_some());
    }
}rate_data.get_contextual_entity("person1").unwrap();
assert_eq!(person.name(), Some("Alice Smith"));
assert_eq!(person.email(), Some("alice@example.com"));
}

#[test]
fn test_builder_with_organization() {
    let crate_data = ROCrateBuilder::new()
        .add_organization("org1")
        .with_name("Example University")
        .with_url("https://example.edu")
        .finish()
        .add_person("person1")
        .with_name("Bob Jones")
        .with_affiliation("org1")
        .finish()
        .build()
        .unwrap();

    let org = crate_data.get_contextual_entity("org1").unwrap();
    assert_eq!(org.name(), Some("Example University"));
    assert!(org.is_organization());

    let person = c

 */
