//! RO-Crate readers for directory and ZIP formats.

use crate::entity::{ContextualEntity, DataEntity, Entity, EntityTrait, RootDataEntity};
use crate::error::{ROCrateError, ValidationError};
use crate::metadata::Metadata;
use crate::types::{LoadingMode, ROCrate};
use crate::validation::{ROCrateValidator, ValidationLevel, ValidationReport};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

/// Trait for RO-Crate readers.
pub trait ROCrateReader {
    /// Read the complete RO-Crate.
    fn read_crate(&self) -> Result<ROCrate, ROCrateError>;

    /// Validate the RO-Crate structure without fully loading it.
    fn validate(&self, crate_data: &ROCrate) -> Result<ValidationReport, ROCrateError>;

    /// Read only the metadata.
    fn read_metadata(&self) -> Result<Metadata, ROCrateError>;

    /// Check if the path contains a valid RO-Crate.
    fn is_valid_rocrate(&self) -> bool;
}

/// Reader for directory-based RO-Crates.
pub struct DirectoryReader {
    root_path: PathBuf,
    validation_level: ValidationLevel,
    loading_mode: LoadingMode,
}

impl DirectoryReader {
    /// Create a new directory reader.
    pub fn new<P: AsRef<Path>>(
        path: P,
        validation_level: ValidationLevel,
    ) -> Result<Self, ROCrateError> {
        let root_path = path.as_ref().to_path_buf();

        if !root_path.is_dir() {
            return Err(ROCrateError::InvalidFormat(
                "Path is not a directory".to_string(),
            ));
        }

        Ok(Self {
            root_path,
            validation_level,
            loading_mode: LoadingMode::InMemory,
        })
    }

    /// Set the loading mode.
    pub fn with_loading_mode(mut self, mode: LoadingMode) -> Self {
        self.loading_mode = mode;
        self
    }

    /// Get the path to the metadata file.
    fn metadata_path(&self) -> PathBuf {
        self.root_path.join("ro-crate-metadata.json")
    }

    /// Read file information for data entities.
    fn read_file_info(&self, relative_path: &str) -> Result<Option<(u64, String)>, ROCrateError> {
        let full_path = self.root_path.join(relative_path);

        if !full_path.exists() {
            return Ok(None);
        }

        let metadata = fs::metadata(&full_path)?;
        let size = metadata.len();

        // Try to determine MIME type from extension
        let content_type = self.guess_content_type(&full_path);

        Ok(Some((size, content_type)))
    }

    /// Guess content type from file extension.
    fn guess_content_type(&self, path: &Path) -> String {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => "application/json",
            Some("csv") => "text/csv",
            Some("txt") => "text/plain",
            Some("pdf") => "application/pdf",
            Some("png") => "image/png",
            Some("jpg") | Some("jpeg") => "image/jpeg",
            Some("html") => "text/html",
            Some("xml") => "application/xml",
            Some("zip") => "application/zip",
            _ => "application/octet-stream",
        }
        .to_string()
    }

    /// Convert JSON entity to appropriate entity type.
    fn convert_entity(&self, json_entity: Entity) -> Result<EntityType, ROCrateError> {
        let id = json_entity.id.clone();

        // Determine entity type based on @type and @id
        if id == "ro-crate-metadata.json" {
            Ok(EntityType::Skip) // Skip metadata descriptor
        } else if id == "./" {
            Ok(EntityType::Root(self.convert_to_root_entity(json_entity)?))
        } else if json_entity.has_type("File") || json_entity.has_type("Dataset") {
            Ok(EntityType::Data(self.convert_to_data_entity(json_entity)?))
        } else {
            Ok(EntityType::Contextual(
                self.convert_to_contextual_entity(json_entity)?,
            ))
        }
    }

    /// Convert JSON entity to RootDataEntity.
    fn convert_to_root_entity(&self, entity: Entity) -> Result<RootDataEntity, ROCrateError> {
        let mut root = RootDataEntity::new();
        // Copy properties from the generic entity
        for (key, value) in entity.properties {
            root.set_property(key, value);
        }
        Ok(root)
    }

    /// Convert JSON entity to DataEntity.
    fn convert_to_data_entity(&self, entity: Entity) -> Result<DataEntity, ROCrateError> {
        let mut data_entity = if entity.has_type("Dataset") {
            DataEntity::new_dataset(entity.id.clone())
        } else {
            DataEntity::new(entity.id.clone())
        };

        // Copy properties
        for (key, value) in entity.properties {
            data_entity.set_property(key, value);
        }

        // Add file information if it's a file and exists on disk
        if data_entity.is_file() {
            if let Ok(Some((size, content_type))) = self.read_file_info(&entity.id) {
                if data_entity.content_size().is_none() {
                    data_entity.set_content_size(size);
                }
                if data_entity.encoding_format().is_none() {
                    data_entity.set_encoding_format(content_type);
                }
            }
        }

        Ok(data_entity)
    }

    /// Convert JSON entity to ContextualEntity.
    fn convert_to_contextual_entity(
        &self,
        entity: Entity,
    ) -> Result<ContextualEntity, ROCrateError> {
        let mut contextual_entity = if entity.has_type("Person") {
            ContextualEntity::new_person(entity.id.clone())
        } else if entity.has_type("Organization") {
            ContextualEntity::new_organization(entity.id.clone())
        } else if entity.has_type("Place") {
            ContextualEntity::new_place(entity.id.clone())
        } else {
            ContextualEntity::new(
                entity.id.clone(),
                entity
                    .entity_type
                    .first()
                    .unwrap_or(&"Thing".to_string())
                    .clone(),
            )
        };

        // Copy properties
        for (key, value) in entity.properties {
            contextual_entity.set_property(key, value);
        }

        Ok(contextual_entity)
    }
}

impl ROCrateReader for DirectoryReader {
    fn read_crate(&self) -> Result<ROCrate, ROCrateError> {
        // Read metadata first
        let metadata = self.read_metadata()?;

        let mut crate_data = ROCrate::new();
        crate_data.set_base_path(self.root_path.clone());
        *crate_data.metadata_mut() = metadata.clone();

        // Process all entities from the metadata graph
        for json_entity in metadata.graph {
            match self.convert_entity(json_entity)? {
                EntityType::Root(root) => {
                    *crate_data.root_data_entity_mut() = root;
                }
                EntityType::Data(data) => {
                    crate_data.add_data_entity(data);
                }
                EntityType::Contextual(contextual) => {
                    crate_data.add_contextual_entity(contextual);
                }
                EntityType::Skip => {
                    // Skip metadata descriptor
                }
            }
        }

        // Validate if required
        if self.validation_level != ValidationLevel::Permissive {
            let report = self.validate(&crate_data)?;
            if !report.is_valid() && self.validation_level == ValidationLevel::Strict {
                return Err(ROCrateError::Validation(ValidationError::Multiple(
                    report.errors,
                )));
            }
        }

        Ok(crate_data)
    }

    fn validate(&self, crate_data: &ROCrate) -> Result<ValidationReport, ROCrateError> {
        let mut validator = ROCrateValidator::new(self.validation_level);
        Ok(validator.validate(crate_data))
    }

    fn read_metadata(&self) -> Result<Metadata, ROCrateError> {
        let metadata_path = self.metadata_path();

        if !metadata_path.exists() {
            return Err(ROCrateError::MissingFile(
                "ro-crate-metadata.json".to_string(),
            ));
        }

        let content = fs::read_to_string(&metadata_path)?;
        Metadata::from_json_string(&content)
    }

    fn is_valid_rocrate(&self) -> bool {
        self.metadata_path().exists()
    }
}

/// Reader for ZIP-based RO-Crates.
pub struct ZipReader {
    zip_path: PathBuf,
    validation_level: ValidationLevel,
    loading_mode: LoadingMode,
}

impl ZipReader {
    /// Create a new ZIP reader.
    pub fn new<P: AsRef<Path>>(
        path: P,
        validation_level: ValidationLevel,
    ) -> Result<Self, ROCrateError> {
        let zip_path = path.as_ref().to_path_buf();

        if !zip_path.exists() {
            return Err(ROCrateError::InvalidFormat(
                "ZIP file does not exist".to_string(),
            ));
        }

        Ok(Self {
            zip_path,
            validation_level,
            loading_mode: LoadingMode::InMemory,
        })
    }

    /// Set the loading mode.
    pub fn with_loading_mode(mut self, mode: LoadingMode) -> Self {
        self.loading_mode = mode;
        self
    }

    /// Open the ZIP archive.
    fn open_archive(&self) -> Result<ZipArchive<fs::File>, ROCrateError> {
        let file = fs::File::open(&self.zip_path)?;
        let archive = ZipArchive::new(file)?;
        Ok(archive)
    }

    /// Read a file from the ZIP archive.
    fn read_file_from_zip(&self, filename: &str) -> Result<String, ROCrateError> {
        let mut archive = self.open_archive()?;
        let mut file = archive
            .by_name(filename)
            .map_err(|_| ROCrateError::MissingFile(filename.to_string()))?;

        let mut content = String::new();
        file.read_to_string(&mut content)?;

        Ok(content)
    }

    /// Get file information from ZIP archive.
    fn get_file_info(&self, filename: &str) -> Result<Option<(u64, String)>, ROCrateError> {
        let mut archive = self.open_archive()?;

        if let Ok(file) = archive.by_name(filename) {
            let size = file.size();
            let content_type = self.guess_content_type_from_name(filename);
            Ok(Some((size, content_type)))
        } else {
            Ok(None)
        }
    }

    /// Guess content type from filename.
    fn guess_content_type_from_name(&self, filename: &str) -> String {
        let path = Path::new(filename);
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => "application/json",
            Some("csv") => "text/csv",
            Some("txt") => "text/plain",
            Some("pdf") => "application/pdf",
            Some("png") => "image/png",
            Some("jpg") | Some("jpeg") => "image/jpeg",
            Some("html") => "text/html",
            Some("xml") => "application/xml",
            _ => "application/octet-stream",
        }
        .to_string()
    }

    /// Convert JSON entity using ZIP file information.
    fn convert_entity(&self, json_entity: Entity) -> Result<EntityType, ROCrateError> {
        let id = json_entity.id.clone();

        if id == "./" {
            Ok(EntityType::Root(self.convert_to_root_entity(json_entity)?))
        } else if id == "ro-crate-metadata.json" {
            Ok(EntityType::Skip)
        } else if json_entity.has_type("File") || json_entity.has_type("Dataset") {
            Ok(EntityType::Data(self.convert_to_data_entity(json_entity)?))
        } else {
            Ok(EntityType::Contextual(
                self.convert_to_contextual_entity(json_entity)?,
            ))
        }
    }

    fn convert_to_root_entity(&self, entity: Entity) -> Result<RootDataEntity, ROCrateError> {
        let mut root = RootDataEntity::new();
        for (key, value) in entity.properties {
            root.set_property(key, value);
        }
        Ok(root)
    }

    fn convert_to_data_entity(&self, entity: Entity) -> Result<DataEntity, ROCrateError> {
        let mut data_entity = if entity.has_type("Dataset") {
            DataEntity::new_dataset(entity.id.clone())
        } else {
            DataEntity::new(entity.id.clone())
        };

        for (key, value) in entity.properties {
            data_entity.set_property(key, value);
        }

        // Add file information from ZIP if available
        if data_entity.is_file() {
            if let Ok(Some((size, content_type))) = self.get_file_info(&entity.id) {
                if data_entity.content_size().is_none() {
                    data_entity.set_content_size(size);
                }
                if data_entity.encoding_format().is_none() {
                    data_entity.set_encoding_format(content_type);
                }
            }
        }

        Ok(data_entity)
    }

    fn convert_to_contextual_entity(
        &self,
        entity: Entity,
    ) -> Result<ContextualEntity, ROCrateError> {
        let mut contextual_entity = if entity.has_type("Person") {
            ContextualEntity::new_person(entity.id.clone())
        } else if entity.has_type("Organization") {
            ContextualEntity::new_organization(entity.id.clone())
        } else if entity.has_type("Place") {
            ContextualEntity::new_place(entity.id.clone())
        } else {
            ContextualEntity::new(
                entity.id.clone(),
                entity
                    .entity_type
                    .first()
                    .unwrap_or(&"Thing".to_string())
                    .clone(),
            )
        };

        for (key, value) in entity.properties {
            contextual_entity.set_property(key, value);
        }

        Ok(contextual_entity)
    }
}

impl ROCrateReader for ZipReader {
    fn read_crate(&self) -> Result<ROCrate, ROCrateError> {
        let metadata = self.read_metadata()?;

        let mut crate_data = ROCrate::new();
        crate_data.set_base_path(self.zip_path.clone());
        *crate_data.metadata_mut() = metadata.clone();

        for json_entity in metadata.graph {
            match self.convert_entity(json_entity)? {
                EntityType::Root(root) => {
                    *crate_data.root_data_entity_mut() = root;
                }
                EntityType::Data(data) => {
                    crate_data.add_data_entity(data);
                }
                EntityType::Contextual(contextual) => {
                    crate_data.add_contextual_entity(contextual);
                }
                EntityType::Skip => {}
            }
        }

        if self.validation_level != ValidationLevel::Permissive {
            let report = self.validate(&crate_data)?;
            if !report.is_valid() && self.validation_level == ValidationLevel::Strict {
                return Err(ROCrateError::Validation(ValidationError::Multiple(
                    report.errors,
                )));
            }
        }

        Ok(crate_data)
    }

    fn validate(&self, crate_data: &ROCrate) -> Result<ValidationReport, ROCrateError> {
        let mut validator = ROCrateValidator::new(self.validation_level);
        Ok(validator.validate(&crate_data))
    }

    fn read_metadata(&self) -> Result<Metadata, ROCrateError> {
        let content = self.read_file_from_zip("ro-crate-metadata.json")?;
        Metadata::from_json_string(&content)
    }

    fn is_valid_rocrate(&self) -> bool {
        self.read_file_from_zip("ro-crate-metadata.json").is_ok()
    }
}

/// Helper enum for entity type conversion.
enum EntityType {
    Root(RootDataEntity),
    Data(DataEntity),
    Contextual(ContextualEntity),
    Skip,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ROCrateWriter;
    use crate::builder::ROCrateBuilder;
    use crate::writer::DirectoryWriter;
    use tempfile::TempDir;

    fn create_test_crate() -> ROCrate {
        ROCrateBuilder::new()
            .with_name("Test Crate")
            .with_description("A test RO-Crate for reader testing")
            .add_file("data/test.txt")
            .with_name("Test File")
            .with_encoding_format("text/plain")
            .finish()
            .add_person("person1")
            .with_name("Test Person")
            .with_email("test@example.com")
            .finish()
            .with_author("person1")
            .build_unchecked()
    }

    #[test]
    fn test_directory_reader() -> Result<(), ROCrateError> {
        let temp_dir = TempDir::new().unwrap();
        let test_crate = create_test_crate();

        // Write the test crate
        let writer = DirectoryWriter::new(temp_dir.path())?;
        writer.write_crate(&test_crate)?;

        // Create test file
        fs::write(temp_dir.path().join("data/test.txt"), "test content").unwrap();

        // Read it back
        let reader = DirectoryReader::new(temp_dir.path(), ValidationLevel::Standard)?;
        assert!(reader.is_valid_rocrate());

        let read_crate = reader.read_crate()?;
        assert_eq!(read_crate.name(), Some("Test Crate"));
        assert_eq!(read_crate.data_entities().len(), 1);
        assert_eq!(read_crate.contextual_entities().len(), 1);

        Ok(())
    }

    #[test]
    fn test_metadata_only_read() -> Result<(), ROCrateError> {
        let temp_dir = TempDir::new().unwrap();
        let test_crate = create_test_crate();

        let writer = DirectoryWriter::new(temp_dir.path())?;
        writer.write_crate(&test_crate)?;

        let reader = DirectoryReader::new(temp_dir.path(), ValidationLevel::Standard)?;
        let metadata = reader.read_metadata()?;

        assert!(metadata.get_root_entity().is_some());
        assert!(metadata.get_metadata_descriptor().is_some());

        Ok(())
    }

    #[test]
    fn test_invalid_directory() {
        let result = DirectoryReader::new("/nonexistent/path", ValidationLevel::Standard);
        assert!(result.is_err());
    }
}
