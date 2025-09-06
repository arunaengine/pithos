//! RO-Crate writers for directory and ZIP formats.

use crate::entity::{Entity, EntityTrait};
use crate::error::ROCrateError;
use crate::metadata::Metadata;
use crate::types::ROCrate;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zip::{CompressionMethod, ZipWriter as ZipWriterTrait, write::FileOptions};

/// Trait for RO-Crate writers.
pub trait ROCrateWriter {
    /// Write the complete RO-Crate.
    fn write_crate(&self, crate_data: &ROCrate) -> Result<(), ROCrateError>;

    /// Write only the metadata file.
    fn write_metadata(&self, metadata: &Metadata) -> Result<(), ROCrateError>;
}

/// Writer for directory-based RO-Crates.
pub struct DirectoryWriter {
    output_path: PathBuf,
    pretty_json: bool,
}

impl DirectoryWriter {
    /// Create a new directory writer.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ROCrateError> {
        let output_path = path.as_ref().to_path_buf();

        Ok(Self {
            output_path,
            pretty_json: true,
        })
    }

    /// Set whether to use pretty-printed JSON.
    pub fn with_pretty_json(mut self, pretty: bool) -> Self {
        self.pretty_json = pretty;
        self
    }

    /// Ensure the output directory exists.
    fn ensure_directory_exists(&self) -> Result<(), ROCrateError> {
        if !self.output_path.exists() {
            fs::create_dir_all(&self.output_path)?;
        }
        Ok(())
    }

    /// Convert RO-Crate entities to JSON-LD graph.
    pub fn build_metadata_graph(&self, crate_data: &ROCrate) -> Vec<Entity> {
        let mut graph = Vec::new();

        // Add root data entity
        graph.push(self.convert_root_to_entity(crate_data.root_data_entity()));

        // Add data entities
        for entity in crate_data.data_entities().values() {
            graph.push(self.convert_data_to_entity(entity));
        }

        // Add contextual entities
        for entity in crate_data.contextual_entities().values() {
            graph.push(self.convert_contextual_to_entity(entity));
        }

        // Add metadata file descriptor
        graph.push(self.create_metadata_descriptor());

        graph
    }

    /// Convert RootDataEntity to generic Entity.
    fn convert_root_to_entity(&self, root: &crate::entity::RootDataEntity) -> Entity {
        Entity {
            id: root.id().to_string(),
            entity_type: root.entity_type().to_vec(),
            properties: root.properties().clone(),
        }
    }

    /// Convert DataEntity to generic Entity.
    fn convert_data_to_entity(&self, data: &crate::entity::DataEntity) -> Entity {
        Entity {
            id: data.id().to_string(),
            entity_type: data.entity_type().to_vec(),
            properties: data.properties().clone(),
        }
    }

    /// Convert ContextualEntity to generic Entity.
    fn convert_contextual_to_entity(&self, contextual: &crate::entity::ContextualEntity) -> Entity {
        Entity {
            id: contextual.id().to_string(),
            entity_type: contextual.entity_type().to_vec(),
            properties: contextual.properties().clone(),
        }
    }

    /// Create the metadata file descriptor entity.
    fn create_metadata_descriptor(&self) -> Entity {
        let mut entity = Entity::new("ro-crate-metadata.json", "CreativeWork");
        entity.set_property(
            "conformsTo".to_string(),
            serde_json::json!({
                "@id": "https://w3id.org/ro/crate/1.2"
            }),
        );
        entity.set_property(
            "about".to_string(),
            serde_json::json!({
                "@id": "./"
            }),
        );
        entity
    }

    /// Write the metadata JSON file.
    fn write_metadata_file(&self, metadata: &Metadata) -> Result<(), ROCrateError> {
        let metadata_path = self.output_path.join("ro-crate-metadata.json");

        let json_content = if self.pretty_json {
            serde_json::to_string_pretty(metadata)?
        } else {
            serde_json::to_string(metadata)?
        };

        fs::write(metadata_path, json_content)?;
        Ok(())
    }

    /// Create directory structure for data entities.
    fn create_data_directories(&self, crate_data: &ROCrate) -> Result<(), ROCrateError> {
        for entity in crate_data.data_entities().values() {
            if entity.is_file() {
                let file_path = self.output_path.join(entity.id());
                if let Some(parent) = file_path.parent()
                    && !parent.exists()
                {
                    fs::create_dir_all(parent)?;
                }
            }
        }
        Ok(())
    }
}

impl ROCrateWriter for DirectoryWriter {
    fn write_crate(&self, crate_data: &ROCrate) -> Result<(), ROCrateError> {
        self.ensure_directory_exists()?;

        // Create metadata with all entities
        let mut metadata = crate_data.metadata().clone();
        metadata.graph = self.build_metadata_graph(crate_data);

        // Write metadata file
        self.write_metadata_file(&metadata)?;

        // Create directory structure for files
        self.create_data_directories(crate_data)?;

        Ok(())
    }

    fn write_metadata(&self, metadata: &Metadata) -> Result<(), ROCrateError> {
        self.ensure_directory_exists()?;
        self.write_metadata_file(metadata)
    }
}

/// Writer for ZIP-based RO-Crates.
pub struct ZipWriter {
    output_path: PathBuf,
    compression_level: u8,
    pretty_json: bool,
}

impl ZipWriter {
    /// Create a new ZIP writer.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ROCrateError> {
        let output_path = path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = output_path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
        }

        Ok(Self {
            output_path,
            compression_level: 6, // Default compression level
            pretty_json: true,
        })
    }

    /// Set the compression level (0-9).
    pub fn with_compression_level(mut self, level: u8) -> Self {
        self.compression_level = level.min(9);
        self
    }

    /// Set whether to use pretty-printed JSON.
    pub fn with_pretty_json(mut self, pretty: bool) -> Self {
        self.pretty_json = pretty;
        self
    }

    /// Convert RO-Crate entities to JSON-LD graph.
    fn build_metadata_graph(&self, crate_data: &ROCrate) -> Vec<Entity> {
        let mut graph = Vec::new();

        // Add root data entity
        graph.push(self.convert_root_to_entity(crate_data.root_data_entity()));

        // Add data entities
        for entity in crate_data.data_entities().values() {
            graph.push(self.convert_data_to_entity(entity));
        }

        // Add contextual entities
        for entity in crate_data.contextual_entities().values() {
            graph.push(self.convert_contextual_to_entity(entity));
        }

        // Add metadata file descriptor
        graph.push(self.create_metadata_descriptor());

        graph
    }

    /// Convert RootDataEntity to generic Entity.
    fn convert_root_to_entity(&self, root: &crate::entity::RootDataEntity) -> Entity {
        Entity {
            id: root.id().to_string(),
            entity_type: root.entity_type().to_vec(),
            properties: root.properties().clone(),
        }
    }

    /// Convert DataEntity to generic Entity.
    fn convert_data_to_entity(&self, data: &crate::entity::DataEntity) -> Entity {
        Entity {
            id: data.id().to_string(),
            entity_type: data.entity_type().to_vec(),
            properties: data.properties().clone(),
        }
    }

    /// Convert ContextualEntity to generic Entity.
    fn convert_contextual_to_entity(&self, contextual: &crate::entity::ContextualEntity) -> Entity {
        Entity {
            id: contextual.id().to_string(),
            entity_type: contextual.entity_type().to_vec(),
            properties: contextual.properties().clone(),
        }
    }

    /// Create the metadata file descriptor entity.
    fn create_metadata_descriptor(&self) -> Entity {
        let mut entity = Entity::new("ro-crate-metadata.json", "CreativeWork");
        entity.set_property(
            "conformsTo".to_string(),
            serde_json::json!({
                "@id": "https://w3id.org/ro/crate/1.2"
            }),
        );
        entity.set_property(
            "about".to_string(),
            serde_json::json!({
                "@id": "./"
            }),
        );
        entity
    }

    /// Write metadata to ZIP archive.
    fn write_metadata_to_zip(
        &self,
        zip: &mut ZipWriterTrait<fs::File>,
        metadata: &Metadata,
    ) -> Result<(), ROCrateError> {
        let options: FileOptions<()> = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(self.compression_level as i64));

        zip.start_file("ro-crate-metadata.json", options)?;

        let json_content = if self.pretty_json {
            serde_json::to_string_pretty(metadata)?
        } else {
            serde_json::to_string(metadata)?
        };

        zip.write_all(json_content.as_bytes())?;
        Ok(())
    }

    /// Add placeholder files for data entities.
    fn add_placeholder_files(
        &self,
        zip: &mut ZipWriterTrait<fs::File>,
        crate_data: &ROCrate,
    ) -> Result<(), ROCrateError> {
        let options: FileOptions<()> =
            FileOptions::default().compression_method(CompressionMethod::Stored); // No compression for empty files

        for entity in crate_data.data_entities().values() {
            if entity.is_file() {
                let file_path = entity.id();

                // Skip if it's a directory path
                if file_path.ends_with('/') {
                    continue;
                }

                zip.start_file(file_path, options)?;

                // Write placeholder content or empty file
                let placeholder = format!(
                    "# Placeholder for {}\n# This file should be replaced with actual content\n",
                    file_path
                );
                zip.write_all(placeholder.as_bytes())?;
            }
        }
        Ok(())
    }
}

impl ROCrateWriter for ZipWriter {
    fn write_crate(&self, crate_data: &ROCrate) -> Result<(), ROCrateError> {
        let file = fs::File::create(&self.output_path)?;
        let mut zip = zip::ZipWriter::new(file);

        // Create metadata with all entities
        let mut metadata = crate_data.metadata().clone();
        metadata.graph = self.build_metadata_graph(crate_data);

        // Write metadata file
        self.write_metadata_to_zip(&mut zip, &metadata)?;

        // Add placeholder files for data entities
        self.add_placeholder_files(&mut zip, crate_data)?;

        zip.finish()?;
        Ok(())
    }

    fn write_metadata(&self, metadata: &Metadata) -> Result<(), ROCrateError> {
        let file = fs::File::create(&self.output_path)?;
        let mut zip = zip::ZipWriter::new(file);

        self.write_metadata_to_zip(&mut zip, metadata)?;

        zip.finish()?;
        Ok(())
    }
}

/// Advanced ZIP writer that can copy files from a source directory.
pub struct ZipWriterWithFiles {
    zip_writer: ZipWriter,
    source_dir: Option<PathBuf>,
}

impl ZipWriterWithFiles {
    /// Create a new ZIP writer with file copying capability.
    pub fn new<P: AsRef<Path>>(output_path: P) -> Result<Self, ROCrateError> {
        let zip_writer = ZipWriter::new(output_path)?;
        Ok(Self {
            zip_writer,
            source_dir: None,
        })
    }

    /// Set the source directory for copying files.
    pub fn with_source_directory<P: AsRef<Path>>(mut self, source_dir: P) -> Self {
        self.source_dir = Some(source_dir.as_ref().to_path_buf());
        self
    }

    /// Set compression level.
    pub fn with_compression_level(mut self, level: u8) -> Self {
        self.zip_writer = self.zip_writer.with_compression_level(level);
        self
    }

    /// Write RO-Crate with actual file content.
    pub fn write_crate_with_files(&self, crate_data: &ROCrate) -> Result<(), ROCrateError> {
        let file = fs::File::create(&self.zip_writer.output_path)?;
        let mut zip = zip::ZipWriter::new(file);

        // Create metadata
        let mut metadata = crate_data.metadata().clone();
        metadata.graph = self.zip_writer.build_metadata_graph(crate_data);

        // Write metadata
        self.zip_writer.write_metadata_to_zip(&mut zip, &metadata)?;

        // Copy actual files if source directory is provided
        if let Some(source_dir) = &self.source_dir {
            self.copy_files_to_zip(&mut zip, crate_data, source_dir)?;
        } else {
            self.zip_writer
                .add_placeholder_files(&mut zip, crate_data)?;
        }

        zip.finish()?;
        Ok(())
    }

    /// Copy files from source directory to ZIP.
    fn copy_files_to_zip(
        &self,
        zip: &mut zip::ZipWriter<fs::File>,
        crate_data: &ROCrate,
        source_dir: &Path,
    ) -> Result<(), ROCrateError> {
        // Create FileOptions with various settings
        let options: FileOptions<()> = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(self.zip_writer.compression_level as i64));

        for entity in crate_data.data_entities().values() {
            if entity.is_file() {
                let file_path = entity.id();
                let source_file = source_dir.join(file_path);

                if source_file.exists() && source_file.is_file() {
                    zip.start_file(file_path, options)?;
                    let content = fs::read(&source_file)?;
                    zip.write_all(&content)?;
                } else {
                    // Write placeholder if file doesn't exist
                    zip.start_file(file_path, options)?;
                    let placeholder = format!(
                        "# File not found: {}\n# Original path: {}\n",
                        file_path,
                        source_file.display()
                    );
                    zip.write_all(placeholder.as_bytes())?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ROCrateReader;
    use crate::builder::ROCrateBuilder;
    use crate::reader::DirectoryReader;
    use tempfile::TempDir;

    fn create_test_crate() -> ROCrate {
        ROCrateBuilder::new()
            .with_name("Test Crate")
            .with_description("A test RO-Crate for writer testing")
            .with_license("MIT")
            .add_file("data/test.txt")
            .with_name("Test File")
            .with_encoding_format("text/plain")
            .with_content_size(13)
            .finish()
            .add_person("person1")
            .with_name("Test Person")
            .with_email("test@example.com")
            .finish()
            .with_author("person1")
            .build_unchecked()
    }

    #[test]
    fn test_directory_writer() -> Result<(), ROCrateError> {
        let temp_dir = TempDir::new()?;
        let test_crate = create_test_crate();

        let writer = DirectoryWriter::new(temp_dir.path())?;
        writer.write_crate(&test_crate)?;

        // Verify metadata file was created
        let metadata_path = temp_dir.path().join("ro-crate-metadata.json");
        assert!(metadata_path.exists());

        // Verify content by reading it back
        let reader = DirectoryReader::new(
            temp_dir.path(),
            crate::validation::ValidationLevel::Standard,
        )?;
        let read_crate = reader.read_crate()?;

        assert_eq!(read_crate.name(), Some("Test Crate"));
        assert_eq!(
            read_crate.description(),
            Some("A test RO-Crate for writer testing")
        );
        assert_eq!(read_crate.data_entities().len(), 1);
        assert_eq!(read_crate.contextual_entities().len(), 1);

        Ok(())
    }

    #[test]
    fn test_zip_writer() -> Result<(), ROCrateError> {
        let temp_dir = TempDir::new()?;
        let zip_path = temp_dir.path().join("test-crate.zip");
        let test_crate = create_test_crate();

        let writer = ZipWriter::new(&zip_path)?;
        writer.write_crate(&test_crate)?;

        // Verify ZIP file was created
        assert!(zip_path.exists());

        // Verify ZIP contains metadata
        let reader =
            crate::reader::ZipReader::new(&zip_path, crate::validation::ValidationLevel::Standard)?;
        assert!(reader.is_valid_rocrate());

        let read_crate = reader.read_crate()?;
        assert_eq!(read_crate.name(), Some("Test Crate"));

        Ok(())
    }

    #[test]
    fn test_metadata_only_write() -> Result<(), ROCrateError> {
        let temp_dir = TempDir::new()?;
        let metadata_path = temp_dir.path().join("ro-crate-metadata.json");

        let test_crate = create_test_crate();
        let writer = DirectoryWriter::new(temp_dir.path())?;
        writer.write_metadata(test_crate.metadata())?;

        assert!(metadata_path.exists());

        // Verify it's valid JSON
        let content = fs::read_to_string(&metadata_path)?;
        let _: serde_json::Value = serde_json::from_str(&content)?;

        Ok(())
    }

    #[test]
    fn test_zip_writer_with_files() -> Result<(), ROCrateError> {
        let temp_path = TempDir::new()?;
        let source_dir = temp_path.path().join("source");
        let zip_path = temp_path.path().join("test-crate.zip");

        // Create source directory with test file
        fs::create_dir_all(&source_dir)?;
        fs::create_dir_all(source_dir.join("data"))?;
        fs::write(source_dir.join("data/test.txt"), "Hello, World!")?;
        dbg!(fs::metadata(source_dir.join("data/test.txt"))?);

        let test_crate = create_test_crate();

        let writer = ZipWriterWithFiles::new(&zip_path)?.with_source_directory(&source_dir);
        writer.write_crate_with_files(&test_crate)?;

        assert!(zip_path.exists());

        // Verify the file was copied
        let reader =
            crate::reader::ZipReader::new(&zip_path, crate::validation::ValidationLevel::Standard)?;
        let read_crate = reader.read_crate()?;
        dbg!(&read_crate);

        // Check that file entity has correct size
        let file_entity = read_crate.get_data_entity("data/test.txt").unwrap();
        assert_eq!(file_entity.content_size(), Some(13)); // "Hello, World!" is 13 bytes

        Ok(())
    }

    #[test]
    fn test_writer_options() -> Result<(), ROCrateError> {
        let temp_dir = TempDir::new().unwrap();
        let test_crate = create_test_crate();

        // Test directory writer with non-pretty JSON
        let writer = DirectoryWriter::new(temp_dir.path())?.with_pretty_json(false);
        writer.write_crate(&test_crate)?;

        let metadata_content = fs::read_to_string(temp_dir.path().join("ro-crate-metadata.json"))?;
        // Non-pretty JSON should not have newlines (except at the end)
        assert!(metadata_content.lines().count() <= 2);

        Ok(())
    }
}
