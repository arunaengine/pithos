//! # RO-Crate Library
//!
//! A Rust library for reading and writing RO-Crate 1.2 compliant research objects.
//!
//! ## Features
//!
//! - Read directory-based and ZIP-based RO-Crates
//! - Create new RO-Crates programmatically
//! - Full RO-Crate 1.2 specification validation
//! - Configurable validation strictness levels
//! - Memory-efficient handling with streaming support
//!
//! ## Quick Start
//!
//! ```ignore
//! use rocrate::{read_rocrate, ValidationLevel};
//!
//! // Read an existing RO-Crate
//! let crate_data = read_rocrate("path/to/rocrate").unwrap();
//!
//! // Access metadata
//! println!("Crate name: {:?}", crate_data.root_data_entity().name());
//! ```

pub mod builder;
pub mod entity;
pub mod error;
pub mod metadata;
pub mod reader;
pub mod types;
mod util;
pub mod validation;
pub mod writer;

// Re-export commonly used types
pub use builder::ROCrateBuilder;
pub use entity::{ContextualEntity, DataEntity, Entity, RootDataEntity};
pub use error::{ROCrateError, ValidationError};
pub use metadata::{Context, Metadata};
pub use reader::{DirectoryReader, ROCrateReader, ZipReader};
pub use types::ROCrate;
pub use validation::{ValidationLevel, ValidationReport};
pub use writer::{DirectoryWriter, ROCrateWriter, ZipWriter};

use std::path::Path;

/// Convenience function to read an RO-Crate from a file system path.
///
/// This function automatically detects whether the path points to a directory
/// or ZIP file and uses the appropriate reader.
///
/// # Arguments
///
/// * `path` - Path to the RO-Crate (directory or ZIP file)
///
/// # Returns
///
/// * `Result<ROCrate, ROCrateError>` - The parsed RO-Crate or an error
///
/// # Examples
///
/// ```ignore
/// use rocrate::read_rocrate;
///
/// // Read a directory-based RO-Crate
/// let crate_data = read_rocrate("./my-research-object").unwrap();
///
/// // Read a ZIP-based RO-Crate
/// let crate_data = read_rocrate("./research-object.zip").unwrap();
/// ```
pub fn read_rocrate<P: AsRef<Path>>(path: P) -> Result<ROCrate, ROCrateError> {
    let path = path.as_ref();

    if path.is_dir() {
        let reader = DirectoryReader::new(path, ValidationLevel::Standard)?;
        reader.read_crate()
    } else if path.extension().map_or(false, |ext| ext == "zip") {
        let reader = ZipReader::new(path, ValidationLevel::Standard)?;
        reader.read_crate()
    } else {
        Err(ROCrateError::InvalidFormat(
            "Path must be a directory or ZIP file".to_string(),
        ))
    }
}

/// Convenience function to write an RO-Crate to a file system path.
///
/// The output format is determined by the file extension:
/// - `.zip` creates a ZIP-based RO-Crate
/// - Otherwise creates a directory-based RO-Crate
///
/// # Arguments
///
/// * `crate_data` - The RO-Crate to write
/// * `path` - Output path
///
/// # Examples
///
/// ```ignore
/// use rocrate::{write_rocrate, ROCrateBuilder};
///
/// let crate_data = ROCrateBuilder::new()
///     .with_name("My Research Object")
///     .build().unwrap();
///
/// // Write as directory
/// write_rocrate(&crate_data, "./output-crate").unwrap();
///
/// // Write as ZIP
/// write_rocrate(&crate_data, "./output-crate.zip").unwrap();
/// ```
pub fn write_rocrate<P: AsRef<Path>>(crate_data: &ROCrate, path: P) -> Result<(), ROCrateError> {
    let path = path.as_ref();

    if path.extension().map_or(false, |ext| ext == "zip") {
        let writer = ZipWriter::new(path)?;
        writer.write_crate(crate_data)
    } else {
        let writer = DirectoryWriter::new(path)?;
        writer.write_crate(crate_data)
    }
}

/// Convenience function to validate an RO-Crate without fully loading it.
///
/// # Arguments
///
/// * `path` - Path to the RO-Crate
/// * `level` - Validation strictness level
///
/// # Returns
///
/// * `Result<ValidationReport, ROCrateError>` - Validation results
///
/// # Examples
///
/// ```ignore
/// use rocrate::{validate_rocrate, ValidationLevel};
///
/// let report = validate_rocrate("./my-crate", ValidationLevel::Strict).unwrap();
/// if report.is_valid() {
///     println!("RO-Crate is valid!");
/// } else {
///     for error in report.errors() {
///         println!("Error: {}", error);
///     }
/// }
/// ```
pub fn validate_rocrate<P: AsRef<Path>>(
    path: P,
    level: ValidationLevel,
) -> Result<ValidationReport, ROCrateError> {
    let path = path.as_ref();

    if path.is_dir() {
        let reader = DirectoryReader::new(path, level)?;
        let rocrate = reader.read_crate()?;
        reader.validate(&rocrate)
    } else if path.extension().map_or(false, |ext| ext == "zip") {
        let reader = ZipReader::new(path, level)?;
        let rocrate = reader.read_crate()?;
        reader.validate(&rocrate)
    } else {
        Err(ROCrateError::InvalidFormat(
            "Path must be a directory or ZIP file".to_string(),
        ))
    }
}
