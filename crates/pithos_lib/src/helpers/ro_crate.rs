use rocrate::{ROCrate, ROCrateError};
use rocrate::{ROCrateReader, ValidationLevel};
use std::path::Path;
pub fn read_ro_crate_directory<P: AsRef<Path>>(path: P) -> Result<ROCrate, ROCrateError> {
    let reader = rocrate::reader::DirectoryReader::new(path, ValidationLevel::Standard)?;
    reader.read_crate()
}

pub fn read_ro_crate_zip<P: AsRef<Path>>(path: P) -> Result<ROCrate, ROCrateError> {
    let reader = rocrate::reader::ZipReader::new(path, ValidationLevel::Standard)?;
    reader.read_crate()
}
