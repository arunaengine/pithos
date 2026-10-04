//! Create an encrypted archive containing one local file.

use pithos_lib::archive::{
    ArchivePath, ArchiveWriter, EntryMetadata, ProcessingOptions, WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let owner = PrivateKey::from_private_pem_bytes(&std::fs::read("owner.pem")?)?;
    let recipient = owner.public_key();
    let input = File::open("report.txt")?;
    let size = input.metadata()?.len();
    let output = File::create("report.pith")?;

    let mut writer = ArchiveWriter::create(output, WriteOptions::new(owner, vec![recipient]))?;
    writer.add_file(
        ArchivePath::new("report.txt")?,
        EntryMetadata::new(0, 0, 0o644),
        ProcessingOptions::default(),
        Some(size),
        input,
    )?;
    writer.finish()?;
    Ok(())
}
