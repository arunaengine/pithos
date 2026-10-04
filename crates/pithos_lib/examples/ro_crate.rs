//! Convert a local RO-Crate directory into a Pithos archive.

use pithos_lib::adapters::ro_crate::{read_ro_crate_directory, write_ro_crate};
use pithos_lib::archive::{ArchiveWriter, ProcessingOptions, WriteOptions};
use pithos_lib::crypto::PrivateKey;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let owner = PrivateKey::from_private_pem_bytes(&std::fs::read("owner.pem")?)?;
    let recipient = owner.public_key();
    let loaded = read_ro_crate_directory("research-crate")?;
    let output = File::create("research-crate.pith")?;
    let mut writer = ArchiveWriter::create(output, WriteOptions::new(owner, vec![recipient]))?;

    write_ro_crate(&mut writer, loaded, ProcessingOptions::default())?;
    writer.finish()?;
    Ok(())
}
