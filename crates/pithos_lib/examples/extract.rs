//! Extract one archive entry through the Linux no-follow filesystem adapter.

use pithos_lib::archive::{AccessKeys, Archive, OpenOptions};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::fs::extract;
use pithos_lib::source::FileSource;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = PrivateKey::from_private_pem_bytes(&std::fs::read("reader.pem")?)?;
    let archive = Archive::open(
        FileSource::open("report.pith")?,
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(reader)),
    )?;

    extract(&archive, "report.txt", Path::new("extracted"))?;
    Ok(())
}
