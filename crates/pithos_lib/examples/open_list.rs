//! Open an archive with a recipient key and list its entries.

use pithos_lib::archive::{AccessKeys, Archive, OpenOptions};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::source::FileSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = PrivateKey::from_private_pem_bytes(&std::fs::read("reader.pem")?)?;
    let archive = Archive::open(
        FileSource::open("report.pith")?,
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(reader)),
    )?;

    for entry in archive.entries() {
        println!("{}: {:?}", entry.path, entry.kind);
    }
    Ok(())
}
