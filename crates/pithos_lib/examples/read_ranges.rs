//! Copy a complete archive entry and a half-open byte range.

use pithos_lib::archive::{AccessKeys, Archive, OpenOptions};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::source::FileSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = PrivateKey::from_private_pem_bytes(&std::fs::read("reader.pem")?)?;
    let archive = Archive::open(
        FileSource::open("report.pith")?,
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(reader)),
    )?;
    let mut complete = std::fs::File::create("report.txt")?;
    archive.copy_to("report.txt", &mut complete)?;

    let mut range = std::fs::File::create("report-prefix.txt")?;
    archive.copy_range_to("report.txt", 0..1024, &mut range)?; // Bytes [0, 1024).
    Ok(())
}
