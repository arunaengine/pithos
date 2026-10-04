//! Export one readable archive entry as a Crypt4GH stream.

use pithos_lib::adapters::crypt4gh::export;
use pithos_lib::archive::{AccessKeys, Archive, OpenOptions};
use pithos_lib::crypto::{PrivateKey, PublicKey};
use pithos_lib::source::FileSource;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let archive_reader = PrivateKey::from_private_pem_bytes(&std::fs::read("reader.pem")?)?;
    let crypt4gh_reader = PublicKey::from_public_pem_bytes(&std::fs::read("reader.pub.pem")?)?;
    let archive = Archive::open(
        FileSource::open("report.pith")?,
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(archive_reader)),
    )?;
    let mut output = File::create("report.txt.c4gh")?;

    export(&archive, "report.txt", vec![crypt4gh_reader], &mut output)?;
    Ok(())
}
