//! Grant an additional recipient access to selected archive entry IDs.

use pithos_lib::archive::{AppendDurability, AppendOptions};
use pithos_lib::crypto::{PrivateKey, PublicKey};
use pithos_lib::fs::grant_readers;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let owner = PrivateKey::from_private_pem_bytes(&std::fs::read("owner.pem")?)?;
    let new_reader = PublicKey::from_public_pem_bytes(&std::fs::read("new-reader.pub.pem")?)?;
    let observation = grant_readers(
        Path::new("report.pith"),
        AppendOptions::new(owner, vec![new_reader]).with_durability(AppendDurability::SyncAll),
        &[0],
    )?;

    println!("archive grew to {} bytes", observation.final_archive_bytes);
    Ok(())
}
