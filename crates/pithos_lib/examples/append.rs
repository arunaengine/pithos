//! Append filesystem entries in a durable Linux filesystem operation.

use pithos_lib::archive::{AppendDurability, AppendOptions};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::fs::append_files;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let owner = PrivateKey::from_private_pem_bytes(&std::fs::read("owner.pem")?)?;
    let recipient = owner.public_key();
    let inputs = vec![PathBuf::from("new-report.txt")];
    let observation = append_files(
        Path::new("report.pith"),
        AppendOptions::new(owner, vec![recipient]).with_durability(AppendDurability::SyncAll),
        &inputs,
    )?;

    println!("archive grew to {} bytes", observation.final_archive_bytes);
    Ok(())
}
