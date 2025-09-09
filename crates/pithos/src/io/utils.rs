use pithos_lib::error::PithosError;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn load_private_key_from_pem(filepath: &PathBuf) -> Result<StaticSecret, PithosError> {
    // Open file handle and read file bytes
    let mut file = File::open(filepath)?;
    let mut file_content = vec![0u8; file.metadata()?.len() as usize];
    file.read_exact(&mut file_content)?;

    Ok(pithos_lib::helpers::x25519_keys::private_key_from_pem_bytes(&file_content)?)
}

pub fn load_public_key_from_pem(filepath: &PathBuf) -> Result<PublicKey, PithosError> {
    // Open file handle and read file bytes
    let mut file = File::open(filepath)?;
    let mut file_content = vec![0u8; file.metadata()?.len() as usize];
    file.read_exact(&mut file_content)?;

    Ok(pithos_lib::helpers::x25519_keys::public_key_from_pem_bytes(
        &file_content,
    )?)
}
