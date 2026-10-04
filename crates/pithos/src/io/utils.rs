use crate::PithosCliError;
use pithos_lib::crypto::{PrivateKey, PublicKey};
use rustix::fs::{Mode, OFlags, open};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// PEM key files are small; this bounds memory use and rejects appended data.
const MAX_PEM_FILE_BYTES: usize = 1024 * 1024;

pub fn load_private_key_from_pem(filepath: &Path) -> Result<PrivateKey, PithosCliError> {
    let mut file_content = Zeroizing::new(Vec::new());
    read_bounded_pem_file(
        filepath,
        "load private key",
        "inspect private key",
        "read private key",
        "private",
        &mut file_content,
    )?;

    pithos_lib::crypto::parse_private_pem(&file_content).map_err(|source| {
        PithosCliError::KeyParse {
            operation: "parse private key",
            path: filepath.to_path_buf(),
            source,
        }
    })
}

pub fn load_public_key_from_pem(filepath: &Path) -> Result<PublicKey, PithosCliError> {
    let mut file_content = Vec::new();
    read_bounded_pem_file(
        filepath,
        "load public key",
        "inspect public key",
        "read public key",
        "public",
        &mut file_content,
    )?;

    pithos_lib::crypto::parse_public_pem(&file_content).map_err(|source| PithosCliError::KeyParse {
        operation: "parse public key",
        path: filepath.to_path_buf(),
        source,
    })
}

fn read_bounded_pem_file(
    filepath: &Path,
    load_operation: &'static str,
    inspect_operation: &'static str,
    read_operation: &'static str,
    key_kind: &'static str,
    file_content: &mut Vec<u8>,
) -> Result<(), PithosCliError> {
    // Keep metadata and reads bound to the same no-follow descriptor.
    let mut file = File::from(
        open(
            filepath,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| PithosCliError::KeyFile {
            operation: load_operation,
            path: filepath.to_path_buf(),
            source: source.into(),
        })?,
    );

    let declared_len = file
        .metadata()
        .map_err(|source| PithosCliError::KeyFile {
            operation: inspect_operation,
            path: filepath.to_path_buf(),
            source,
        })?
        .len();
    if declared_len > MAX_PEM_FILE_BYTES as u64 {
        return Err(PithosCliError::KeyFile {
            operation: read_operation,
            path: filepath.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{key_kind} key file exceeds {MAX_PEM_FILE_BYTES}-byte limit"),
            ),
        });
    }

    let content_len = usize::try_from(declared_len).map_err(|_| PithosCliError::KeyFile {
        operation: read_operation,
        path: filepath.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{key_kind} key file exceeds {MAX_PEM_FILE_BYTES}-byte limit"),
        ),
    })?;
    file_content.resize(content_len, 0);
    file.read_exact(file_content)
        .map_err(|source| PithosCliError::KeyFile {
            operation: read_operation,
            path: filepath.to_path_buf(),
            source,
        })?;
    let mut trailing_byte = [0u8; 1];
    if file
        .read(&mut trailing_byte)
        .map_err(|source| PithosCliError::KeyFile {
            operation: read_operation,
            path: filepath.to_path_buf(),
            source,
        })?
        != 0
    {
        return Err(PithosCliError::KeyFile {
            operation: read_operation,
            path: filepath.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{key_kind} key file has trailing content"),
            ),
        });
    }

    Ok(())
}
