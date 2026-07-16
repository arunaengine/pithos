use crate::error::PithosError;
use fastcdc::v2020::{Normalization, StreamCDC};
use std::env::current_dir;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[tracing::instrument(level = "trace", skip(path))]
pub fn extract_filename(path: &str) -> Option<&str> {
    Path::new(path).file_name()?.to_str()
}

#[tracing::instrument(level = "trace")]
pub fn current_timestamp() -> Result<u64, PithosError> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs())
}

#[tracing::instrument(level = "trace", skip(file))]
pub fn get_symlink_target(file: &std::fs::File) -> Result<String, PithosError> {
    let fd = file.as_raw_fd();
    let proc_path = format!("/proc/self/fd/{fd}");
    Ok(std::fs::read_link(proc_path)?.to_string_lossy().to_string())
}

#[tracing::instrument(level = "trace", skip(path, base_dir))]
pub fn create_dir(path: &str, base_dir: Option<&PathBuf>) -> Result<(), PithosError> {
    // If no base dir provided create directory hierarchy in current working directory
    let path = if let Some(base_dir) = base_dir {
        base_dir.join(path)
    } else {
        current_dir()?.join(path)
    };
    std::fs::create_dir_all(path)?;

    Ok(())
}

#[tracing::instrument(level = "trace", skip(path, target, base_dir))]
pub fn create_symlink(
    path: &str,
    target: &str,
    base_dir: Option<&PathBuf>,
) -> Result<(), PithosError> {
    // Resolve only the link location. The target is stored verbatim so relative
    // targets remain relative to the created symlink.
    let path = if let Some(base_dir) = base_dir {
        base_dir.join(path)
    } else {
        current_dir()?.join(path)
    };
    std::os::unix::fs::symlink(target, path)?;

    Ok(())
}

#[tracing::instrument(level = "trace", skip(content, cdc))]
pub fn create_stream_cdc<R: Read>(content: R, cdc: Option<(usize, usize, usize)>) -> StreamCDC<R> {
    match cdc {
        Some((min, avg, max)) => {
            StreamCDC::with_level(content, min, avg, max, Normalization::Level1)
        }
        None => StreamCDC::with_level(
            content,
            fastcdc::v2020::MINIMUM_MAX,
            fastcdc::v2020::AVERAGE_MAX,
            fastcdc::v2020::MAXIMUM_MAX,
            Normalization::Level1,
        ),
    }
}
