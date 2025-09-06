use crate::io::pithosreader::PithosReaderError;
use crate::io::pithoswriter::PithosWriterError;
use fastcdc::v2020::{Normalization, StreamCDC};
use std::env::current_dir;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub fn extract_filename(path: &str) -> Option<&str> {
    Path::new(path).file_name()?.to_str()
}

pub fn current_timestamp() -> Result<u64, PithosWriterError> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs())
}

pub fn get_symlink_target(file: &std::fs::File) -> Result<String, PithosWriterError> {
    let fd = file.as_raw_fd();
    let proc_path = format!("/proc/self/fd/{fd}");
    Ok(std::fs::read_link(proc_path)?.to_string_lossy().to_string())
}

pub fn create_dir(path: &str, base_dir: Option<&PathBuf>) -> Result<(), PithosReaderError> {
    // If no base dir provided create directory hierarchy in current working directory
    let path = if let Some(base_dir) = base_dir {
        base_dir.join(path)
    } else {
        current_dir()?.join(path)
    };
    std::fs::create_dir_all(path)?;

    Ok(())
}

pub fn create_symlink(
    path: &str,
    target: &str,
    base_dir: Option<&PathBuf>,
) -> Result<(), PithosReaderError> {
    // If no output path provided create symlink in current working directory
    let (path, target) = if let Some(base_dir) = base_dir {
        (base_dir.join(path), base_dir.join(target))
    } else {
        (current_dir()?.join(path), current_dir()?.join(target))
    };
    std::os::unix::fs::symlink(path, target)?;

    Ok(())
}

pub fn create_stream_cdc(
    content: Box<dyn Read>,
    cdc: Option<(u32, u32, u32)>,
) -> StreamCDC<Box<dyn Read>> {
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
