use crate::io::pithoswriter::PithosWriterError;
use std::os::fd::AsRawFd;
use std::path::Path;
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
    let proc_path = format!("/proc/self/fd/{}", fd);
    Ok(std::fs::read_link(proc_path)?.to_string_lossy().to_string())
}
