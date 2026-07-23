use crate::error::PithosError;
use crate::helpers::archive_path::{validate_entry_path, validate_symlink_target};
use crate::io::extraction::ExtractionRoot;
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
    validate_entry_path(path)?;
    let root = base_dir.cloned().unwrap_or(current_dir()?);
    ExtractionRoot::open(&root, true)?.create_dir(path)
}

#[tracing::instrument(level = "trace", skip(path, target, base_dir))]
pub fn create_symlink(
    path: &str,
    target: &str,
    base_dir: Option<&PathBuf>,
) -> Result<(), PithosError> {
    validate_entry_path(path)?;
    validate_symlink_target(path, target)?;
    let root = base_dir.cloned().unwrap_or(current_dir()?);
    ExtractionRoot::open(&root, true)?.create_symlink(path, target)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Cursor;
    use std::time::UNIX_EPOCH;
    use tempfile::TempDir;

    #[test]
    fn extract_filename_handles_paths_and_roots() {
        assert_eq!(extract_filename("file.txt"), Some("file.txt"));
        assert_eq!(extract_filename("nested/file.txt"), Some("file.txt"));
        assert_eq!(extract_filename("/"), None);
    }

    #[test]
    fn current_timestamp_is_current() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp = current_timestamp().unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!((before..=after).contains(&timestamp));
    }

    #[test]
    fn get_symlink_target_reports_the_open_file() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.txt");
        let link = temp_dir.path().join("link.txt");
        fs::write(&target, b"content").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let file = File::open(&link).unwrap();
        assert_eq!(get_symlink_target(&file).unwrap(), target.to_string_lossy());
    }

    #[test]
    fn create_dir_creates_nested_paths_with_a_base_directory() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path().join("base");
        create_dir("nested/path", Some(&base_dir)).unwrap();
        assert!(base_dir.join("nested/path").is_dir());
    }

    #[test]
    fn create_symlink_preserves_relative_targets_at_the_requested_path() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path().join("output");
        fs::create_dir(&base_dir).unwrap();

        create_dir("nested", Some(&base_dir)).unwrap();
        create_symlink("nested/link", "../target.txt", Some(&base_dir)).unwrap();

        let link = base_dir.join("nested/link");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(link).unwrap(), PathBuf::from("../target.txt"));
    }

    #[test]
    fn create_symlink_rejects_absolute_targets() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path().join("output");
        let target = temp_dir.path().join("outside-target");
        fs::create_dir(&base_dir).unwrap();

        assert!(create_symlink("link", target.to_str().unwrap(), Some(&base_dir)).is_err());
        assert!(fs::symlink_metadata(temp_dir.path().join("outside-target")).is_err());
    }

    #[test]
    fn create_stream_cdc_respects_custom_limits_and_preserves_content() {
        let content = (0..4096)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let chunks = create_stream_cdc(Cursor::new(content.clone()), Some((64, 256, 1024)))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let mut reconstructed = Vec::new();
        let mut next_offset = 0;
        for chunk in chunks {
            assert_eq!(chunk.offset, next_offset);
            assert_eq!(chunk.length, chunk.data.len());
            assert!(chunk.length <= 1024);
            next_offset += chunk.length as u64;
            reconstructed.extend_from_slice(&chunk.data);
        }

        assert_eq!(reconstructed, content);
    }

    #[test]
    fn create_stream_cdc_defaults_preserve_content() {
        let content = b"small stream".to_vec();
        let reconstructed = create_stream_cdc(Cursor::new(content.clone()), None)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .flat_map(|chunk| chunk.data)
            .collect::<Vec<_>>();

        assert_eq!(reconstructed, content);
    }
}
