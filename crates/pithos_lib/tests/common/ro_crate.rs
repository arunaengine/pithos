use super::keys::{private_key, public_key};
use pithos_lib::adapters::ro_crate::{LoadedRoCrate, RoCrateError, write_ro_crate};
use pithos_lib::archive::{
    ArchivePath, ArchiveWriter, Chunking, EntryMetadata, ProcessingOptions, WriteOptions,
};
use std::fs::{self, File};
use std::path::Path;

#[allow(dead_code)]
pub fn metadata(has_part: &[&str]) -> String {
    let parts = has_part
        .iter()
        .map(|path| format!(r#"{{"@id":"{path}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let entities = has_part
        .iter()
        .map(|path| format!(r#"{{"@id":"{path}","@type":"File"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let entity_suffix = if entities.is_empty() {
        String::new()
    } else {
        format!(",{entities}")
    };
    format!(
        r#"{{"@context":"https://w3id.org/ro/crate/1.2/context","@graph":[{{"@id":"ro-crate-metadata.json","@type":"CreativeWork","conformsTo":{{"@id":"https://w3id.org/ro/crate/1.2"}},"about":{{"@id":"./"}}}},{{"@id":"./","@type":"Dataset","name":"Test Crate","description":"A test RO-Crate","datePublished":"2024-01-01","license":"MIT","hasPart":[{parts}]}}{entity_suffix}]}}"#
    )
}

#[allow(dead_code)]
pub fn write_raw_zip(path: &Path, entries: &[(&[u8], &[u8], u32)]) {
    let mut archive = Vec::new();
    let mut central_directory = Vec::new();
    let mut offsets = Vec::with_capacity(entries.len());
    for (name, content, permissions) in entries {
        let offset = archive.len() as u32;
        offsets.push(offset);
        let checksum = crc32fast::hash(content);
        archive.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&checksum.to_le_bytes());
        archive.extend_from_slice(&(content.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(content.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(name);
        archive.extend_from_slice(content);

        central_directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central_directory.extend_from_slice(&20u16.to_le_bytes());
        central_directory.extend_from_slice(&20u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&checksum.to_le_bytes());
        central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
        central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
        central_directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&(*permissions << 16).to_le_bytes());
        central_directory.extend_from_slice(&offset.to_le_bytes());
        central_directory.extend_from_slice(name);
    }
    let central_offset = archive.len() as u32;
    archive.extend_from_slice(&central_directory);
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    archive.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    archive.extend_from_slice(&(central_directory.len() as u32).to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    fs::write(path, archive).unwrap();
}

#[allow(dead_code)]
pub fn write_loaded(output: &Path, loaded: LoadedRoCrate, chunking: Chunking) {
    let mut writer = ArchiveWriter::create(
        File::create(output).unwrap(),
        WriteOptions::new(private_key("sender"), vec![public_key("recipient1")])
            .with_chunking(chunking),
    )
    .unwrap();
    write_ro_crate(
        &mut writer,
        loaded,
        ProcessingOptions::new(false, 0).unwrap(),
    )
    .unwrap();
    writer.finish().unwrap();
}

#[allow(dead_code)]
pub fn conversion_error(loaded: LoadedRoCrate) -> RoCrateError {
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(private_key("sender"), vec![public_key("recipient1")]),
    )
    .unwrap();
    write_ro_crate(
        &mut writer,
        loaded,
        ProcessingOptions::new(false, 0).unwrap(),
    )
    .unwrap_err()
}

#[allow(dead_code)]
pub fn duplicate_conversion_error(loaded: LoadedRoCrate, path: &str) -> RoCrateError {
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(private_key("sender"), vec![public_key("recipient1")]),
    )
    .unwrap();
    writer
        .add_directory(
            ArchivePath::new(path).unwrap(),
            EntryMetadata::new(0, 0, 0o755),
        )
        .unwrap();
    write_ro_crate(
        &mut writer,
        loaded,
        ProcessingOptions::new(false, 0).unwrap(),
    )
    .unwrap_err()
}
