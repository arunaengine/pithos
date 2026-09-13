# Pithos library

`pithos_lib` is the public Rust API for creating, opening, reading, extending, extracting, and adapting Pithos archives. It has no network client or transport policy. This branch implements the Pithos 1.0 draft wire rules; Cargo package versioning is separate.

## Installation

Add the crate to an application using Rust 1.88 or newer:

```toml
[dependencies]
pithos_lib = "0.8"
```

## Create an archive

A base archive needs no keys and accepts only local, uncompressed, unencrypted content:

```rust,no_run
use pithos_lib::archive::{ArchivePath, ArchiveWriter, EntryMetadata, ProcessingOptions, WriteOptions};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = ArchiveWriter::create(File::create("report.pith")?, WriteOptions::base())?;
    writer.add_file(
        ArchivePath::new("report.txt")?,
        EntryMetadata::new(0, 0, 0o644),
        ProcessingOptions::new(false, 0)?,
        None,
        File::open("report.txt")?,
    )?;
    writer.finish()?;
    Ok(())
}
```

This example encrypts a local file for its owner. The recipient public key is derived from the private key only for a self-contained example; production applications should provide the intended recipients' public keys.

```rust,no_run
use pithos_lib::archive::{
    ArchivePath, ArchiveWriter, EntryMetadata, ProcessingOptions, WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let owner = PrivateKey::from_private_pem_bytes(&std::fs::read("owner.pem")?)?;
    let recipient = owner.public_key();
    let input = File::open("report.txt")?;
    let size = input.metadata()?.len();
    let output = File::create("report.pith")?;

    let mut writer = ArchiveWriter::create(output, WriteOptions::new(owner, vec![recipient]))?;
    writer.add_file(
        ArchivePath::new("report.txt")?,
        EntryMetadata::new(0, 0, 0o644),
        ProcessingOptions::default(),
        Some(size),
        input,
    )?;
    writer.finish()?;
    Ok(())
}
```

See [`examples/create.rs`](examples/create.rs) for the maintained version and the [CLI guide](../pithos/README.md) for a command-line workflow.

## Public API

- Create archives with `archive::ArchiveWriter`, `archive::WriteOptions`, and `crypto` keys.
- Open an immutable `archive::Archive` from a `source::ArchiveSource`, such as `source::FileSource` or `source::MemorySource`.
- Read a complete entry with `copy_to` or a checked range with `copy_range_to`.
- Use `fs::extract`, `fs::append_files`, `fs::grant_readers`, and `fs::ingest` for Linux host operations.
- Use `adapters::ro_crate` for local directory/ZIP conversion and `adapters::crypt4gh::export` for Crypt4GH output.

Compiled examples are included with the package: [`create`](examples/create.rs), [`open_list`](examples/open_list.rs), [`read_ranges`](examples/read_ranges.rs), [`extract`](examples/extract.rs), [`append`](examples/append.rs), [`grant_readers`](examples/grant_readers.rs), [`ro_crate`](examples/ro_crate.rs), and [`crypt4gh`](examples/crypt4gh.rs). They are local-only and return errors to their caller.

The typed archive API deliberately keeps old model, helper, and wire-record access private. Use `WriteOptions::base` for plain output or `WriteOptions::new` for encrypted output.

## Read and extract semantics

Opening validates archive structure and accessible metadata. Payload integrity is lazy: each block is verified when it is read. `copy_to` and `copy_range_to` do not write bytes from a failed block, but a generic sink can retain earlier verified blocks if a later block fails. `PithosError::ContentUnavailable` means the entry is present but no supplied key can access its content; it is different from an integrity or corruption error.

`fs::extract` is Linux-only. It walks destination components without following symlinks, stages regular-file output anonymously with Linux `O_TMPFILE`, and publishes without replacing an existing entry. The destination filesystem must support `O_TMPFILE` and `linkat(AT_EMPTY_PATH)`; extraction can therefore fail on a collision rather than overwrite a destination.

## RO-Crate ingestion

Load a directory or ZIP RO-Crate, then convert its retained source through a configured writer:

```rust,no_run
use pithos_lib::adapters::ro_crate::{read_ro_crate_directory, write_ro_crate};
use pithos_lib::archive::ProcessingOptions;

# fn convert<W: std::io::Write>(writer: &mut pithos_lib::archive::ArchiveWriter<W>) -> Result<(), Box<dyn std::error::Error> {
let loaded = read_ro_crate_directory("path/to/ro-crate")?;
write_ro_crate(writer, loaded, ProcessingOptions::default())?;
# Ok(())
# }
```

The upstream parser accepts RO-Crate 1.1 and 1.2 metadata without upstream validation or warning emission; Pithos then applies its own source, path, limit, metadata, and conversion policy. Conversion stores the inspected `ro-crate-metadata.json` bytes rather than reserializing the graph. ZIP conversion streams retained members and does not extract them first.

## Platform behavior

Filesystem ingestion, extraction, append, and grants are Linux-only in 0.8. Append uses a cooperating-writer advisory lock and can request `AppendDurability::SyncAll`; it attempts to truncate a failed child directory, but it cannot promise rollback after an unrecoverable host or power failure.
