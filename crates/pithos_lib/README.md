[![Rust](https://img.shields.io/badge/built_with-Rust-dca282.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/arunaengine/aruna-file/blob/main/LICENSE-MIT)
[![License](https://img.shields.io/badge/License-APACHE-brightgreen.svg)](https://github.com/arunaengine/aruna-file/blob/main/LICENSE-APACHE)
[![Codecov](https://codecov.io/github/ArunaStorage/aruna-file/coverage.svg?branch=main)](https://codecov.io/gh/ArunaStorage/aruna-file)
[![Dependency status](https://deps.rs/repo/github/ArunaStorage/aruna-file/status.svg)](https://deps.rs/repo/github/ArunaStorage/aruna-file)
___

# Pithos library

A library for creating, handling and transforming Pithos files, an object storage optimized file format for Research Data Management (RDM).

For the formal file specification click [here](../../spec/PITHOS_1.0.0_draft.md).

## Guidance 

Short guidance for usage of the `PithosWriter` and similarly for the `PithosReader` custom component. 
Both components provide convenience functionality to write individual Pithos file components or read them again efficiently.

PithosWriter Example:
```rust
use x25519_dalek::{PublicKey, StaticSecret};

// Create a simple Pithos file with a single entry
let sender_key = StaticSecret::from([0u8; 32]);
let recipient_key = PublicKey::from([1u8; 32]);

// Dummy input file
let input_file = InputFile {
    file_type: FileType::Data,
    inner_path: "very_important.txt".to_string(),
    data: Content::File("tests/data/t8.shakespeare.sample.txt".to_string()),
    metadata: None,
    encrypt: true,
    compression_level: Some(7),
};
let temp_dir = TempDir::new().unwrap();
let outfile = File::create(temp_dir.path().join("example.pith")).unwrap();

// Process
let mut writer = PithosWriter::new(sender_key, vec![recipient_key], None, Box::new(outfile)).unwrap();
writer.write_file_header().unwrap();
writer.process_input(input_file).unwrap();
writer.write_directory().unwrap();
```

### RO-Crate ingestion

Load an RO-Crate directory and process it with a configured `PithosWriter`:

```rust
use pithos_lib::helpers::ro_crate::read_ro_crate_directory;

let loaded = read_ro_crate_directory("path/to/ro-crate")?;
writer.process_ro_crate(&loaded)?;
```

ZIP archives use the same writer operation:

```rust
use pithos_lib::helpers::ro_crate::read_ro_crate_zip;

let loaded = read_ro_crate_zip("path/to/ro-crate.zip")?;
writer.process_ro_crate(&loaded)?;
```

`loaded.ro_crate` is the upstream `ro-crate-rs` graph. Conversion stores the original
`ro-crate-metadata.json` bytes instead of reserializing that graph, and every physical regular
data file references the metadata entry. ZIP conversion streams archive members directly and
does not extract them first.

The upstream parser accepts RO-Crate 1.1 and 1.2 metadata. Pithos uses its warning-level
vocabulary checks, not full RO-Crate conformance validation. The upstream root deserializer is
strict: the root Dataset must contain `@id`, `@type`, `name`, `description`, `datePublished`, and
`license`.

### Breaking migration

| Removed API | Replacement |
| --- | --- |
| `rocrate::ROCrate` | `pithos_lib::helpers::ro_crate::RoCrate` re-export from `rocraters` |
| `ROCrate.base_path` | `LoadedRoCrate.source` |
| `data_entities()` | Match `GraphVector::DataEntity` in `loaded.ro_crate.graph` |
| `contextual_entities()` | Match `GraphVector::ContextualEntity` |
| `ROCrateBuilder` | Upstream public structs/graph construction; no Pithos compatibility builder |
| Local validation levels/reports | Upstream read validation behavior |
| Local directory/ZIP reader traits | `read_ro_crate_directory` and `read_ro_crate_zip` |

PithosReader Example:
```rust
let pithos_file = PathBuf::from("example.pith");
let mut reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();
let (directory, _) = reader.read_directory().unwrap();

println!("{:#?}", reader.read_file_paths(&directory).unwrap());
```
