[![Rust](https://img.shields.io/badge/built_with-Rust-dca282.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/ArunaStorage/aruna-file/blob/main/LICENSE)
![CI](https://github.com/ArunaStorage/aruna-file/actions/workflows/push.yaml/badge.svg)
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
// Create a simple Pithos file with a single entry
let sender_key = [0u8; 32];
let recipient_key = [1u8; 32];

// Dummy input file
let input_file = InputFile {
    file_type: FileType::Data,
    file_path: "very_important.txt".to_string(),
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

PithosReader Example:
```rust
let pithos_file = PathBuf::from("example.pith");
let mut reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();
let (directory, _) = reader.read_directory().unwrap();

println!("{:#?}", reader.read_file_paths(&directory).unwrap());
```