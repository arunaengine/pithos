<p align="center">
    <img src="./assets/pithos_logo.png" style="height: 8rem; width: 8rem;">
</p>

<h1 align="center">Pithos</h1>

<p align="center">
     <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/built_with-Rust-dca282.svg" alt="Language: Rust"></a>
     <a href="https://github.com/arunaengine/pithos/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/License-MIT-brightgreen.svg" alt="License: MIT"></a>
     <a href="https://github.com/arunaengine/pithos/blob/main/LICENSE-APACHE"><img src="https://img.shields.io/badge/License-APACHE-brightgreen.svg" alt="License: Apache 2.0"></a>
     <a href="https://codecov.io/gh/arunaengine/pithos"><img src="https://codecov.io/github/arunaengine/pithos/coverage.svg?branch=main" alt="Codecov"></a>
</p>

<p align="center">A secure archive format and Rust implementation for research-data packaging.</p>

Pithos packages files into a chunked base or encrypted archive that can be read sequentially or by byte range. The Rust implementation supports streaming creation, validated opening, filesystem ingestion and extraction, archive extension, RO-Crate conversion, and Crypt4GH export.

## Get started

Install the command-line tool with Rust's package manager:

```bash
cargo install pithos
```

Create a recipient key pair, then create and inspect an archive. This example assumes `input/` already contains the files to package.

```bash
mkdir -p keys
pithos --output keys keypair --prefix owner
pithos --secret-key keys/owner.sec.pem --public-keys keys/owner.pub.pem --output research.pith create input
pithos --secret-key keys/owner.sec.pem read list research.pith
```

For the complete command workflow, including extracting entries, see the [CLI guide](crates/pithos/README.md). For Rust applications, start with the [library guide](crates/pithos_lib/README.md).

## What it provides

- Encrypted archive entries with recipient-key access control and per-block integrity verification.
- Content-defined chunking, optional compression, and indexed reads of complete entries or byte ranges.
- Local filesystem operations that avoid symlink traversal and refuse to overwrite existing extracted files.
- RO-Crate directory and ZIP conversion, plus Crypt4GH export for readable entries.

The filesystem operations are Linux-only and require destination filesystem support for `O_TMPFILE` and `linkat(AT_EMPTY_PATH)`. Core archive reading and writing do not require Linux filesystem access.

## Crates

| crate | version | docs |
| :------------------------- | :-----------------------------------------------------------------------------------------: | :------------------------------------------------------------------: |
| [pithos](crates/pithos/) | [crates.io](https://crates.io/crates/pithos) | [docs.rs](https://docs.rs/pithos/) |
| [pithos_lib](crates/pithos_lib/) | [crates.io](https://crates.io/crates/pithos_lib) | [docs.rs](https://docs.rs/pithos_lib/) |

`pithos` is the command-line interface. `pithos_lib` is the public Rust API and includes [compiled examples](crates/pithos_lib/examples/). The `pithos_pyo3` workspace member is an unpublished empty Rust stub, not a Python API.

## Compatibility

Version 0.8 is a source break from 0.7. Use the selected public API in `pithos_lib::archive`, `crypto`, `source`, `fs`, and `adapters`; old model, helper, and wire-record paths are not compatibility APIs.

This branch implements the wire rules in the [Pithos 1.0 draft](spec/PITHOS_1.0.0_draft.md). Cargo package versioning is maintained separately from the wire-format version.
