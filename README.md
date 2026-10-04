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
- Fixed 4 MiB blocks by default or optional content-defined chunking, optional compression, and indexed reads of complete entries or byte ranges.
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

This branch implements the wire rules in the [Pithos 1.1 draft](spec/PITHOS_1.1.0_draft.md). Cargo package versioning is maintained separately from the wire-format version.

## Format 1.1

Format 1.1 keeps every 1.0 structure and encoding. This version reads 1.0 and 1.1 archives, writes new archives as 1.1, and appends to an archive with the rules of its own version. It also reads archives written by Pithos 0.7, but does not append to them (spec Appendix C). The changes are:

- The header version is `0x0101`.
- A recipient grant key is derived with HKDF-SHA256 instead of using the raw X25519 shared secret.
- A file's block list can be sealed in independent pieces, each with its own key. Pieces can be joined later without opening a key.
- An encrypted block can use a random key instead of its content-derived key. Such blocks are never deduplicated.
- An encrypted block payload can use AES-256-GCM instead of ChaCha20-Poly1305.

Breaking changes in the 0.8 API:

- New writers use fixed 4 MiB blocks by default. Use `Chunking::ContentDefined` with `WriteOptions::with_chunking` or `PieceEncoder::with_chunking` for FastCDC blocks.
- The RO-Crate and Crypt4GH adapters are behind the default features `ro-crate` and `crypt4gh`.
- `Archive::open` no longer reads block markers. A missing or changed marker fails when the block is read.
- The default `OpenLimits` admit objects up to 5 TiB.
- The minimum supported Rust version is 1.89.
