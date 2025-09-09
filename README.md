<!--
<div style="display: flex; align-items: center; justify-content: center;">
    <img src="./assets/pithos_logo.png" style="height: 8rem; width: 8rem;">
    <p style="serif; font-size: 6rem; margin: 2rem;">Pithos</p>
</div>
-->
<p align="center">
    <img src="./assets/pithos_logo.png" style="height: 8rem; width: 8rem;">
</p>

<h1 align="center">Pithos</h1>

<p align="center">
     <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/built_with-Rust-dca282.svg" alt="Language: Rust"></a>
     <a href="https://github.com/ArunaStorage/aruna-file/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-brightgreen.svg" alt="License: MIT"></a>
     <a href="#"><img src="https://github.com/ArunaStorage/aruna-file/actions/workflows/push.yaml/badge.svg" alt="License: MIT"></a>
</p>

<p align="center">🔑 A secure, fast and versatile package file format for object storage focused data management 📦</p>
<div style="margin-top: 3rem"><div/>

## Description

Pithos (a large ancient greek storage container) is a packaging file format for arbitrary data that enhances the use of Object Storage for (research) data management. This is done by combining multiple existing file standards with new enhancements. A format specification can be found [[here]](./spec/PITHOS_1.0.0_draft.md).

## Features

- **Encryption**: Pithos implements fast ChaCha20-Poly1305 encryption and enables data exchange compatible to the Crypt4GH standard used for sensitive medical data.
- **Smart Compression**: Via compression probing Pithos can automatically detect and apply fast ZStandard compression for compressible data and optionally skip it when the data is incompressible.
- **Metadata**: Pithos not only includes technical metadata like file size and checksums but can also embed any semantic metadata directly in the file.
- **Indexing**: A built in index allows for fast random access of arbitrary ranges in encrypted and compressed files.
- **Tooling**: Pithos comes with a rich set of existing tools that simplify file handling and can additionally be handled with existing tools for the Crypt4GH and Zstandard file formats.

Pithos comes with two main crates, a library for programmatic use and a CLI application that uses the library:

| crate                      |                                           version                                           |                                 docs                                 |
| :------------------------- | :-----------------------------------------------------------------------------------------: | :------------------------------------------------------------------: |
| [pithos](./crates/pithos/)       |    [![Crates.io](https://img.shields.io/crates/v/pithos.svg)](https://crates.io/crates/pithos)    |    [![Docs](https://docs.rs/pithos/badge.svg)](https://docs.rs/pithos/)    |
| [pithos_lib](./crates/pithos_lib/)       |    [![Crates.io](https://img.shields.io/crates/v/pithos_lib.svg)](https://crates.io/crates/pithos_lib)    |    [![Docs](https://docs.rs/pithos_lib/badge.svg)](https://docs.rs/pithos_lib/)    |


For a more detailed documentation of the individual crates see [Library](./crates/pithos_lib/README.md) and [CLI](./crates/pithos/README.md)
