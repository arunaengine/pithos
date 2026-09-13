//! Pithos archive reading, writing, Linux filesystem operations, and presentation adapters.
//!
//! # Public archive API
//!
//! Create archives with [`archive::ArchiveWriter`], then open them through
//! [`archive::Archive`] and an immutable [`source::ArchiveSource`]. Create either a base archive
//! with [`archive::WriteOptions::base`] for local, uncompressed, unencrypted content, or an
//! encrypted archive with a sender key and one or more recipient public keys. Opening encrypted
//! content requires the matching recipient private key in [`archive::AccessKeys`].
//!
//! Payload integrity is checked when bytes are read, not when the archive is opened. In
//! particular, [`archive::Archive::copy_to`] and [`archive::Archive::copy_range_to`] verify each
//! full block before releasing bytes from that block. A generic sink can retain earlier verified
//! output if a later block fails. For Linux paths, [`fs::extract`] instead stages each regular
//! file and publishes it without replacing an existing destination entry.
//!
//! The compiled examples cover [creation](https://github.com/arunaengine/pithos/tree/main/crates/pithos_lib/examples),
//! listing, range reads, extraction, append and reader grants, RO-Crate conversion, and Crypt4GH
//! export. They use only this public boundary and perform no network operations.
//!
//! The Linux filesystem adapter is intentionally host-specific. Core archive reading and writing
//! remain independent of filesystem traversal and presentation formats.
//!
//! Wire records and compatibility modules are deliberately not part of the public API:
//!
//! ```compile_fail
//! use pithos_lib::model::structs::Directory;
//! ```
//!
//! ```compile_fail
//! use pithos_lib::helpers::directory::DirectoryBuilder;
//! ```
//!
//! ```compile_fail
//! use pithos_lib::format::wire::FileHeader;
//! ```

pub mod adapters;
pub mod archive;
mod block;
pub mod crypto;
pub mod error;
mod format;
pub mod fs;

pub mod source;

/// Byte-oriented parser entry points for the standalone fuzz targets.
///
/// This module is intentionally excluded from normal builds and exposes no
/// format records or key material.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
