//! Private current-format byte grammar.
//!
//! This module deliberately contains no archive policy, filesystem, adapter, or
//! transport concerns.

pub(crate) mod block;
pub(crate) mod directory;
pub(crate) mod encryption;
pub(crate) mod error;
pub(crate) mod file_entry;
pub(crate) mod header;
pub(crate) mod limits;
pub(crate) mod primitives;
