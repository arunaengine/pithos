# Test fixtures

This directory is for repository-owned integration-test inputs. The fixtures are deliberately small and are not examples of production data.

- `dummy_dir/` is a hand-authored RO-Crate 1.2 directory fixture consumed by
  `ro_crate_directory.rs`. It covers upstream graph parsing and Pithos directory conversion. Its
  `literature/pithos-placeholder.pdf` is a minimal repository-owned PDF retained solely to cover
  a non-text `application/pdf` member and `encodingFormat` handling.
- `pithos-0.7.0.pith` and `pithos-0.7.3.pith` were written by the Pithos 0.7.0 release binary and
  by 0.7.3 with the `sender` and `recipient1` test keys: a small directory tree, then one appended
  file. They cover reading Pithos 0.7 archives (spec Appendix C).
- `keys/` contains test-only PEM key pairs consumed through `tests/common/keys.rs` by archive,
  filesystem, adapter, and CLI integration tests. They are public repository test material, not
  operational credentials.
- ZIP RO-Crates are generated deterministically by `tests/common/ro_crate.rs::write_raw_zip` for
  `ro_crate_zip.rs`, `ro_crate_conversion.rs`, and the adapter benchmark. No committed ZIP fixture
  is required.
