# AGENTS.md

## Boundaries

- This is a Rust 2024 workspace (`crates/*`) with MSRV Rust 1.88. `pithos_lib` and the `pithos` CLI each declare their own version; `pithos_pyo3` is an unpublished, nonfunctional stub.
- `pithos_lib` is the implementation: `archive/` is the public reader/writer API; private `format/` is the only wire-format authority; `crypto.rs` and `block.rs` isolate keys and transforms.
- Keep core archive/format code independent of host files and presentation formats. Linux-only filesystem work belongs in `fs/`; RO-Crate and Crypt4GH presentation work belongs in `adapters/`. Preserve adapter-specific errors and host/path/member context instead of expanding core `PithosError` or exposing secrets.
- `pithos` is the Clap wrapper. Keep CLI parsing, output staging, and filesystem presentation in `crates/pithos`; put archive behavior in `pithos_lib`.
- `fs` uses no-follow traversal and no-clobber staged extraction. It requires Linux filesystem support for `O_TMPFILE` and `linkat(AT_EMPTY_PATH)`; do not assume filesystem-facing features are portable.

## Compatibility And Tests

- This branch implements the Pithos 1.0 draft wire rules; Cargo package versioning is separate. Do not expose old `model`, `helpers`, or wire-record paths.
- Treat changes under `src/format/`, archive validation/indexing, encryption, compression, flags, indexes, or directory layout as on-disk compatibility changes. Do not casually normalize the currently inconsistent `.pto`, `.pith`, and `.pithos` extensions.
- `pithos_lib` integration tests use committed fixtures and test-only PEM keys in `crates/pithos_lib/tests/data/`; reuse helpers from `tests/common/`.
- Put wire-format unit coverage in `src/format/`, reader-internal coverage in `src/archive/reader_private_tests.rs`, and public extraction/range coverage in `crates/pithos_lib/tests/reader.rs`. Keep RO-Crate tests in the `ro_crate_{directory,zip,conversion}` integration targets.

## Verification

- CI parity: `cargo +stable test --locked --workspace --all-features --lib --bins --tests`; MSRV parity: `cargo +1.88.0 test --locked --workspace --all-features`.
- Before finishing Rust changes, run `cargo +stable fmt --all -- --check` and `cargo +stable clippy --locked --workspace --all-targets --all-features -- -D warnings` when practical.
- Focused library tests use integration targets, for example `cargo test -p pithos_lib --test reader`; focused RO-Crate coverage is `cargo test -p pithos_lib --test ro_crate_directory` (or `ro_crate_zip` / `ro_crate_conversion`). CLI smoke check: `cargo +stable run --locked -p pithos -- --help`.
- Release/package changes also require `python3 .github/release/check.py contracts` and `python3 .github/release/check.py package check pithos_lib` (and `pithos` when affected). The package policy is a ratchet: `package update` needs `--allow-increase` to raise a budget.
- Run benchmark baselines and candidates locally on the same machine with the same toolchain, locked dependencies, power settings, and workload environment variables; GitHub-hosted runners are not comparable benchmark evidence.
