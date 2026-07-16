# AGENTS.md

## Workspace Map

- This is a Rust 2024 workspace whose four members are selected by `crates/*`; the root README only describes two of them.
- `crates/pithos_lib` owns the Pithos format: `model/` is the on-disk data model and marshalling, `io/` is the high-level reader/writer API, and `helpers/` contains crypto, compression, directory, and RO-Crate integration.
- `crates/pithos` is a single-binary Clap wrapper. Keep CLI parsing and filesystem presentation here; format behavior belongs in `pithos_lib`.
- `crates/rocrate` is a separate RO-Crate library, but `pithos_lib` depends on it for conversion. Its tests are inline under `src/`, not in a `tests/` directory.
- `crates/pithos_pyo3` is currently an empty Rust library stub with no PyO3 dependency or Python API. Do not infer functionality from its name or copied README.
- Crates declare versions independently; none inherits `workspace.package.version`. Release/version work must update the intended crate manifests, not just the root version.
- There is no pinned toolchain or MSRV. CI installs stable; coverage alone installs nightly plus `llvm-tools-preview`.

## Sources Of Truth

- Treat `spec/PITHOS_1.0.0_draft.md`, model marshalling code, and integration tests as compatibility-sensitive. Changes to serialized fields, flags, encryption, compression, indexes, or directory layout can alter the on-disk format.
- Prefer current structs and tests over README snippets. The `pithos_lib` README writer example still uses `InputFile.file_path`; the current field is `inner_path`.
- File extensions are inconsistent in current prose and code (`.pto`, `.pith`, `.pithos`). Do not normalize them as incidental cleanup.
- `AGENTS.md` is listed in `.gitignore` and is not tracked in the current checkout, so edits to it do not appear in normal `git status` output.

## Verification

- CI parity is `cargo test --all-features` from the workspace root.
- Current-checkout caveat: `pithos_lib` declares and references feature `async`, but there is no `src/async.rs` or `src/async/mod.rs`; therefore the CI command currently fails with E0583. `cargo test --workspace` is the working default-feature baseline.
- Run one library integration target with `cargo test -p pithos_lib --test reader`, `--test writer`, or `--test marshalling`.
- Run one integration case with `cargo test -p pithos_lib --test reader test_reader_file_ranges -- --nocapture`.
- Run one inline RO-Crate test with `cargo test -p rocrate validation::tests::test_validation_levels`.
- Exercise CLI parsing with `cargo run -p pithos -- --help`; the CLI crate currently has no tests.
- The formatter check is `cargo fmt --all --check`, but it currently stops on the same missing `async` module. CI has no format or Clippy job, and the default build has existing unused-variable warnings, so do not describe `clippy -D warnings` as CI parity.
- Coverage mirrors `.github/workflows/codecov.yaml`: install `cargo-llvm-cov`, use nightly with `llvm-tools-preview`, then run `cargo llvm-cov --lcov --output-path=./.coverage/lcov.info`.

## Test And Release Gotchas

- `pithos_lib` integration tests depend on committed fixtures and PEM keys under `crates/pithos_lib/tests/data/`; reuse `tests/common/util.rs`. They create outputs in `tempfile` directories and require no external service.
- Put format round-trip coverage in `tests/marshalling.rs`, end-to-end extraction/range coverage in `tests/reader.rs`, and creation/append/directory/RO-Crate coverage in `tests/writer.rs`.
- Tags matching `v*` publish only `pithos_lib` and then `pithos`; `rocrate` and `pithos_pyo3` are not published by the workflow.
