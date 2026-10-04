# Pithos Fuzzing

This guide is for maintainers running the standalone format fuzzing targets. It is a conventional non-workspace `cargo-fuzz` package with its own `Cargo.lock`; do not add it to the root workspace or use the workspace lockfile for fuzz jobs.

Install exactly `cargo-fuzz 0.13.2` and a Rust nightly toolchain with the platform C/C++ linker:

```bash
cargo +nightly install cargo-fuzz --version 0.13.2 --locked
cargo +nightly fuzz build
```

Run commands from the repository root. Committed seed corpora are under `fuzz/corpus/` and are
small format-marker cases plus fixed short-input regressions. The
`header_decode/file-header-marker` seed is exactly the four ASCII bytes `PITH`. The directory
corpus includes the valid 25-byte minimal complete directory so mutations can reach
footer, checksum, consumption, and body parsing rather than stopping at the minimum-length check.
Crash artifacts and generated build output belong under `fuzz/artifacts/` and `fuzz/target/` and
are ignored by Git. Keep any minimized regression that fixes a bug in `fuzz/corpus/<target>/`.

Pull requests targeting `main` run a smoke fuzz pass for all four targets. Each target runs for
60 seconds, with a five-second per-input timeout and a 1024 MiB RSS limit:

```bash
cargo +nightly fuzz run header_decode -- -max_total_time=60 -timeout=5 -rss_limit_mb=1024
cargo +nightly fuzz run directory_decode -- -max_total_time=60 -timeout=5 -rss_limit_mb=1024
cargo +nightly fuzz run crypt4gh_decode -- -max_total_time=60 -timeout=5 -rss_limit_mb=1024
cargo +nightly fuzz run chain_validation -- -max_total_time=60 -timeout=5 -rss_limit_mb=1024
```

The same four targets run weekly on Sundays at 02:30 UTC for an extended 15-minute pass, with a
10-second per-input timeout and a 1536 MiB RSS limit. The fuzz workflow can also be started
manually with those extended settings. Failure artifacts are retained for 14 days; fuzzing does
not persist generated corpus data.

The root dependency policy does not include this package. Run its policy check separately after
generating or updating `fuzz/Cargo.lock`:

```bash
cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml --locked check
```

Targets receive only bytes through the feature-gated `pithos_lib::fuzzing` harness and reduce
results to an error/success category. They do not expose wire records, decrypted metadata, or
secrets. The directory target validates complete marker, length, checksum, and parser-consumption
framing rather than invoking the raw directory body decoder.
