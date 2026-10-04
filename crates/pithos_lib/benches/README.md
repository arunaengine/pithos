# Benchmarks

This guide is for maintainers measuring `pithos_lib` performance. Run comparisons locally on the
same machine under consistent conditions.

## Quick developer smoke

Build every explicit target without running it:

```bash
cargo bench --locked -p pithos_lib --no-run
```

Run individual short local checks from the workspace root with the locked dependency graph:

```bash
cargo bench --locked -p pithos_lib --bench archive_path -- --quick
PITHOS_BENCH_100K=1 cargo bench --locked -p pithos_lib --bench archive_path -- --quick
cargo bench --locked -p pithos_lib --bench block_pipeline -- --quick
cargo bench --locked -p pithos_lib --bench archive_io -- --quick
cargo bench --locked -p pithos_lib --bench append -- --quick
cargo bench --locked -p pithos_lib --bench adapters -- --quick
```

`archive_path` covers flat and duplicate 1K/10K creation, opt-in 100K creation,
deep 10/100/1K paths, both 1K hierarchy-conflict directions, ancestor-first and
descendant-first incremental insertion, 100/1K metadata/data pairs with references,
100-entry flat archive open/index validation, and filesystem extraction of every file in a
100-entry archive. `block_pipeline` covers
compressible and high-entropy transforms plus an 8 MiB virtual-stream workload;
set `PITHOS_BENCH_LARGE_STREAM=1` to include its 64 MiB variant. The virtual reader
and counting sink never retain the logical input or archive output.

`archive_io` builds a real two-generation temporary archive and uses `FileSource` for open/merge,
sequential full reads, and prefix, middle, tiny, and full ranges. Its counting source
reports the read calls and requested bytes actually made by the archive reader.
`append` uses Criterion batched setup to build the base archive, input file, and keys
before timing only the supported locked direct append. It includes new and duplicate
content. Its observation reports reads from the actual existing-archive source used
to construct the append snapshot; output bytes are the appended tail, not final archive size.
The append target also measures one final append against prepared 1-, 10-, and 100-generation
archives. Generation construction and final input creation are setup rather than measured work.
`adapters` loads a directory RO-Crate with a content member and a ZIP RO-Crate with a deterministic
1 MiB ordinary member before timing conversion through `write_ro_crate` and writer finalization.
It also opens a verified archive entry before timing its Crypt4GH export using the current GA4GH
header KDF. The adapter target uses counted sinks, so output bytes remain observable without
retaining a second full output copy.

`cargo test --locked -p pithos_lib --test benchmark_contracts -- --nocapture --test-threads=1`
enforces these workload shapes without runtime thresholds. The streamed-memory test emits a
machine-readable line containing both measured peaks, their delta, output sizes, and bound.

Keys, input payloads, archive fixtures, and temporary directories are setup, not timed,
unless creation itself is the named workload. Each resource record is one `pithos-bench-v1`
JSON object with exactly `workload`, `setup`,
`peak_heap_bytes`, `archive_bytes`, `output_bytes`, `source_read_count`,
`source_read_bytes`, `bytes_appended`, and `dedup_signal`. All six metrics must be
finite non-negative numbers; the setup and deduplication signal are stable strings.
Extra timing fields and `null` observations are not valid benchmark evidence. Criterion's
`target/criterion/**/new/estimates.json` remains the runtime distribution source.

## Local comparisons

Measure the baseline and candidate on the same machine with the same Rust version, locked
dependencies, power settings, and workload environment variables. Keep other system activity low.
Do not compare results from GitHub-hosted runners or different machines.

On the baseline revision, save each Criterion baseline:

```bash
for bench in archive_path block_pipeline archive_io append adapters; do
    cargo +1.89.0 bench --locked -p pithos_lib --bench "$bench" -- --save-baseline before
done
```

Then switch to the candidate revision and compare against it:

```bash
for bench in archive_path block_pipeline archive_io append adapters; do
    cargo +1.89.0 bench --locked -p pithos_lib --bench "$bench" -- --baseline before
done
```

Set `PITHOS_BENCH_100K=1` or `PITHOS_BENCH_LARGE_STREAM=1` for both runs when those optional
workloads are relevant. Review Criterion's terminal comparison and
`target/criterion/**/change/estimates.json`; also compare the emitted `pithos-bench-v1` resource
records. Recreate the saved baseline when the toolchain, dependencies, machine, or workload
settings change.
