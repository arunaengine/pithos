# Pithos CLI

`pithos` creates, reads, and extends Pithos archives from the command line. It is the filesystem-oriented companion to the [`pithos_lib`](../pithos_lib/README.md) Rust API.

## Installation

Published releases are available from [crates.io](https://crates.io/crates/pithos). Install Rust through [rustup](https://rustup.rs/) first.

```text
cargo install pithos
```

## Create and read an archive

Create a directory for a key pair, then generate an owner key pair. The private key decrypts the archive; the public key identifies a recipient that may read it.

```bash
mkdir -p keys restored
pithos --output keys keypair --prefix owner
```

Create a plain base archive for a file or directory without keys. Base output is local, uncompressed, and unencrypted:

```bash
pithos --output plain.pith create --plain input
pithos read list plain.pith
pithos read data plain.pith report.txt > report.txt
```

Create an encrypted archive for a file or directory. This example gives the owner access and writes `research.pith`; replace `input` with your source path.

```bash
pithos --secret-key keys/owner.sec.pem --public-keys keys/owner.pub.pem --output research.pith create input
pithos --secret-key keys/owner.sec.pem read list research.pith
pithos --secret-key keys/owner.sec.pem --output restored read all research.pith
pithos --secret-key keys/owner.sec.pem read data research.pith report.txt > report.txt
```

Encrypted archives can be listed without a key, but reading their content requires the matching private key. Plain archives can be read without `--secret-key`:

```bash
pithos read list research.pith
pithos read list plain.pith
pithos read data plain.pith report.txt
```

`read data` also accepts `--ranges START:END,...` for half-open byte ranges. Use `read info` to inspect an entry and `read directory` to inspect every entry's metadata.

## More operations

- `append files` adds filesystem input to an existing archive.
- `append readers` grants additional recipient public keys access to selected entry IDs.
- `export --format crypt4gh` exports a readable entry as a Crypt4GH stream.

Use built-in help for required arguments, available options, and the complete command reference:

```text
pithos --help
pithos create --help
pithos read --help
pithos append --help
pithos export --help
```

## Platform behavior

Filesystem-facing operations are Linux-only in 0.8. New archive output, file output, export output, and extraction are staged without replacing existing destinations; they require a destination filesystem with Linux `O_TMPFILE` and `linkat(AT_EMPTY_PATH)` support. Direct append modifies an existing archive and does not require those operations.

For programmatic use, see the [pithos_lib documentation](https://docs.rs/pithos_lib/) and [compiled examples](https://github.com/arunaengine/pithos/tree/main/crates/pithos_lib/examples).
