# Pithos File Format Specification

**Version:** 1.1
**Status:** Draft
**Date:** October 2026
**Purpose:** Next-generation file format for scientific data management, optimized for object storage with built-in deduplication, encryption, and metadata support

## 1. Introduction

This document specifies the Pithos file format using the key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

Pithos is an append-only archive format designed for efficient storage and sharing of scientific data. It combines block-level deduplication, convergent encryption, and flexible metadata support optimized for object storage systems.

**Illustrative data model.** Rust declarations in this document illustrate the
data model only; implementations may use different declarations. Normative
prose and encoded-form tables govern conformance and the bytes on disk.

This document defines Pithos 1.1 and the version 1.0 rules it keeps. Version 1.0
archives remain valid; Section 1.3 lists every difference between the versions.
Where a current 0.8 implementation differs, this document governs.

### 1.1 Reader's Guide

- **Readers:** Start with the common encoding rules (Section 3.1), then follow
  terminal Directory lookup and append-chain validation (Sections 4.3.1 and
  4.3.2), content processing (Section 5), and capability handling (Section
  8).
- **Writers:** Follow the encoded forms in Section 4, content processing in
  Section 5, and the writing operation sequence in Section 6.2.
- **Security reviewers:** Review the cryptographic construction in Section 5.3,
  block verification in Section 5.2, and the security considerations in
  Section 7.
- **Conformance-test authors:** Use the encoding rules in Section 3.1 and the
  encoded-form tables in Section 4 as the normative byte-level rules; Sections
  5 and 8 define processing and capability outcomes.

### 1.2 Terminology

- **segment:** The portion of an archive that introduces block data and ends
  with one Directory.
- **base Directory:** The oldest Directory in a selected chain. It has no
  parent and defines the standard relationships required by Section 4.3.2.
- **terminal Directory:** The newest Directory in a selected chain, located at
  the end of the file during normal reading as specified in Section 4.3.1.
- **selected chain:** The ordered sequence of Directories obtained by following
  parent links from the terminal Directory to the base Directory.
- **effective archive:** The archive view produced by merging the selected
  chain from the base Directory to the terminal Directory under Section 4.3.2.
- **effective descriptor:** The descriptor selected for a block hash after the
  selected chain is merged, as specified in Section 4.3.2.
- **archive root path:** The implicit root of the archive path hierarchy; it has
  no directory entry.
- **unavailable content:** Content that is structurally known but cannot be
  read because it requires an unsupported optional capability, as specified in
  Section 8.2.
- **salvage mode:** A recovery mode that may locate an older Directory after a
  normal terminal-Directory lookup fails; its result is incomplete and is not a
  normal archive view.

### 1.3 Version Differences

Version 1.1 keeps every version 1.0 structure and encoding. The header version
selects the rules for the whole archive, including every appended segment.
Version 1.1 differs from version 1.0 only in these points:

1. The header version is `0x0101` (Section 4.1).
2. A recipient grant's wrapping key is derived with HKDF-SHA256 instead of using
   the raw X25519 shared secret (Section 5.3).
3. A file's block list may be sealed in independent pieces, each with its own
   key (BlockDataState tag `02`, Section 4.4.2). Piece key IDs share the file ID
   space (Section 4.3.2).
4. An encrypted block may use a unique random key instead of its convergent key
   (ProcessingFlags bit 4, Section 4.2.3). Its block hash is then a keyed BLAKE3
   identity (Section 5.2), and the block is never deduplicated (Section 5.3).
5. An encrypted block payload may use AES-256-GCM instead of ChaCha20-Poly1305
   (ProcessingFlags bit 5, Sections 4.2.3 and 5.3). Block lists, pieces and
   recipient grants keep ChaCha20-Poly1305.

Readers MUST support both versions. Writers MUST create new archives as version
1.1. An append MUST follow the version of the archive it extends, so appending
to a version 1.0 archive uses the version 1.0 rules.

## 2. Core Design Principles

1. **Append-only architecture**: New data and metadata MUST be appended, never modifying existing content
2. **Content-addressed storage**: All blocks MUST be identified by BLAKE3 block hashes; convergent blocks enable deduplication
3. **Encrypted recipient grants**: Encrypted recipient data protects its file-key
   grants from parties that cannot decrypt it
4. **Flexible metadata**: Metadata MUST be stored as regular files with special type markers
5. **Progressive enhancement**: Implementations MUST support the base format and MAY support optional features
6. **Limited recovery**: Recovery tools MAY treat block markers as untrusted candidates; directories provide block metadata
7. **Hierarchical organization**: Files use full paths from the archive root path; directories MUST be declared before their contents

## 3. File Structure and Encoding

A Pithos file MUST have the following structure:

```
File start                                                                  EOF
    |                                                                        |
    v                                                                        v
+------------+-------------+----------------+-----------------+--------------------+
| FileHeader | Base blocks | Base Directory | Appended blocks | Terminal Directory |
+------------+-------------+----------------+-----------------+--------------------+
|<--------------- base segment ------------>|<-------- appended segment ---------->|

Directory chain:

[Base Directory] <- [Directory] <- ... <- [Terminal Directory]
        parent_directory_offset links each Directory to its predecessor
```

Each segment ends immediately after its Directory. Encryption sections, when
present, are items in that Directory's `encryption` vector. The final 12 bytes
of every Directory are `dir_len:u64be || crc32:u32be`.

### 3.1 Common Encoding Rules

The following rules define the bytes stored in the file for every structure in
Section 4:

1. Fixed byte arrays are stored exactly as shown, with no length prefix.
2. `u16`, `u32`, and `u64` fields explicitly marked fixed-width are big-endian.
3. Other unsigned integers use ULEB128. For a field of width `N`, an encoding is
   valid when it terminates within `ceil(N / 7)` bytes and decodes to a value
   representable by that field. Non-minimal encodings within that bound are
   valid. Writers SHOULD use the shortest valid encoding. Readers MUST accept
   valid non-minimal encodings and MUST reject truncated, unterminated, or
   overflowing encodings. ULEB128 string-length and vector-count prefixes have
   `u64` width.
4. A string is a ULEB128 byte length followed by that many UTF-8 bytes.
5. A vector is a ULEB128 item count followed by the items in order.
6. A tuple stores its members in the stated order.
7. Options and enum variants use a one-byte tag followed by the selected value,
   if any. Each Section 4 tag table defines the allowed tags.
8. Structures have no alignment bytes or implicit padding.
9. A reader MUST consume exactly the bytes assigned to a structure and reject
   unknown tags.

### 3.2 Resource Safety

Readers MUST treat every encoded length and count as untrusted, use checked
arithmetic and checked conversion to host sizes before indexing or allocating,
and fail on allocation failure. Implementations MAY enforce documented,
configured resource limits on input sizes, counts, and derived work; they MUST
fail before an applicable limit is exceeded and MUST NOT expose a partial archive
view after a resource or conversion failure.

## 4. Core Data Structures

### 4.1 File Header

A FileHeader identifies a Pithos file and its format version.

```rust
/// File header - appears once at the beginning of every Pithos file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4],    // b"PITH"
    pub version: u16,      // fixed-width big-endian, 0x0100 for 1.0, 0x0101 for 1.1
}
```

**Encoded Form**

| Field | Bytes stored in the file |
| --- | --- |
| `magic` | Exactly 4 bytes: ASCII `PITH` |
| `version` | Fixed-width `u16be` |

Readers MUST reject a header whose magic is not `PITH` or whose version is
neither `0x0100` nor `0x0101`. The encoded form is exactly six bytes: `PITH 01 01`
for version 1.1 and `PITH 01 00` for version 1.0.

### 4.2 Block Storage

#### 4.2.1 Block Header

A BlockHeader marks the beginning of locally stored block data.

```rust
/// Minimal block header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub marker: [u8; 4],   // MUST be b"BLCK"
}
```

**Encoded Form**

| Field | Bytes stored in the file |
| --- | --- |
| `marker` | Exactly 4 bytes: ASCII `BLCK` |

Readers MUST reject a block header whose marker is not `BLCK`.

#### 4.2.2 Block Descriptor

The hash-keyed block descriptor describes one block stored or referenced by a directory.

```rust
/// Block descriptor body; its hash is the key in Directory::blocks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDescriptor {
    pub offset: u64,             // Local byte offset; zero for External (varint encoded)
    pub stored_size: u64,        // Size as stored (compressed/encrypted) (varint)
    pub original_size: u64,      // Original uncompressed size (varint)
    pub flags: ProcessingFlags,  // Compression, encryption settings
    pub location: BlockLocation, // Where block data resides
}
```

**Encoded Form**

The directory block sequence is a vector. Each item is encoded as follows:

| Field | Bytes stored in the file |
| --- | --- |
| `block_hash` | Exactly 32 bytes: block hash as defined in Section 5.2 |
| `offset` | ULEB128 `u64`: local block offset, or zero for `External` |
| `stored_size` | ULEB128 `u64` |
| `original_size` | ULEB128 `u64` |
| `flags` | One ProcessingFlags byte as defined in Section 4.2.3 |
| `location` | One tag byte: `00` local, or `01` followed by an external location identifier string |

Readers MUST reject duplicate block hashes in one directory and MUST use the
32-byte hash as the block's only identity.

#### 4.2.3 Processing Flags

ProcessingFlags records the compression level, whether a block is encrypted and,
in version 1.1, how an encrypted block is keyed and sealed.

```rust
/// Processing flags packed into one byte
bitflags::bitflags! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProcessingFlags: u8 {
        // Bits 0-2: Compression (0=none; 1-7=Zstandard)
        const COMPRESSION_LEVEL_1 = 0b0000_0001;
        const COMPRESSION_LEVEL_2 = 0b0000_0010;
        const COMPRESSION_LEVEL_3 = 0b0000_0011;
        const COMPRESSION_LEVEL_4 = 0b0000_0100;
        const COMPRESSION_LEVEL_5 = 0b0000_0101;
        const COMPRESSION_LEVEL_6 = 0b0000_0110;
        const COMPRESSION_LEVEL_7 = 0b0000_0111;
        const COMPRESSION_MASK    = 0b0000_0111;

        // Bit 3: Encryption enabled
        const ENCRYPTION_ENABLED = 0b0000_1000;

        // Bit 4: Unique random block key (version 1.1, requires bit 3)
        const UNIQUE_KEY = 0b0001_0000;

        // Bit 5: AES-256-GCM payload (version 1.1, requires bit 3)
        const AES_256_GCM = 0b0010_0000;

        // Bits 6-7: Reserved for future use (MUST be zero)
    }
}
```

**Encoded Form**

| Bits | Meaning |
| --- | --- |
| 0-2 | Compression: `0` means the stored payload is not compressed; `1` through `7` each mean the stored payload is one standard Zstandard frame |
| 3 | Encryption enabled: `0` is disabled; `1` is enabled |
| 4 | Unique key (version 1.1): `0` means the block key is convergent; `1` means it is a unique random key (Section 5.3) |
| 5 | AES-256-GCM (version 1.1): `0` means the payload is sealed with ChaCha20-Poly1305; `1` means it is sealed with AES-256-GCM (Section 5.3) |
| 6-7 | Reserved; all bits MUST be zero |

ProcessingFlags is stored as exactly one byte. Readers MUST reject a value with
any reserved bit set. Bits 4 and 5 are valid only in a version 1.1 archive and
only when bit 3 is set. Readers MUST reject a descriptor that sets either bit in
a version 1.0 archive or without bit 3. The same rules apply wherever a writer
records these flags. For example, encrypted blocks with no compression have the
flags byte `18` with a unique key, `28` with AES-256-GCM, and `38` with both.

#### 4.2.4 Block Location

BlockLocation states where the bytes for a block can be obtained.

```rust
/// Block storage location
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockLocation {
    Local,                                // Block data at specified offset in this file
    External { location: String },        // Opaque external location identifier
}
```

**Encoded Form**

| Tag | Variant | Bytes after the tag |
| --- | --- | --- |
| `00` | `Local` | None |
| `01` | `External` | External location identifier as a string |

Readers MUST reject unknown tags. A local block's offset and size describe its
location in this file; [Section 4.2.5](#425-local-block-boundaries-and-recovery)
defines its block-boundary rules. An external location identifier is an opaque
string interpreted only by an enabled caller-supplied resolver. Writers MUST
encode `offset` as zero for `External`; readers MUST ignore that field for
`External`.

#### 4.2.5 Local Block Boundaries and Recovery

A local block is `BLCK || stored_payload`. Its `offset` is the zero-based file
offset of the first byte of `BLCK`; `stored_size` counts only `stored_payload`.
The marker occupies bytes `offset` through `offset + 3`. The payload starts at
`offset + 4` and occupies exactly `stored_size` bytes; when nonempty, its last
byte is `offset + 4 + stored_size - 1`.

The local block-data region of the base segment begins immediately after the
six-byte FileHeader and ends at the base Directory's start. The local
block-data region of an appended segment begins immediately after its parent
Directory and ends at its declaring Directory's start. For every effective
descriptor with `Local` location, its effective local extent is the half-open
range `[offset, offset + 4 + stored_size)`; it MUST fit wholly in
the local block-data region of its declaring segment, begin with `BLCK`, and
not overlap another effective local extent. Readers and writers MUST use
checked arithmetic to compute all extent and region bounds.

If ProcessingFlags encryption is enabled, `stored_size` MUST be at least 28
bytes: the 12-byte nonce plus the 16-byte authentication tag. This requirement
does not impose a minimum stored size for an unencrypted payload.

Readers locate local blocks from effective directory descriptors and MUST NOT
search payload bytes for `BLCK`. Recovery tools MAY treat `BLCK` as an
untrusted candidate only: the marker alone provides no length, flags, or
identity.

Opening an archive validates its metadata and reads no block bytes. A reader
MUST check a local block's `BLCK` marker when it reads that block, before it
uses the payload, and MUST reject the block if the marker is wrong. A reader
SHOULD fetch the marker and the payload in one read of `4 + stored_size` bytes.

#### 4.2.6 External Block Resolution

External resolution is an optional capability and MUST remain disabled until a
caller supplies both a resolver and an access policy. The resolver receives the
opaque external location identifier and MUST return exactly one framed block:
`BLCK || stored_payload`, with total length `4 + stored_size`. The returned
bytes have the same representation as a local block and MUST undergo the same
marker, transform, stored-size, original-size, and hash validation.

This specification does not define a network protocol or client. A resolver
that performs network access MUST require explicit enablement, enforce
response-size and time bounds, and apply its access policy to every network
target and redirect.

### 4.3 Directory Structure

A Directory contains the metadata for one appended archive segment, which ends
after the directory.

```rust
/// Directory - lists all files and blocks in this segment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub identifier: [u8; 8],                            // MUST be exactly ASCII b"PITHOSDR"
    pub parent_directory_offset: Option<(u64, u64)>,    // Previous directory (start, len) (varint, backwards chain)
    pub files: Vec<(u64, String, FileEntry)>,           // File ID, path, and body
    pub blocks: Vec<([u8; 32], BlockDescriptor)>,       // Block hash and body
    pub relations: Vec<(u64, String)>,                  // Relation idx, relationname / id
    pub encryption: Vec<([u8; 32], EncryptionSection)>, // Sender key and body
    pub dir_len: u64,
    pub crc32: u32,                                     // CRC-32/ISO-HDLC of serialized bytes through dir_len
}
```

**Encoded Form**

| Field | Bytes stored in the file |
| --- | --- |
| `identifier` | Exactly 8 bytes: ASCII `PITHOSDR` |
| `parent_directory_offset` | Option tag, then, for tag `01`, tuple of ULEB128 `start` and ULEB128 `len` |
| `files` | Vector of records: ULEB128 `file_id`, path string, then FileEntry body |
| `blocks` | Vector of items: `block_hash[32]`, then ULEB128 `offset`, ULEB128 `stored_size`, ULEB128 `original_size`, one flags byte, and location |
| `relations` | Vector of tuples: ULEB128 relationship ID followed by relationship-name string |
| `encryption` | Vector, which MAY be empty, of items: `sender_public_key[32]`, then a recipient-record vector |
| `dir_len` | Fixed-width `u64be` |
| `crc32` | Fixed-width `u32be` |

The parent option tag is `00` for no parent and `01` for a parent, followed by
the parent's zero-based start and complete length as ULEB128 values. The
selected chain MUST have exactly one base Directory, whose parent tag is `00`.
For tag `01`, the parent range MUST be within the file, end no later than the
child directory start, and have the same length as the parent's embedded
`dir_len`. Readers MUST use checked arithmetic for all ranges and validate each
parent's marker, length, CRC, and exact byte consumption before merging.
Readers MUST reject self-links, cycles, repeated parent ranges, forward links,
overlapping parent and child ranges, and invalid parent tags. Readers MAY
enforce documented chain-depth and total-directory-byte limits; exceeding one
MUST return a resource-limit error without exposing a partial archive view.

Readers MUST reject duplicate relationship IDs, duplicate sender public keys,
duplicate file IDs, duplicate file paths, or duplicate block hashes.

The directory marker MUST be exactly the eight ASCII bytes `PITHOSDR`. 
The final 12 directory bytes MUST be `dir_len:u64be || crc32:u32be`, where `dir_len` is the complete directory length from the marker through the CRC, inclusive. 
The CRC MUST be CRC-32/ISO-HDLC with width 32, polynomial `0x04C11DB7`, initial value`0xFFFFFFFF`, reflected input and output, and final XOR `0xFFFFFFFF` (the check value for ASCII `123456789` is `0xCBF43926`). 
It MUST cover every exact serialized byte from the marker through the fixed-width `dir_len`, excluding only the stored final CRC. 
Readers MUST validate the marker, embedded length, CRC, and exact parser consumption for the terminal Directory before decrypting, merging, or otherwise using its metadata. Invalid Directories MUST be rejected.

#### 4.3.1 Terminal Directory Lookup

To locate the terminal Directory during normal reading:

1. Read the final 12 file bytes as `dir_len:u64be || crc32:u32be`.
2. Compute `directory_start = file_length - dir_len` using checked subtraction.
3. Require `dir_len >= 25`, the syntactic framing floor for a Directory.
4. Parse the directory at `directory_start` and require it to end exactly at the end of the file.
5. Validate the marker, embedded length, CRC, and exact byte consumption before using metadata.

Normal reading MUST reject trailing bytes, truncation, underflow, a false marker, and a torn final append. It MUST NOT fall back to an older directory. Salvage is a separate mode; if it locates an older directory, it MUST label the result incomplete.

#### 4.3.2 Append Chains

Each Directory contains the entries introduced by its segment. To construct the
effective archive, readers merge the selected chain from the base Directory to
the terminal Directory. An append adds file entries, block
descriptors, relationship definitions, and recipient grants. Neither version
has deletion, replacement, or tombstone.

File IDs and paths MUST be unique across the selected chain. Writers assign file ID 0
to the first file and assign each later file ID as the current maximum ID plus
1, where the maximum also covers every piece key ID (Section 4.4.2). Readers MUST
accept unused file-ID gaps. A rename adds a file record with a
new file ID and path; the old record remains in the effective archive.

A repeated block hash in one Directory is invalid. Across Directories in the
selected chain, a block hash MAY reappear only when its `original_size` is the
same. The descriptor in the oldest Directory in the selected chain that
contains that hash remains the effective descriptor. Exact repeated
relationship definitions are allowed; conflicting definitions of one
relationship ID are invalid. Exact repeated recipient grants are allowed;
conflicting grants for the same sender public key and recipient public key are
invalid.

Recipient-grant equality is structural after ULEB128 decoding. Two grants are
equal when their sender public key, recipient public key, `RecipientData`
variant, and decoded body are equal. Encrypted bodies compare their complete
encrypted byte vectors. Decrypted bodies compare their ordered `(file_id,
file_key)` records. Different valid ULEB128 encodings of the same count, length,
or file ID do not make otherwise equal grants conflict.

The base Directory MUST store these ten standard relationship definitions in its
`relations` vector, in ascending relationship-ID order: `0 DESCRIBES`,
`1 ANNOTATES`, `2 DERIVED_FROM`, `3 SOURCE_OF`, `4 PREVIOUS_VERSION`,
`5 NEXT_VERSION`, `6 PART_OF`, `7 CONTAINS`, `8 INPUT_TO`, and
`9 OUTPUT_FROM`. Non-base Directories inherit these definitions and MAY repeat
one only when its relationship ID and stored name match exactly.

The relationship requirement is semantic validation separate from the `25`-byte
syntactic framing floor. A valid empty base Directory is 146 bytes, and the
minimum valid appended Directory is 28 bytes. A non-base Directory MAY have an
empty `relations` vector.

**Valid append-chain merge example:** three segments with parent order `base <-
append-1 <- append-2` introduce the following records.

| Segment | Entries introduced |
| --- | --- |
| `base` | file ID 0, `data/a`; block `H` with `original_size` 4; the ten standard relationships |
| `append-1` | file ID 1, `data/b`; exact repeat of block `H` with `original_size` 4; recipient grant `G` |
| `append-2` | file ID 2, `results/a`; block `J`; exact repeat of recipient grant `G` |

The final effective archive contains file IDs 0 (`data/a`), 1 (`data/b`), and 2
(`results/a`); block `H` from `base`; block `J`; the standard relationships; and
recipient grant `G`.

#### 4.3.3 Directory Entry and Path Ordering

Directory entries MUST follow these ordering and path rules:

1. An entry path is a non-empty UTF-8 sequence of non-empty `/`-separated
   components. It MUST NOT start or end with `/`, contain NUL or `\`, contain a
   `.` or `..` component, or use a drive-qualified form (a path whose second
   byte is `:`, such as invalid `C:` or `C:/data`).
2. The archive root path is implicit and MUST NOT have an entry.
3. A path is a descendant of a directory only when its component sequence has
   that directory's component sequence as a strict prefix. Every entry below the
   archive root path MUST have each of its ancestor paths declared as a
   `Directory` entry.
4. Declaration order is the concatenation of the `files` vectors from the base
   Directory through the terminal Directory, preserving each vector's stored
   order. Each ancestor Directory MUST occur before its descendant. An ancestor
   declared in an earlier Directory satisfies this rule for an entry in a later
   Directory.
5. Readers and writers MUST reject a path or declaration order that violates these rules.

**Valid ordering example:**
```
data                    (Directory)
data/raw                (Directory; parent `data` already declared)
data/raw/file1.csv       (Data; parent `data/raw` already declared)
data/processed          (Directory; parent `data` already declared)
data/processed/file2.csv (Data; parent `data/processed` already declared)
docs                    (Directory)
docs/README.md           (Data; parent `docs` already declared)
data/raw/file1_v2.csv    (Data; parent `data/raw` already declared)
```

**Invalid ordering example:**
```
data/raw/file1.csv       (parent `data/raw` not yet declared)
data/raw                (too late; parent `data` not yet declared)
data                    (too late; a descendant already occurred)
```

#### 4.3.4 Metadata Digest

The metadata digest of an archive is the BLAKE3 hash of the concatenated 32-byte
BLAKE3 hashes of each Directory's exact bytes, in selected-chain order from the
base Directory to the terminal Directory. It is not stored in the archive and is
the same for both versions. An application MAY keep the digest in storage it
trusts and supply it when it opens the archive again. A reader given an expected
digest MUST compare it after validating the Directory framing and before
decrypting, merging, or otherwise using any metadata, and MUST reject the archive
on a mismatch. Every append changes the digest.

### 4.4 File Representation

#### 4.4.1 File Types

FileType identifies the kind of a directory file record.

```rust
/// File types (u8 representation for efficiency)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Directory = 0,   // Directory entry
    Data = 1,        // Regular data file
    Metadata = 2,    // Metadata file (RO-Crate, DataCite, etc.)
    Symlink = 3,     // Symbolic link
    // Values 4-255 reserved for future use
}
```

**Encoded Form**

| Byte | Variant |
| --- | --- |
| `00` | `Directory` |
| `01` | `Data` |
| `02` | `Metadata` |
| `03` | `Symlink` |

FileType is stored as exactly one byte. Readers MUST reject values from `04`
through `ff`.

#### 4.4.2 Block Data State

BlockDataState stores encrypted file block data, a decrypted block list, or, in
version 1.1, a block list sealed in pieces.

```rust
pub enum BlockDataState {
    Encrypted(Vec<u8>),             // nonce || ciphertext || tag
    Decrypted(Vec<([u8; 32], [u8; 32])>), // Block hash and block key
    Pieces(Vec<(u64, Vec<u8>)>),    // Piece key ID and nonce || ciphertext || tag
}
```

**Encoded Form**

| Tag | Variant | Bytes after the tag |
| --- | --- | --- |
| `00` | `Encrypted` | Vector of bytes |
| `01` | `Decrypted` | Vector of tuples, each `block_hash[32] || block_key[32]` |
| `02` | `Pieces` | Vector of items, each ULEB128 `key_id` followed by a vector of bytes |

Readers MUST reject unknown tags. A decrypted block list is a ULEB128 count
followed by that many `block_hash[32] || block_key[32]` pairs. Block-list
identity, reuse, and validation are defined in Section 5.2.

Tag `02` is valid only in version 1.1 archives; readers MUST reject it in a
version 1.0 archive. Each piece decrypts, with the piece key granted for its
`key_id` (Section 5.3), to a decrypted block list in the encoding above. The
file's block list is the concatenation of the piece lists in stored order. The
vector MAY be empty, which is an empty block list. Within one file, `key_id`
values MUST be strictly increasing. A piece key ID MUST NOT equal any file ID in
the effective archive and MUST NOT appear in more than one piece of the
effective archive. Readers MUST reject an archive that violates these rules.
Pieces let a writer seal parts of one file independently and join them later
without opening any of them.

#### 4.4.3 File Entry

Each directory file record identifies and names one file, then stores its FileEntry body.

```rust

/// File entry - describes a single file, directory, or symlink
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub file_type: FileType,             // Type of entry
    pub block_data: BlockDataState,
    pub created: u64,                    // Unix timestamp (seconds since epoch)
    pub modified: u64,                   // Unix timestamp (seconds since epoch)
    pub file_size: u64,                  // Total size in bytes (varint)
    pub permissions: u32,                // Unix-style permissions
    pub references: Vec<Reference>,      // References from this file
    pub symlink_target: Option<String>,  // Target path for symlinks
}
```

**Encoded Form**

The directory file sequence is a vector. Each record is encoded as follows:

| Field | Bytes stored in the file |
| --- | --- |
| `file_id` | ULEB128 `u64` |
| `path` | String |
| `FileEntry` body | Fields in the following table |

| FileEntry body field | Bytes stored in the file |
| --- | --- |
| `file_type` | FileType encoded form above |
| `block_data` | Tag `00` and byte vector; tag `01` and vector of `block_hash[32] || block_key[32]` tuples; or, in version 1.1, tag `02` and vector of ULEB128 `key_id` plus byte-vector items (Section 4.4.2) |
| `created` | ULEB128 `u64` |
| `modified` | ULEB128 `u64` |
| `file_size` | ULEB128 `u64` |
| `permissions` | ULEB128 `u32` |
| `references` | Vector of tuples: ULEB128 `target_file_id` followed by ULEB128 `relationship` |
| `symlink_target` | Option tag, then, for tag `01`, a target string |

The `symlink_target` option tag is `00` for no target and `01` for a target.
Readers MUST reject other tags. File IDs and paths are record fields, not fields
of the FileEntry body.

**FileEntry field-combination validity:**

| `file_type` | `block_data` | `file_size` | `symlink_target` |
| --- | --- | --- | --- |
| `Directory` | MUST be `Decrypted` with an empty list | MUST be `0` | MUST be absent (`00`) |
| `Data` | `Encrypted` or `Decrypted`; in version 1.1 also `Pieces` | MUST equal the sum of referenced effective descriptors' `original_size` values when the block list is available | MUST be absent (`00`) |
| `Metadata` | `Encrypted` or `Decrypted`; in version 1.1 also `Pieces` | MUST equal the sum of referenced effective descriptors' `original_size` values when the block list is available | MUST be absent (`00`) |
| `Symlink` | MUST be `Decrypted` with an empty list | MUST be `0` | MUST be present (`01`) |

Readers MUST reject a combination that violates this table. For encrypted block
lists, the content-size validation for `Data` and `Metadata` occurs once the
block list is available; until then, the content is unavailable as specified in
Section 8.2. A block list sealed in pieces is available once every piece is
decrypted.

`permissions` stores the low 12 bits of a POSIX mode, in the range
`0o0000..=0o7777`; file-type bits are not stored. Readers MUST reject a value
with any higher bit set and retain all 12 bits as metadata. An extractor MUST
NOT apply set-user-ID, set-group-ID, or sticky bits unless the caller explicitly
opts in. A non-POSIX implementation MAY retain the value as metadata and need
not map it to a platform ACL.

For a `Symlink`, `symlink_target` is a non-empty UTF-8 sequence of non-empty
`/`-separated components. It MUST NOT contain NUL or `\`, start with `/`, use a
drive-qualified form as defined for entry paths, or contain a `.` component. A
`..` component is permitted only when lexical interpretation of the target
relative to the symlink's parent does not move above the archive root path. The
target need not name an existing entry: contained dangling links and cycles are
valid.

#### 4.4.4 File References

A Reference identifies a target file and a relationship. The file containing the
Reference is the source, and `target_file_id` identifies the target. Any file
type MAY be a source or target.

```rust
/// Simplified reference structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub target_file_id: u64,    // Target file ID (varint)
    pub relationship: u64,      // Relationship type (varint)
}
```

**Encoded Form**

| Field | Bytes stored in the file |
| --- | --- |
| `target_file_id` | ULEB128 `u64` |
| `relationship` | ULEB128 `u64` |

References have no tag or length of their own; their containing vector provides
the count. Readers MUST consume both fields for every reference. The target file
ID and relationship ID MUST each exist in the effective archive.

**Standard relationship semantics:**

| ID | Stored name | Meaning |
| --- | --- | --- |
| 0 | `DESCRIBES` | The source describes the target. |
| 1 | `ANNOTATES` | The source annotates the target. |
| 2 | `DERIVED_FROM` | The source is derived from the target. |
| 3 | `SOURCE_OF` | The source is a source of the target. |
| 4 | `PREVIOUS_VERSION` | The source is the previous version of the target. |
| 5 | `NEXT_VERSION` | The source is the next version of the target. |
| 6 | `PART_OF` | The source is part of the target. |
| 7 | `CONTAINS` | The source contains the target. |
| 8 | `INPUT_TO` | The source is an input to the target. |
| 9 | `OUTPUT_FROM` | The source is an output from the target. |

Custom relationship IDs MUST be at least `1000`; their stored names MUST be
non-empty UTF-8 strings.

The following are valid relationship-interpretation examples. A reference from `normalized.csv` to `raw.csv` with
`DERIVED_FROM` means `normalized.csv` is derived from `raw.csv`; reversing the
reference means `raw.csv` is derived from `normalized.csv`. A reference from
`raw.csv` to `normalized.csv` with `SOURCE_OF` means `raw.csv` is a source of
`normalized.csv`. A reference from `report-v1.pdf` to `report-v2.pdf` with
`PREVIOUS_VERSION` means `report-v1.pdf` is the previous version of
`report-v2.pdf`; reversing it with `NEXT_VERSION` means `report-v2.pdf` is the
next version of `report-v1.pdf`.

### 4.5 Encryption Section

Encryption sections are items in `Directory.encryption` and carry per-sender
recipient data.

#### 4.5.1 EncryptionSection

An EncryptionSection contains the recipient records associated with one sender public key.

```rust
/// Encryption section - per-sender recipient access data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionSection {
    pub recipients: Vec<([u8; 32], RecipientSection)>, // Recipient key and body
}
```

**Encoded Form**

The Directory `encryption` vector stores each sender public key as the leading
32 bytes of its item, followed by this EncryptionSection body:

| Field | Bytes stored in the file |
| --- | --- |
| `recipients` | Vector of records: `recipient_public_key[32]` followed by RecipientSection body |

Sender public keys are exactly 32 bytes. Readers MUST reject a duplicate sender
key within a directory.

#### 4.5.2 RecipientSection

A RecipientSection contains the data associated with one recipient public key.

```rust
/// Per-recipient encrypted data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSection {
    pub recipient_data: RecipientData,   // Encrypted FileKeyEntry list
}
```

**Encoded Form**

Each recipient record stores its recipient public key as the leading 32 bytes,
followed by this RecipientSection body:

| Field | Bytes stored in the file |
| --- | --- |
| `recipient_data` | Tag `00` and byte vector, or tag `01` and vector of ULEB128 `file_id` plus `file_key[32]` tuples |

Recipient public keys are exactly 32 bytes. Readers MUST reject a duplicate
recipient key within an EncryptionSection.

#### 4.5.3 RecipientData

RecipientData stores either encrypted recipient data or a decrypted file-key list.

```rust
pub enum RecipientData {
    Encrypted(Vec<u8>),             // nonce || ciphertext || tag
    Decrypted(Vec<(u64, [u8; 32])>) // File ID and file key
}
```

**Encoded Form**

| Tag | Variant | Bytes after the tag |
| --- | --- | --- |
| `00` | `Encrypted` | Vector of bytes |
| `01` | `Decrypted` | Vector of tuples, each ULEB128 `file_id` followed by `file_key[32]` |

Readers MUST reject unknown tags. A decrypted recipient-data list is a ULEB128
count followed by that many ULEB128 `file_id` and `file_key[32]` pairs. A
repeated file ID is valid only when it has the same file key; readers MUST
reject a conflicting duplicate file ID and file key. In version 1.1 the
`file_id` field may also hold a piece key ID; its `file_key` is then that
piece's key. Access to a file sealed in pieces therefore needs one record
for each of its piece key IDs.

## 5. Content Processing

### 5.1 Chunking

Writers choose block boundaries. Fixed-size blocks and content-defined chunking
are both valid. Chunking parameters are writer guidance, not a compatibility
requirement; see Appendix A.

### 5.2 Block Hashing

The block hash is a block's only identity. It is 32 bytes and covers the exact
plaintext chunk before compression or encryption. Its form depends on
ProcessingFlags bit 4 of the block's effective descriptor:

- **Convergent key (bit 4 is `0`):** the full default unkeyed BLAKE3 digest of
  the plaintext.
- **Unique key (bit 4 is `1`):** a keyed BLAKE3 identity. The 32-byte identity
  subkey is BLAKE3 `derive_key` with the context string
  `pithos 1.1 block identity` (25 ASCII bytes) and the block key as key
  material. The block hash is BLAKE3 `keyed_hash` of the plaintext under the
  identity subkey. Equal plaintext under different random keys has different
  block hashes.

A keyed block hash identifies one stored block. It is not a content hash of the
block or of its file and cannot be compared with a plain BLAKE3 digest.

The Directory `blocks` vector is keyed by block hash, and each file's block list
is an ordered sequence of `(block_hash, block_key)` pairs. That order
reconstructs the file. For a file sealed in pieces, the sequence is the
concatenation of its piece lists, and every rule in this section applies to that
whole sequence.

Every block hash referenced by a file MUST resolve to exactly one effective
descriptor after the selected chain is merged. A repeated hash in one file is
valid only if every occurrence carries the same block key; otherwise readers
MUST reject the file. Two files MAY reference the same hash and effective
descriptor. Deduplication is a writer choice: a writer MAY store the same
plaintext again, provided the directory conflict rules in Section 4.3.2 are
satisfied.

Using checked arithmetic, readers MUST sum the `original_size` of each
referenced effective descriptor and require the result to equal `file_size`. An
empty file has `file_size` zero and an empty block list.

Readers MUST retrieve each stored block, authenticate and decrypt it when
encrypted, decompress it when compressed using the recorded original size as
the output bound, require the resulting plaintext length to equal the recorded
original size, compute the block hash of the complete plaintext in the form
selected above, and compare it with the stored block hash before releasing any
output derived from that block.

Readers MAY use bounded memory or temporary spill-backed storage while
performing this verification, but MUST NOT release output derived from a block
until its required transforms, size, and hash have all been verified.

**Block-list reuse examples:** where `H` and `J` are distinct block hashes and
`K` and `L` are block keys, each row states its explicit verdict.

| Case | Block lists or directory records | Validity and reconstruction result |
| --- | --- | --- |
| Reuse by two files | `a: [(H, K)]`; `b: [(H, K)]` | Valid. Both files reconstruct from the effective descriptor for `H`. |
| Repetition in one file | `a: [(H, K), (H, K)]` | Valid. `a` reconstructs as the plaintext for `H` followed by itself. |
| Conflicting key | `a: [(H, K), (H, L)]` | Invalid. The file is rejected. |
| Later-segment size conflict | Base Directory has `H` with `original_size: 4`; an appended Directory has `H` with `original_size: 5` | Invalid. The appended Directory is rejected; no effective descriptor is selected from it. |
| Repetition across pieces | `a` sealed in pieces `[(H, K)]` and `[(H, K)]` | Valid. The whole sequence is `[(H, K), (H, K)]`. |
| Conflicting key across pieces | `a` sealed in pieces `[(H, K)]` and `[(H, L)]` | Invalid. The rule applies to the whole sequence; the file is rejected. |
| Unique keys and equal plaintext | `a: [(H, K), (J, L)]`; both blocks set bit 4, have equal plaintext, and have random keys `K` and `L` | Valid. `H` and `J` differ because each is keyed by its own block key; each has its own descriptor. |

### 5.3 Convergent Encryption

Encryption is optional. An implementation that supports encryption MUST use
X25519, SHAKE256, and ChaCha20-Poly1305 as specified here. Version 1.1 adds
HKDF-SHA256 for recipient grants, BLAKE3 key derivation and, for blocks that set
ProcessingFlags bit 5, AES-256-GCM.

All encryption keys are 32 bytes. ChaCha20-Poly1305 and AES-256-GCM each use a
12-byte nonce and produce a 16-byte authentication tag. Every encrypted value is stored as
`nonce || ciphertext || tag`; the nonce is part of the stored byte vector. The
additional authenticated data (AAD) is empty.

By default the block key is convergent: the first 32 output bytes of
`SHAKE256(plaintext)`, where `plaintext` is the exact block plaintext before
compression or encryption. No label or length prefix is included. A block
payload with encryption enabled and ProcessingFlags bit 5 clear is encrypted
with its block key directly. With bit 5 set, the payload key is derived from the
block key as described below.

In version 1.1, a block whose ProcessingFlags bit 4 is set has a unique key
instead: 32 bytes generated uniformly at random with a cryptographically secure
random number generator. A writer MUST generate a fresh unique key for every
block it encodes in this mode, including a block whose plaintext it has stored
before, and MUST NOT use that key for any other block. Unique-key blocks are
therefore never deduplicated: each occurrence is stored with its own key and
block hash (Section 5.2). The block list carries the unique key like any other
block key.

In version 1.1, a block whose ProcessingFlags bit 5 is set has an AES-256-GCM
payload instead of a ChaCha20-Poly1305 payload. Its payload key is the 32-byte
BLAKE3 `derive_key` output with the context string
`pithos 1.1 aes-256-gcm payload` (30 ASCII bytes) and the block key as key
material. The block key itself is convergent or unique as described above, and
it is the key stored in the block list. The payload is stored as
`nonce || ciphertext || tag` with empty AAD. Block lists, pieces and recipient
grants always use ChaCha20-Poly1305.

The cipher is a property of each effective descriptor, not of the archive. One
archive, and one file, MAY contain blocks sealed with both ciphers. A writer
that reuses an existing descriptor for a convergent block hash, by
deduplication or composition, keeps that descriptor's cipher. Requesting
AES-256-GCM therefore does not guarantee that every block of a file uses it.
Readers MUST select the cipher from each block's effective descriptor.

A file key is 32 random bytes. It encrypts the decrypted block list for a file.
In version 1.1, a piece key is 32 random bytes and encrypts the decrypted block
list of one piece in the same way.
For each recipient record, the shared secret is the raw 32-byte X25519 shared
secret between the sender private key and recipient public key. The wrapping key
encrypts the decrypted recipient list with ChaCha20-Poly1305:

- **Version 1.0:** the wrapping key is the shared secret itself.
- **Version 1.1:** the wrapping key is the 32-byte HKDF-SHA256 output
  (RFC 5869) with the record's 12-byte nonce as salt, the shared secret as input
  key material, and info `pithos 1.1 recipient grant` (26 ASCII bytes) followed
  by the sender public key and then the recipient public key. The keys are the
  ones stored in the Directory: the EncryptionSection key and the recipient
  record key.

Each version 1.1 grant key is therefore bound to both public keys and to the
grant nonce. Grants with different nonces have different keys; a repeated nonce
for the same key pair repeats the key (Section 7).
Implementations MUST reject non-contributory X25519 public keys.

An implementation MUST generate every nonce independently and uniformly at
random with a cryptographically secure random number generator and MUST NOT
deliberately reuse a nonce under the same key. It MUST authenticate and decrypt
an encrypted value successfully before using its plaintext or releasing output
derived from it.

**Nonce scope of block payloads.** A ChaCha20-Poly1305 payload uses the block key
as its AEAD key, and an AES-256-GCM payload uses the derived payload key, so the
two ciphers never share an AEAD key. A unique key seals exactly one payload. A
convergent key is the same for every encryption of the same block plaintext, by
any writer and in any archive. All those encryptions share one key and one
random-nonce scope. NIST SP 800-38D Section 8.3 limits AES-GCM with random
96-bit nonces to at most 2^32 invocations of the encryption function per key.
Writers SHOULD apply the same limit to ChaCha20-Poly1305 block payloads. A
repeated nonce under one key exposes the XOR of the two stored payloads, which
can differ in compression, and AES-256-GCM also loses authenticity under that
key; the block hash check still rejects altered plaintext. Writers SHOULD reuse
an existing stored block instead of encrypting a convergent block again.
Deployments that may encrypt one plaintext more often than this bound across
all archives SHOULD use unique keys.

Neither version uses a SHAKE256 label or AAD. A redesign of any cryptographic
input requires a new format version.

### 5.4 Compression

The compression value in ProcessingFlags describes the stored payload actually
written. Value `0` means the stored payload is not compressed. Each nonzero
value from `1` through `7` means the stored payload is one standard Zstandard
frame. Readers that support compression MUST decode any valid Zstandard frame
and bound decompressed output by `original_size`; they do not need the writer's
compression level.
Readers MUST reject ProcessingFlags with any nonzero reserved bit.
A writer that stores the plaintext payload rather than compressed data MUST
encode compression value `0`.

Conforming encoders need not produce byte-identical Zstandard output. Appendix B
provides decode-direction vectors containing stored compressed bytes,
`original_size`, the expected plaintext, and its expected 32-byte BLAKE3 hash.
Those vectors MUST decode to the expected plaintext with different supported
Zstandard versions.

## 6. Operations Overview

### 6.1 Reading Operations

1. Read and validate file header
2. Locate and validate the terminal Directory using the direct lookup in Section 4.3.1, then each parent Directory of the selected chain
3. Validate directory ordering
4. Build the effective block-descriptor mapping
5. Extract files by reading referenced blocks, checking each local block's marker as it is read (Section 4.2.5)

Steps 1 to 4 open the archive. They validate metadata only and read no block
bytes, so the number of reads at open depends on the length of the chain, not on
the number of blocks.

### 6.2 Writing Operations

1. Write the file header: version 1.1 for a new archive. An append writes no
   header and keeps the version of the archive it extends (Section 1.3).
2. Process files in correct directory order
3. Split content into blocks (fixed-size or content-defined)
4. Choose the ProcessingFlags of each new block. In version 1.1 an encrypted
   block MAY also set bit 4 (unique key) or bit 5 (AES-256-GCM), or both. An
   append to a version 1.0 archive MUST NOT set either bit and SHOULD reject
   such a request before writing any bytes.
5. Deduplicate convergent blocks by hash. A reused descriptor keeps its own
   flags, including its cipher. Unique-key blocks are never deduplicated.
6. Store each file's block list decrypted, encrypted under a file key, or, in
   version 1.1, sealed in pieces under piece keys (Section 4.4.2).
7. Write a directory, including its encryption sections when present. A
   recipient needs a grant for the file key or for every piece key of each file
   it may read (Section 4.5.3).
8. Validate complete structure

A version 1.1 writer MAY also join independently written pieces without their
keys: it writes the header, the stored blocks of every piece in order, and one
Directory. That Directory has one file record whose `Pieces` state lists the
sealed piece lists in order, one descriptor for each distinct block hash, and
the unchanged piece grants (Appendix A).

### 6.3 Directory Tree Operations

When archiving directory trees:
1. Process directories before their contents
2. Maintain relative path structure
3. Preserve file metadata (permissions, timestamps)
4. Handle symlinks appropriately per platform

## 7. Security Considerations

Directory CRC-32 detects accidental corruption of the serialized Directory bytes
it covers; it is not authentication. An application that keeps the metadata
digest (Section 4.3.4) in trusted storage gains metadata integrity for its own
later reads; the digest does not authenticate archive origin to anyone else. Neither version provides archive-wide origin
authentication or metadata integrity: an unauthenticated Directory can replace
both a block hash and its referenced content. AEAD authenticates each encrypted
value's ciphertext, but its empty AAD does not bind that value to its surrounding
Directory, file, or recipient context. BLAKE3 verifies a recovered plaintext
against the hash supplied by the Directory; without authenticated metadata, it
does not authenticate archive origin.

Encrypted `RecipientData` protects file-key grants only when its `Encrypted`
form is used. Sender and recipient public keys, encryption-section and
recipient counts, ciphertext lengths, and the segment timing of grants are
visible. `RecipientData::Decrypted` exposes its file-key grants and provides no
grant confidentiality.

Version 1.0 recipient wrapping uses a raw static X25519 shared secret directly as
its AEAD key, with no KDF, label, or AAD. That construction has no domain
separation, and each static sender-recipient key pair has one nonce-collision
scope across all archives that use it. Version 1.1 derives every wrapping key
with HKDF-SHA256 from the shared secret, the grant's random nonce and both public
keys. This adds domain separation and binds each wrapping key to its sender and
recipient. It does not shrink the nonce-collision scope: the nonce is the HKDF
salt, so a repeated grant nonce for the same sender and recipient key pair
repeats both the derived key and the AEAD nonce. Each key pair therefore still
has one nonce-collision scope across all archives that use it. A fresh sender
key for each archive or piece keeps that scope small. Appends to version 1.0
archives keep the version 1.0 construction. The plaintext-derived Directory block hash exposes
block equality, and equal plaintext also derives the same convergent block key.

Unique-key blocks (Section 5.3) hide one thing: whether two stored blocks have
equal plaintext, from anyone who does not hold the block key. Their block hashes
are keyed with random keys, so equal plaintext gives unrelated hashes in the
same or in different archives. Unique keys do not hide stored and original block
sizes, the number of blocks, the ProcessingFlags, or file sizes. A reader that
holds a block key can test a guessed plaintext against that block's hash. A whole-file content hash
kept outside the archive is separate from the keyed block identity and still
reveals equal files.

The payload cipher (ChaCha20-Poly1305 or AES-256-GCM) does not change what is
hidden. Every encryption of one convergent block shares one key and one nonce
scope across all archives; Section 5.3 states the resulting invocation bound.

Pieces are joined in the order the Directory stores them. Their strictly
increasing key IDs and the `file_size` check detect some reordering and missing
pieces, but without authenticated metadata a modified Directory can still drop or
reorder whole pieces together with `file_size`.

Readers must verify each block as required by Section 5.2 before releasing its
output. Networked external resolution can expose a caller to unsafe targets and
resource exhaustion; Section 4.2.6 defines the required resolver safeguards.
Extraction safety requires that archive paths are created without traversing
archive-created or pre-existing symlinks, existing entries are not clobbered by
default, and special permission bits are not applied without explicit caller
policy; Sections 8.3 and 4.4.3 define these requirements.

## 8. Implementation Requirements

### 8.1 Base Reader and Writer

A base reader supports the version 1.0 and 1.1 structure, including its required
validation, and can read local blocks whose ProcessingFlags have compression
value `0` and encryption bit `0`. It supports decrypted BlockDataState lists.
A base writer can create an archive containing only such local blocks and an
empty Directory `encryption` vector.

**Optional-capability indications:** a reader discovers a
needed capability from the stored fields; it does not use a profile or a
negotiation record.

| Capability | Stored indication |
| --- | --- |
| Block compression | ProcessingFlags compression bits are `1` through `7` |
| Block encryption | ProcessingFlags encryption bit is `1` |
| Unique block keys | ProcessingFlags bit 4 is `1` (version 1.1) |
| AES-256-GCM payloads | ProcessingFlags bit 5 is `1` (version 1.1) |
| Encrypted block lists | BlockDataState tag is `00` (`Encrypted`) or, in version 1.1, `02` (`Pieces`) |
| Encrypted recipient lists | RecipientData tag is `00` (`Encrypted`) |
| External storage | BlockLocation tag is `01` (`External`) |

Compression, block encryption, unique block keys, AES-256-GCM payloads,
encrypted block lists, encrypted recipient lists, and external storage are
optional capabilities. An
implementation that supports an optional capability MUST process it according
to its definition in this specification.

### 8.2 Unavailable Content

A reader MUST validate and list an archive whose known-version, known-tag
structure contains content requiring an unsupported optional capability. It
MUST mark only the affected content unavailable; unaffected entries remain
readable. Attempting to read unavailable content MUST return
`UnsupportedFeature` before releasing any output derived from that content.
The reader MUST NOT reinterpret bytes requiring an unsupported capability as
uncompressed or unencrypted bytes.

**Unsupported-capability outcomes:**

| Block form | Listing result | Content-read result |
| --- | --- | --- |
| Plain local: local, compression `0`, encryption `0` | Listed | Readable by a base reader |
| Compressed local: local, compression `1` through `7`, encryption `0` | Listed | Readable only with block-compression capability; otherwise unavailable |
| Encrypted local: local, compression `0`, encryption `1` | Listed | Readable only with block-encryption capability and any encrypted-list capability needed to obtain its block key; otherwise unavailable |
| Unique-key local: local, encryption `1`, bit 4 `1` | Listed | Readable only with block-encryption and unique-block-key capability and any encrypted-list capability needed to obtain its block key; otherwise unavailable |
| AES-256-GCM local: local, encryption `1`, bit 5 `1` | Listed | Readable only with block-encryption and AES-256-GCM capability and any encrypted-list capability needed to obtain its block key; otherwise unavailable |
| External: BlockLocation `External` | Listed | Readable only with external-storage capability and every capability required by its flags and data states; otherwise unavailable |
| Combined: any combination of compression, encryption, unique key, and AES-256-GCM, at either location | Listed | Readable only when every indicated capability is supported; otherwise unavailable |

For the table, an encrypted BlockDataState, which includes a `Pieces` state,
requires encrypted-block-list capability, and an encrypted RecipientData
required to obtain its file key or piece keys requires encrypted-recipient-list
capability. Content sealed in pieces is unavailable until the key of every piece
is available. A content read that needs either unsupported list form is
unavailable even when its block flags themselves are otherwise supported.

Readers MUST reject an unsupported header version and any unknown tag rather
than list the archive, because the structure of such input is not known.

Both versions intentionally permit decrypted block and recipient list variants
and an empty Directory `encryption` vector.

### 8.3 Platform-Specific Considerations

#### Symlinks

An extractor on a platform that supports symbolic links MAY create a symbolic
link with the stored target. While creating other archive entries, it MUST NOT
traverse an archive-created or pre-existing symbolic link. An extractor MUST
NOT clobber an existing entry by default. On a platform that does not support
symbolic links, an extractor MAY reject the operation or skip the symlink with a
diagnostic, but MUST NOT silently change the entry type.

#### Permissions

Extractors apply permissions subject to the FileEntry rules in Section 4.4.3.
Non-POSIX platforms MAY retain them as metadata without an ACL mapping.

#### Path Separators
- Archives use forward slashes (`/`) internally
- Convert to platform-appropriate separators on extraction

## 9. Future Extensions

The format reserves space for future extensions:
- Header versions other than `0x0100` and `0x0101`
- FileType values 4-255
- ProcessingFlags bits 6-7
- Relationship IDs 10 through 999, for future standard relationships
- Custom relationship types starting at 1000
- BlockDataState tags `03` through `ff`
- BlockLocation and RecipientData tags `02` through `ff`

Custom relationship types are valid as defined in Section 4.4.4. Readers of this
version MUST reject every other value listed here (Sections 3.1 and 8.2).

A paged block index for very large files is a planned extension. It would let a
reader fetch only the descriptors and block keys a byte range needs. Version 1.1
keeps every block list complete in its Directory, so writers of very large files
should use larger blocks to keep Directories small.

Extensions MUST maintain backwards compatibility for reading.

## 10. Constants and Identifiers

### 10.1 Magic Values

- File Header: `b"PITH"`
- Block Header: `b"BLCK"`
- Directory: `b"PITHOSDR"`

### 10.2 Version Numbers

- Version 1.0: `0x0100`
- Version 1.1: `0x0101`

### 10.3 Key-Derivation Context Strings

Version 1.1 uses these ASCII strings, without a terminator:

- `pithos 1.1 block identity`: block identity subkey (Section 5.2)
- `pithos 1.1 aes-256-gcm payload`: AES-256-GCM payload key (Section 5.3)
- `pithos 1.1 recipient grant`: HKDF info prefix of a grant key (Section 5.3)

### 10.4 Default Values

- Current timestamp: Unix seconds since epoch
- Default file permissions: `0o644`
- Default directory permissions: `0o755`
- Default symlink permissions: `0o777`

## Appendix A. Writer Guidance (Non-Normative)

This appendix suggests writer choices only. It does not define archive
conformance or reader behavior.

**Recommended block size:** fixed 4 MiB (4,194,304 byte) blocks. Every block
of an independently encoded part has this size except its last, which may be
shorter. A file written in one pass therefore has at most one short block, at
its end. A file joined from pieces has one possible short block at the end of
each piece: two 5 MiB pieces give blocks of 4, 1, 4 and 1 MiB. Block boundaries
depend only on byte offsets within a part, not on how the input was read. This
suits object storage and multipart uploads, where parts are written
independently.
Content-defined chunking (for example FastCDC) is optional. It can find more
repeated blocks when content shifts, at the cost of variable block sizes.

**Directory size:** each block adds one descriptor and one block-list entry, so
the directory grows with the block count. A 5 TiB file at 4 MiB blocks has
about 1.31 million blocks and roughly 150 MB of directory. Smaller blocks
increase this size in proportion.

**Recommended compression mapping:** a writer may map ProcessingFlags values
`1` through `7` to Zstandard levels `1`, `4`, `8`, `11`, `15`, `18`, and `22`,
respectively. A writer may sample 4096 bytes and require a 0.85 compression
ratio before compressing. These suggestions are non-normative.

**Joining independently written parts:** a version 1.1 writer may encode each
part of a file on its own, seal that part's block list as one piece under a fresh
piece key, and grant the piece key with a fresh sender key per piece. A later
step can then join the parts into one archive without any key: it copies the
stored blocks, keeps every sealed piece and grant unchanged, and writes one
Directory. Because convergent block keys are equal for equal plaintext, a block
that repeats in two parts needs only one effective descriptor. Unique-key blocks
never repeat.

**Whole-file hash of joined parts:** a writer that knows a part's absolute file
offset (a multiple of 1024 bytes) may also keep the BLAKE3 chaining values of
the aligned subtrees that cover that part. The joining step can merge them into
the BLAKE3 hash of the whole file without any key. This works only when the
recorded offsets match the actual part sizes. The result is only as trustworthy
as the stored part records; a full read of the file confirms it. Chaining values
are plaintext fingerprints, like convergent block hashes, so a writer that uses
unique-key blocks should not keep them unless the owner allows it. This record
is not part of the archive format.

## Appendix B. Conformance Examples and Vectors

This appendix is informative. The cited sections remain authoritative. Complete
archives appear only here so that an implementation can use these bytes directly
as test input.

### B.1 Notation and Byte Anchors

Hex offsets are zero-based file offsets. Each hex line contains at most 16 bytes;
`0000:` is an offset, not encoded data. Integers without a fixed-width suffix use
shortest ULEB128 in these deterministic vectors, although Section 3.1 also
permits bounded non-minimal forms. `u64be` and `u32be` are big-endian. The
canonical archives are version 1.0 archives, which every reader accepts, so their
header is always
`50 49 54 48 01 00` (`PITH`, version `0x0100`); the other magic values are
`42 4c 43 4b` (`BLCK`) and `50 49 54 48 4f 53 44 52` (`PITHOSDR`).

CRC values use Section 4.3's CRC-32/ISO-HDLC definition. As a check on an
implementation, CRC-32 of ASCII `123456789` is `cb f4 39 26`.

### B.2 Canonical Archives

#### CV-BASE-EMPTY-146

| Item | Value |
| --- | --- |
| Purpose | Minimal valid base archive with its ten required relationships |
| Required capability | Base reader |
| Total length | 152 bytes (6-byte header plus 146-byte Directory) |
| Expected result | Valid empty archive |

```text
0000: 50 49 54 48 01 00 50 49 54 48 4f 53 44 52 00 00
0010: 00 0a 00 09 44 45 53 43 52 49 42 45 53 01 09 41
0020: 4e 4e 4f 54 41 54 45 53 02 0c 44 45 52 49 56 45
0030: 44 5f 46 52 4f 4d 03 09 53 4f 55 52 43 45 5f 4f
0040: 46 04 10 50 52 45 56 49 4f 55 53 5f 56 45 52 53
0050: 49 4f 4e 05 0c 4e 45 58 54 5f 56 45 52 53 49 4f
0060: 4e 06 07 50 41 52 54 5f 4f 46 07 08 43 4f 4e 54
0070: 41 49 4e 53 08 08 49 4e 50 55 54 5f 54 4f 09 0b
0080: 4f 55 54 50 55 54 5f 46 52 4f 4d 00 00 00 00 00
0090: 00 00 00 92 a0 cf 03 d2
```

| Offset range | Bytes | Field | Decoded value | Meaning |
| --- | --- | --- | --- | --- |
| `00..05` | `50 49 54 48 01 00` | header | Pithos 1.0 | File header |
| `06..0d` | `50 49 54 48 4f 53 44 52` | identifier | `PITHOSDR` | Directory marker |
| `0e..11` | `00 00 00 0a` | parent, files, blocks, relations count | none, 0, 0, 10 | Empty base records |
| `12..8a` | shown | relations | IDs 0 through 9 | Required standard definitions in order |
| `8b` | `00` | encryption count | 0 | No grants |
| `8c..93` | `00 00 00 00 00 00 00 92` | `dir_len` | 146 | Complete Directory length |
| `94..97` | `a0 cf 03 d2` | CRC | `0xa0cf03d2` | Stored CRC |

The Directory starts at `0x06`; `dir_len = 146`; its CRC-covered range is
`0x06..0x93` inclusive (142 bytes), and its stored CRC is at `0x94..0x97`.
Length arithmetic is `8 + 1 + 1 + 1 + 1 + 121 + 1 + 8 + 4 = 146`.
The output has no entries or blocks and has the ten Section 4.3.2 relationships.

#### CV-APPEND-EMPTY-28

| Item | Value |
| --- | --- |
| Purpose | Valid base Directory followed by the smallest valid appended terminal Directory |
| Required capability | Base reader with append-chain support |
| Total length | 180 bytes |
| Expected result | Valid empty archive; terminal parent is the base Directory |

```text
0000: 50 49 54 48 01 00 50 49 54 48 4f 53 44 52 00 00
0010: 00 0a 00 09 44 45 53 43 52 49 42 45 53 01 09 41
0020: 4e 4e 4f 54 41 54 45 53 02 0c 44 45 52 49 56 45
0030: 44 5f 46 52 4f 4d 03 09 53 4f 55 52 43 45 5f 4f
0040: 46 04 10 50 52 45 56 49 4f 55 53 5f 56 45 52 53
0050: 49 4f 4e 05 0c 4e 45 58 54 5f 56 45 52 53 49 4f
0060: 4e 06 07 50 41 52 54 5f 4f 46 07 08 43 4f 4e 54
0070: 41 49 4e 53 08 08 49 4e 50 55 54 5f 54 4f 09 0b
0080: 4f 55 54 50 55 54 5f 46 52 4f 4d 00 00 00 00 00
0090: 00 00 00 92 a0 cf 03 d2 50 49 54 48 4f 53 44 52
00a0: 01 06 92 01 00 00 00 00 00 00 00 00 00 00 00 1c
00b0: 50 a2 dc 75
```

| Offset range | Bytes | Field | Decoded value | Meaning |
| --- | --- | --- | --- | --- |
| `00..97` | same as CV-BASE-EMPTY-146 | base segment | 146-byte Directory | Valid base |
| `98..9f` | `50 49 54 48 4f 53 44 52` | identifier | `PITHOSDR` | Terminal marker |
| `a0..a3` | `01 06 92 01` | parent | start 6, length 146 | Backward parent range |
| `a4..a7` | `00 00 00 00` | vector counts | 0, 0, 0, 0 | Empty files, blocks, relations, encryption |
| `a8..af` | `00 00 00 00 00 00 00 1c` | `dir_len` | 28 | Terminal length |
| `b0..b3` | `50 a2 dc 75` | CRC | `0x50a2dc75` | Stored CRC |

The terminal Directory starts at `0x98`; `dir_len = 28`; its CRC-covered range
is `0x98..0xaf`; CRC is `0x50a2dc75` at `0xb0..0xb3`. Its arithmetic is
`8 + (1 + 1 + 2) + 4 + 8 + 4 = 28`. Expected output is the same
empty entry set and inherited ten relationships as the base.

#### CV-LOCAL-HELLO-279

| Item | Value |
| --- | --- |
| Purpose | Plain local block and one `Data` entry named `hello` |
| Required capability | Base reader |
| Total length | 279 bytes |
| Expected result | Valid archive; read `hello` as ASCII `hello` |

```text
0000: 50 49 54 48 01 00 42 4c 43 4b 68 65 6c 6c 6f 50
0010: 49 54 48 4f 53 44 52 00 01 00 05 68 65 6c 6c 6f
0020: 01 01 01 ea 8f 16 3d b3 86 82 92 5e 44 91 c5 e5
0030: 8d 4b b3 50 6e f8 c1 4e b7 8a 86 e9 08 c5 62 4a
0040: 67 20 0f 12 34 07 5a e4 a1 e7 73 16 cf 2d 80 00
0050: 97 45 81 a3 43 b9 eb bc a7 e3 d1 db 83 39 4c 30
0060: f2 21 62 00 00 05 a4 03 00 00 01 ea 8f 16 3d b3
0070: 86 82 92 5e 44 91 c5 e5 8d 4b b3 50 6e f8 c1 4e
0080: b7 8a 86 e9 08 c5 62 4a 67 20 0f 06 05 05 00 00
0090: 0a 00 09 44 45 53 43 52 49 42 45 53 01 09 41 4e
00a0: 4e 4f 54 41 54 45 53 02 0c 44 45 52 49 56 45 44
00b0: 5f 46 52 4f 4d 03 09 53 4f 55 52 43 45 5f 4f 46
00c0: 04 10 50 52 45 56 49 4f 55 53 5f 56 45 52 53 49
00d0: 4f 4e 05 0c 4e 45 58 54 5f 56 45 52 53 49 4f 4e
00e0: 06 07 50 41 52 54 5f 4f 46 07 08 43 4f 4e 54 41
00f0: 49 4e 53 08 08 49 4e 50 55 54 5f 54 4f 09 0b 4f
0100: 55 54 50 55 54 5f 46 52 4f 4d 00 00 00 00 00 00
0110: 00 01 08 7c 05 e6 a2
```

| Offset range | Bytes | Field | Decoded value | Meaning |
| --- | --- | --- | --- | --- |
| `00..0e` | header, `42 4c 43 4b 68 65 6c 6c 6f` | header and block | `BLCK || hello` | Local extent `[6, 15)` |
| `0f..16` | `PITHOSDR` | identifier | Directory | Directory start |
| `17..1f` | `00 01 00 05 68 65 6c 6c 6f` | parent, files, ID, path | base; one record; ID 0; path `hello` | No trailing slash |
| `20..69` | shown | FileEntry | Data, decrypted list of one pair, times 0, size 5, permissions `0o644`, no references/target | Valid Data combination |
| `6a..8f` | shown | blocks count and record | one hash; offset 6 at `8b`; stored/original size 5; flags 0 at `8e`; Local at `8f` | Plain local descriptor |
| `90..109` | shown | relations count and records | IDs 0 through 9 | Required base definitions |
| `10a` | `00` | encryption count | 0 | No grants |
| `10b..112` | `00 00 00 00 00 00 01 08` | `dir_len` | 264 | Complete Directory length |
| `113..116` | `7c 05 e6 a2` | CRC | `0x7c05e6a2` | Stored CRC |

The Directory starts at `0x0f`; `dir_len = 264`; its CRC-covered range is
`0x0f..0x112`; CRC is `0x7c05e6a2` at `0x113..0x116`; `15 + 264 = 279`.
The decoded entry is ID 0, path `hello`, type Data, size 5, mode `0o644`.
Its sole block plaintext is `68 65 6c 6c 6f`; its BLAKE3 hash is
`ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f`; its
block key in the decrypted pair is SHAKE256(`hello`)[0..32],
`1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f22162`.

#### CV-PIECES-HELLO-766

| Item | Value |
| --- | --- |
| Purpose | Version 1.1 archive whose `Data` entry `hello` is sealed in two pieces, each granted to Bob |
| Required capability | Block encryption, encrypted block lists and encrypted recipient lists |
| Total length | 766 bytes |
| Expected result | Valid archive; with Bob's private key, read `hello` as ASCII `hello world`; without it, `hello` is listed with size 11 and is unavailable |

Bob's keys are the RFC 7748 test keys of the recipient-wrap vectors below; his private
key is `5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb`. For
piece `n` (1 for `hello`, 2 for ` world`), the vector uses these fixed inputs:
block nonce `n0` repeated 12 times, piece key byte `0n` repeated 32 times, piece
list nonce `1n` repeated 12 times, sender private key byte `3n` repeated 32
times, and grant nonce `4n` repeated 12 times. Block keys are convergent
(Section 5.3), and each grant record is `01 0n` followed by the piece key.

```text
0000: 50 49 54 48 01 01 42 4c 43 4b 10 10 10 10 10 10
0010: 10 10 10 10 10 10 8c 95 2e 75 aa 57 95 de 40 5c
0020: a4 29 e9 97 b9 ad 24 35 31 a8 cd 42 4c 43 4b 20
0030: 20 20 20 20 20 20 20 20 20 20 20 39 5a 8e 4a 74
0040: 68 8b bf 2a f6 2e 6d 11 92 a4 58 be e3 f4 5d 22
0050: cb 50 49 54 48 4f 53 44 52 00 01 00 05 68 65 6c
0060: 6c 6f 01 02 02 01 5d 11 11 11 11 11 11 11 11 11
0070: 11 11 11 b8 99 ae be f7 3e 3a 3b 8a 7e 15 a0 59
0080: 49 88 7f a7 0a c7 21 ef 07 ac f9 30 80 6e 69 a6
0090: 80 af 84 99 06 c0 11 e8 b7 d7 b7 99 d9 8a 6c 11
00a0: a5 67 59 d9 1f 7c 8f 31 22 ce 10 31 e6 5a 22 c6
00b0: 6f aa 66 d1 ae 1e a8 42 aa 3d cc 80 1f f4 59 83
00c0: 6e 2e ec 6e 02 5d 12 12 12 12 12 12 12 12 12 12
00d0: 12 12 a3 9a c0 1b 2b 0f 69 f5 be b3 61 ad af d5
00e0: 7e dc 34 f6 82 9a ff f4 d5 7f 2e db fb 4d bf 85
00f0: 7a ae 35 b6 7a 49 79 17 6a fa 8d 32 fa 15 27 a9
0100: 12 a2 80 7f fc d9 56 c6 6a c4 3d a7 26 94 8b cc
0110: 3e 35 cf b0 81 0d b8 fe fc cf 8d 7d 92 68 83 25
0120: fb 8c 59 00 00 0b a4 03 00 00 02 ea 8f 16 3d b3
0130: 86 82 92 5e 44 91 c5 e5 8d 4b b3 50 6e f8 c1 4e
0140: b7 8a 86 e9 08 c5 62 4a 67 20 0f 06 21 05 08 00
0150: cb 7a 20 2c 78 d1 fc 0b b6 98 a1 2b 4b 0c 95 13
0160: d2 72 08 36 76 e9 55 3b 38 40 e8 93 66 71 e8 5a
0170: 2b 22 06 08 00 0a 00 09 44 45 53 43 52 49 42 45
0180: 53 01 09 41 4e 4e 4f 54 41 54 45 53 02 0c 44 45
0190: 52 49 56 45 44 5f 46 52 4f 4d 03 09 53 4f 55 52
01a0: 43 45 5f 4f 46 04 10 50 52 45 56 49 4f 55 53 5f
01b0: 56 45 52 53 49 4f 4e 05 0c 4e 45 58 54 5f 56 45
01c0: 52 53 49 4f 4e 06 07 50 41 52 54 5f 4f 46 07 08
01d0: 43 4f 4e 54 41 49 4e 53 08 08 49 4e 50 55 54 5f
01e0: 54 4f 09 0b 4f 55 54 50 55 54 5f 46 52 4f 4d 02
01f0: 04 f5 f2 91 62 c3 1a 8d ef a1 8e 6e 74 22 24 ee
0200: 80 6f c1 71 8a 27 8b e8 59 ba 56 20 40 2b 8f 3a
0210: 01 de 9e db 7d 7b 7d c1 b4 d3 5b 61 c2 ec e4 35
0220: 37 3f 83 43 c8 5b 78 67 4d ad fc 7e 14 6f 88 2b
0230: 4f 00 3e 41 41 41 41 41 41 41 41 41 41 41 41 d5
0240: 91 81 e5 13 df d5 0d b5 8d 13 41 09 e1 a3 4b ba
0250: 61 34 a5 d0 ec 4d 12 7b 5b a8 a1 04 24 87 1f 0c
0260: 18 9f 61 0a 13 c4 0b 0f 44 4b ee 26 66 e0 9a 81
0270: b6 59 d9 22 54 73 45 1e ff fe 6b 36 db ca ef db
0280: f7 b1 89 5d e6 20 84 50 9a 7f 5b 58 bf 01 d0 64
0290: 18 01 de 9e db 7d 7b 7d c1 b4 d3 5b 61 c2 ec e4
02a0: 35 37 3f 83 43 c8 5b 78 67 4d ad fc 7e 14 6f 88
02b0: 2b 4f 00 3e 42 42 42 42 42 42 42 42 42 42 42 42
02c0: 33 72 35 6a b6 7a 39 7b 36 d7 c8 6e cf 5c 57 37
02d0: b2 7d 9d 62 f2 ff c3 31 bc 55 32 b9 66 1f fa 09
02e0: 9c 3d a9 dd 19 ee f5 a5 23 66 45 93 a2 10 aa 0c
02f0: ed c0 00 00 00 00 00 00 02 ad 3c f3 d9 39
```

| Offset range | Field | Meaning |
| --- | --- | --- |
| `00..05` | header | Pithos 1.1, `PITH 01 01` |
| `06..2a` | first block | `BLCK` and the 33-byte sealed `hello` |
| `2b..50` | second block | `BLCK` and the 34-byte sealed ` world` |
| `51..2fd` | Directory | One file record with tag `02` and pieces 1 and 2, two encrypted block descriptors, the ten standard relationships, and two encryption sections |

The Directory starts at `0x51` and `dir_len = 685`; `0x51 + 685 = 766`.

### B.3 Processing Vectors

| Vector ID | Stored bytes | `original_size` | Expected plaintext | BLAKE3 |
| --- | --- | --- | --- | --- |
| PV-ZSTD-HELLO | `28 b5 2f fd 04 48 29 00 00 68 65 6c 6c 6f a3 6d 9f 88` | 5 | `68 65 6c 6c 6f` | `ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f` |
| PV-ZSTD-TEXT | `28 b5 2f fd 04 58 c1 00 00 50 69 74 68 6f 73 20 5a 73 74 61 6e 64 61 72 64 20 76 65 63 74 6f 72 0a 41 f2 4f db` | 24 | ASCII `Pithos Zstandard vector\n` | `453c33f042159bc7dca06dcc08111d69c53fe167f329e084a85d950b70d84560` |

`PV-RECIPIENT-WRAP-01` is a known-answer test for Section 5.3, not a
production nonce choice. Alice private key
`77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a` and
Bob public key `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f`
produce raw X25519 shared secret
`4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742`.
With empty AAD, nonce `000102030405060708090a0b`, and decrypted
RecipientData `01 07` followed by bytes `00` through `1f` (one record,
file ID 7, 32-byte file key), the stored `nonce || ciphertext || tag` is:

```text
0000: 00 01 02 03 04 05 06 07 08 09 0a 0b e7 f1 ee 41
0010: ba 83 3f 09 8e d2 9f ec a3 de f9 c9 62 fc 8d c0
0020: cf 87 24 1b ff 58 9b 33 26 6a 0d fa f4 a5 eb a0
0030: 83 d4 2e 52 db 61 81 9d 09 53 81 70 aa e7
```

Successful decryption yields exactly the stated 34-byte RecipientData
plaintext. Fixed nonces are permitted here only as test inputs; writers use
random nonces as required by Section 5.3.

`PV-RECIPIENT-WRAP-11` is the version 1.1 known-answer test with the same
inputs. The sender public key is Alice's public key
`8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a` and the
recipient public key is Bob's. The derived wrapping key is
`16894ee78d378733e5148de641263d7503e3131e51ee894d60a56caa36c7caaa`, and the
stored `nonce || ciphertext || tag` is:

```text
0000: 00 01 02 03 04 05 06 07 08 09 0a 0b 25 3f 85 dd
0010: 25 c7 5f b6 81 1b 4d 7c 0d 8e 14 3f b3 fc de 6d
0020: 59 94 e4 8a 32 ca 15 61 6a 2f 26 f9 9b 3c 42 da
0030: 43 a0 94 bb cc 91 e1 c5 a6 53 62 9a d4 a1
```

`PV-UNIQUE-KEY-HELLO` is a version 1.1 known-answer test for one unique-key block
(Sections 5.2 and 5.3). The plaintext is ASCII `hello` and the flags byte is `18`
(no compression, encryption, unique key). The test inputs are block key bytes
`00` through `1f` and nonce bytes `a0` through `ab`; writers use random values.
The identity subkey is
`7523b18f1fdbfe99d23177669ef03ce0ca6925cfe372b8a26cc99804db196d6b`, and the
block hash is
`ca2bb927d0c0ac7196480fdf9c5101615bd8bc349663ffd9c3fef37228675a62`, not the
plain BLAKE3 digest of `hello`. The stored ChaCha20-Poly1305
`nonce || ciphertext || tag` is:

```text
0000: a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab 64 ce 14 33
0010: 22 bc 47 c9 e5 cc ec e2 dd 29 f5 e4 22 c2 e7 bc
0020: d2
```

`PV-AES-GCM-HELLO` is a version 1.1 known-answer test for one AES-256-GCM block
with a convergent key (Section 5.3). The plaintext is ASCII `hello` and the flags
byte is `28` (no compression, encryption, AES-256-GCM). The block key is
`SHAKE256("hello")`,
`1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f22162`, and the
derived payload key is
`7207849ab2398b3765b8c0ec4c43646d7e0ccdae28ed3d393f037a5a0febf245`. The block
hash is the plain BLAKE3 digest of `hello`. With the test nonce bytes `b0`
through `bb`, the stored `nonce || ciphertext || tag` is:

```text
0000: b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb 37 8d 6e 4e
0010: 73 d7 d5 ba 27 60 8f ef 88 ed 83 96 88 2e 54 d5
0020: cd
```

### B.4 Acceptance and Rejection Mutations

Each `AV-*` or `RV-*` vector is a mutation of the named canonical vector.
“Re-encode” means update all affected vector lengths, `dir_len`, and the CRC so
parsing reaches the cited semantic rule; it does not describe a separate
archive.

| Vector ID | Base and mutation | Clause | Required result |
| --- | --- | --- | --- |
| AV-ULEB-NONMINIMAL | CV-BASE-EMPTY-146: replace relations count at `11` `0a` with `8a 00`, then re-encode framing | 3.1 | Accept archive as the same empty archive |
| RV-ULEB | CV-BASE-EMPTY-146: replace relations count at `11` `0a` with the overflowing ten-byte `ff ff ff ff ff ff ff ff ff 02`, then re-encode framing | 3.1 | Reject archive |
| RV-FLAGS | CV-LOCAL-HELLO-279: replace flags at `8e` `00` with `10` and CRC `7c 05 e6 a2` with `7b d3 b1 03` | 4.2.3 | Reject archive |
| RV-UNKNOWN-TAG | CV-LOCAL-HELLO-279: replace Local tag at `8f` `00` with `02` and CRC with `86 cf 12 82` | 3.1, 4.2.4 | Reject archive |
| RV-DUPLICATES | CV-LOCAL-HELLO-279: append a second file record, block record, or relationship with the same ID, path, hash, or relationship ID; re-encode | 4.2.2, 4.3 | Reject archive |
| RV-PATH | CV-LOCAL-HELLO-279: replace path bytes `hello` at `1b..1f` with `/hell`, `hell/`, `a\\b`, `.`, or `C:` and adjust length if needed; re-encode | 4.3.3 | Reject archive |
| RV-SYMLINK | Re-encode the file as Symlink with nonempty block list, nonzero size, absent target, absolute target, or target escaping root | 4.4.3 | Reject archive |
| RV-FILETYPE | CV-LOCAL-HELLO-279: replace FileType at `20` `01` with `04` and CRC with `50 f4 25 95` | 4.4.1 | Reject archive |
| RV-PERMISSIONS | CV-LOCAL-HELLO-279: replace permissions at `66..67` `a4 03` with `80 20` (ULEB128 `0x1000`) and CRC with `9f 6a f3 6e` | 4.4.3 | Reject archive |
| RV-PARENT | CV-APPEND-EMPTY-28: change parent start at `a1` from `06` to `98` (self-link) and CRC `50 a2 dc 75` to `b7 34 ab f4`, or change parent length at `a2..a3` from `92 01` to `1c` and re-encode | 4.3 | Reject archive |
| RV-UNDERFLOW | CV-BASE-EMPTY-146: replace terminal `dir_len` at `8c..93` with `00 00 00 00 00 00 00 99` and CRC with `37 1d da 5a` | 4.3.1 | Reject archive |
| RV-TRAILING | CV-BASE-EMPTY-146: append `00` after `d2` | 4.3.1 | Reject archive |
| RV-CRC | CV-BASE-EMPTY-146: replace CRC byte at `97` `d2` with `d3` | 4.3 | Reject archive |
| RV-EXTENT | CV-LOCAL-HELLO-279: change descriptor offset at `8b` from `06` to `0f` and CRC to `62 3c 8b 49`, or add a second overlapping Local descriptor; re-encode | 4.2.5 | Reject archive |
| RV-SHORT-ENCRYPTED | CV-LOCAL-HELLO-279: set flags `8e` to `08`, retain stored size `05`, and CRC to `92 56 4e 52` | 4.2.5 | Reject archive |
| RV-EXTERNAL | Re-encode the hello descriptor as External (offset zero and location identifier). The archive is valid and listable; when an enabled resolver returns `BLCK ||` four payload bytes while `stored_size` is 5, its content read fails before output. Without external capability, content is unavailable. | 4.2.6, 8.2 | Content read fails before output / content unavailable |
| RV-CROSS-SIZE | CV-LOCAL-HELLO-279: append a new terminal Directory whose parent is its 264-byte Directory at start `0x0f`, repeats the existing hello hash with `original_size` 6, and has re-encoded parent, footer, and CRC | 4.3.2 | Reject archive |

### B.5 Validation Index

| Condition class | Authoritative section | Vector ID | Required result |
| --- | --- | --- | --- |
| Header, integer, tags, and flags | 3.1, 4.1, 4.2.3-4.2.4 | AV-ULEB-NONMINIMAL, RV-ULEB, RV-FLAGS, RV-UNKNOWN-TAG | Accept or reject archive as stated |
| Directory framing, CRC, and chain | 4.3, 4.3.1, 4.3.2 | CV-BASE-EMPTY-146, CV-APPEND-EMPTY-28, RV-PARENT, RV-UNDERFLOW, RV-TRAILING, RV-CRC, RV-CROSS-SIZE | Valid archive or reject archive as stated |
| Entries and paths | 4.3.3, 4.4.1, 4.4.3 | CV-LOCAL-HELLO-279, RV-DUPLICATES, RV-PATH, RV-SYMLINK, RV-FILETYPE, RV-PERMISSIONS | Valid archive or reject archive as stated |
| Block locations and extents | 4.2.2, 4.2.5, 4.2.6, 8.2 | CV-LOCAL-HELLO-279, RV-EXTENT, RV-SHORT-ENCRYPTED, RV-EXTERNAL | Valid archive, reject archive, content read fails before output, or content unavailable as stated |
| Content transforms and hashes | 5.2, 5.3, 5.4 | PV-ZSTD-HELLO, PV-ZSTD-TEXT, PV-RECIPIENT-WRAP-01, PV-RECIPIENT-WRAP-11, PV-UNIQUE-KEY-HELLO, PV-AES-GCM-HELLO | Decode/decrypt to stated output |
| Version 1.1 pieces and grants | 1.3, 4.4.2, 5.3 | CV-PIECES-HELLO-766, PV-RECIPIENT-WRAP-11 | Valid archive; content readable only with the granted key |
