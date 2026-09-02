# Pithos File Format Specification

**Version:** 1.0
**Status:** Draft
**Date:** July 2026
**Purpose:** Next-generation file format for scientific data management, optimized for object storage with built-in deduplication, encryption, and metadata support

## 1. Introduction

This document specifies the Pithos file format using the key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

Pithos is an append-only archive format designed for efficient storage and sharing of scientific data. It combines content-defined deduplication, convergent encryption, and flexible metadata support optimized for object storage systems.

**Illustrative data model.** Rust declarations in this document illustrate the
data model only; implementations may use different declarations. Normative
prose and encoded-form tables govern conformance and the bytes on disk.

This document defines Pithos 1.0. Where a current 0.8 implementation differs,
this document governs.

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

## 2. Core Design Principles

1. **Append-only architecture**: New data and metadata MUST be appended, never modifying existing content
2. **Content-addressed storage**: All blocks MUST be identified by Blake3 hashes enabling deduplication
3. **Encrypted recipient grants**: Encrypted recipient data protects its file-key
   grants from parties that cannot decrypt it
4. **Flexible metadata**: Metadata MUST be stored as regular files with special type markers
5. **Progressive enhancement**: Implementations MUST support the base format and MAY support optional features
6. **Limited recovery**: Recovery tools MAY treat block markers as untrusted candidates; directories provide block metadata
7. **Hierarchical organization**: Files use full paths from the archive root path; directories MUST be declared before their contents

## 3. File Structure and Encoding

A Pithos file MUST have the following structure:

```
+-- base segment --------------------+ +-- appended terminal segment -------------------+
| [FileHeader][Base Blocks][Base Dir] | | [Appended Blocks][Terminal Dir ... dir_len || crc32] | EOF
+-------------------------------------+ +-----------------------------------------------------+
                                      ^                                      |
                                      +-- parent (start, len) <-------------+
                                                                    `dir_len || crc32` = final 12 bytes
```

Each segment ends immediately after its Directory. Encryption sections, when
present, are items in that Directory's `encryption` vector.

### 3.1 Common Encoding Rules

The following rules define the bytes stored in the file for every structure in
Section 4:

1. Fixed byte arrays are stored exactly as shown, with no length prefix.
2. `u16`, `u32`, and `u64` fields explicitly marked fixed-width are big-endian.
3. Other unsigned integers use the shortest valid ULEB128 form. Readers MUST
   reject truncated, overlong, and overflowing encodings.
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
    pub version: u16,      // fixed-width big-endian, 0x0100 for 1.0
}
```

**Encoded Form**

| Field | Bytes stored in the file |
| --- | --- |
| `magic` | Exactly 4 bytes: ASCII `PITH` |
| `version` | Fixed-width `u16be` |

Readers MUST reject a header whose magic is not `PITH` or whose version is not
`0x0100`. The encoded form is exactly six bytes: `PITH 01 00`.

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
| `flags` | One ProcessingFlags byte: bits 0-2 compression level, bit 3 encryption enabled, bits 4-7 zero |
| `location` | One tag byte: `00` local, or `01` followed by an external location identifier string |

Readers MUST reject duplicate block hashes in one directory and MUST use the
32-byte hash as the block's only identity.

#### 4.2.3 Processing Flags

ProcessingFlags records the compression level and whether a block is encrypted.

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

        // Bits 4-7: Reserved for future use (MUST be zero)
    }
}
```

**Encoded Form**

| Bits | Meaning |
| --- | --- |
| 0-2 | Compression: `0` means the stored payload is not compressed; `1` through `7` each mean the stored payload is one standard Zstandard frame |
| 3 | Encryption enabled: `0` is disabled; `1` is enabled |
| 4-7 | Reserved; all bits MUST be zero |

ProcessingFlags is stored as exactly one byte. Readers MUST reject a value with
any reserved bit set.

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
descriptors, relationship definitions, and recipient grants. Version 1.0 has
no deletion, replacement, or tombstone.

File IDs and paths MUST be unique across the selected chain. Writers assign file ID 0
to the first file and assign each later file ID as the current maximum ID plus
1. Readers MUST accept unused file-ID gaps. A rename adds a file record with a
new file ID and path; the old record remains in the effective archive.

A repeated block hash in one Directory is invalid. Across Directories in the
selected chain, a block hash MAY reappear only when its `original_size` is the
same. The descriptor in the oldest Directory in the selected chain that
contains that hash remains the effective descriptor. Exact repeated
relationship definitions are allowed; conflicting definitions of one
relationship ID are invalid. Exact repeated recipient grants are allowed;
conflicting grants for the same sender public key and recipient public key are
invalid.

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

BlockDataState stores either encrypted file block data or a decrypted block list.

```rust
pub enum BlockDataState {
    Encrypted(Vec<u8>),             // nonce || ciphertext || tag
    Decrypted(Vec<([u8; 32], [u8; 32])>), // Block hash and block key
}
```

**Encoded Form**

| Tag | Variant | Bytes after the tag |
| --- | --- | --- |
| `00` | `Encrypted` | Vector of bytes |
| `01` | `Decrypted` | Vector of tuples, each `block_hash[32] || block_key[32]` |

Readers MUST reject unknown tags. A decrypted block list is a ULEB128 count
followed by that many `block_hash[32] || block_key[32]` pairs. Block-list
identity, reuse, and validation are defined in Section 5.2.

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
| `block_data` | Tag `00` and byte vector, or tag `01` and vector of `block_hash[32] || block_key[32]` tuples |
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
| `Data` | Either state is permitted | MUST equal the sum of referenced effective descriptors' `original_size` values when the block list is available | MUST be absent (`00`) |
| `Metadata` | Either state is permitted | MUST equal the sum of referenced effective descriptors' `original_size` values when the block list is available | MUST be absent (`00`) |
| `Symlink` | MUST be `Decrypted` with an empty list | MUST be `0` | MUST be present (`01`) |

Readers MUST reject a combination that violates this table. For encrypted block
lists, the content-size validation for `Data` and `Metadata` occurs once the
block list is available; until then, the content is unavailable as specified in
Section 8.2.

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
reject a conflicting duplicate file ID and file key.

## 5. Content Processing

### 5.1 Content-Defined Chunking

Writers MAY use content-defined chunking. Chunking parameters are writer guidance,
not a compatibility requirement; see Appendix A.

### 5.2 Block Hashing

The block hash is the full 32-byte default unkeyed BLAKE3 digest of the exact
plaintext chunk before compression or encryption. It is a block's only
identity. The Directory `blocks` vector is keyed by block hash, and each file's
block list is an ordered sequence of `(block_hash, block_key)` pairs. That order
reconstructs the file.

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
original size, compute the complete plaintext digest, and compare it with the
block hash before releasing any output derived from that block.

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

### 5.3 Convergent Encryption

Encryption is optional. An implementation that supports encryption MUST use
X25519, SHAKE256, and ChaCha20-Poly1305 as specified here.

All encryption keys are 32 bytes. ChaCha20-Poly1305 uses a 12-byte nonce and
produces a 16-byte authentication tag. Every encrypted value is stored as
`nonce || ciphertext || tag`; the nonce is part of the stored byte vector. The
additional authenticated data (AAD) is empty.

The block key is the first 32 output bytes of `SHAKE256(plaintext)`, where
`plaintext` is the exact block plaintext before compression or encryption. No
label or length prefix is included. A block payload with encryption enabled is
encrypted with its block key.

A file key is 32 random bytes. It encrypts the decrypted block list for a file.
For each recipient record, the recipient wrapping key is the raw 32-byte X25519
shared secret between the sender private key and recipient public key. That
shared secret is used directly as the ChaCha20-Poly1305 key to encrypt the
decrypted recipient list; no intermediate KDF is used. Implementations MUST
reject non-contributory X25519 public keys.

An implementation MUST generate every nonce independently and uniformly at
random with a cryptographically secure random number generator and MUST NOT
deliberately reuse a nonce under the same key. It MUST authenticate and decrypt
an encrypted value successfully before using its plaintext or releasing output
derived from it.

Version 1.0 deliberately has no SHAKE256 label, intermediate X25519 KDF, or
AAD. A redesign of any of these inputs requires a new format version.

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
will provide decode-direction vectors containing stored compressed bytes,
`original_size`, the expected plaintext, and its expected 32-byte BLAKE3 hash.
Those vectors MUST decode to the expected plaintext with different supported
Zstandard versions.

## 6. Operations Overview

### 6.1 Reading Operations

1. Read and validate file header
2. Locate and validate the terminal Directory using the direct lookup in Section 4.3.1
3. Validate directory ordering
4. Build the effective block-descriptor mapping
5. Extract files by reading referenced blocks

### 6.2 Writing Operations

1. Write file header
2. Process files in correct directory order
3. Chunk content using content-defined chunking
4. Deduplicate blocks by hash
5. Write a directory, including its encryption sections when present
6. Validate complete structure

### 6.3 Directory Tree Operations

When archiving directory trees:
1. Process directories before their contents
2. Maintain relative path structure
3. Preserve file metadata (permissions, timestamps)
4. Handle symlinks appropriately per platform

## 7. Security Considerations

Directory CRC-32 detects accidental corruption of the serialized Directory bytes
it covers; it is not authentication. Pithos 1.0 provides no archive-wide origin
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

Recipient wrapping uses a raw static X25519 shared secret directly as its AEAD
key, with no KDF, label, or AAD. Consequently, the construction has no domain
separation, and each static sender-recipient key pair has one nonce-collision
scope across all archives that use it; uniformly random CSPRNG nonces reduce but
cannot eliminate collision risk. The plaintext-derived Directory block hash
exposes block equality, and equal plaintext also derives the same convergent
block key.

Readers must verify each block as required by Section 5.2 before releasing its
output. Networked external resolution can expose a caller to unsafe targets and
resource exhaustion; Section 4.2.6 defines the required resolver safeguards.
Extraction safety requires that archive paths are created without traversing
archive-created or pre-existing symlinks, existing entries are not clobbered by
default, and special permission bits are not applied without explicit caller
policy; Sections 8.3 and 4.4.3 define these requirements.

## 8. Implementation Requirements

### 8.1 Base Reader and Writer

A base reader supports the version 1.0 structure, including its required
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
| Encrypted block lists | BlockDataState tag is `00` (`Encrypted`) |
| Encrypted recipient lists | RecipientData tag is `00` (`Encrypted`) |
| External storage | BlockLocation tag is `01` (`External`) |

Compression, block encryption, encrypted block lists, encrypted recipient
lists, and external storage are optional capabilities. An implementation that
supports an optional capability MUST process it according to its definition in
this specification.

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
| External: BlockLocation `External` | Listed | Readable only with external-storage capability and every capability required by its flags and data states; otherwise unavailable |
| Combined: compression and encryption, at either location | Listed | Readable only when every indicated capability is supported; otherwise unavailable |

For the table, an encrypted BlockDataState requires encrypted-block-list
capability, and an encrypted RecipientData required to obtain its file key
requires encrypted-recipient-list capability. A content read that needs either
unsupported list form is unavailable even when its block flags themselves are
otherwise supported.

Readers MUST reject an unsupported header version and any unknown tag rather
than list the archive, because the structure of such input is not known.

Pithos 1.0 intentionally permits decrypted block and recipient list variants
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
- FileType values 4-255
- ProcessingFlags bits 4-7
- Custom relationship types starting at 1000

Extensions MUST maintain backwards compatibility for reading.

## 10. Constants and Identifiers

### 10.1 Magic Values

- File Header: `b"PITH"`
- Block Header: `b"BLCK"`
- Directory: `b"PITHOSDR"`

### 10.2 Version Numbers

- Version 1.0: `0x0100`

### 10.3 Default Values

- Current timestamp: Unix seconds since epoch
- Default file permissions: `0o644`
- Default directory permissions: `0o755`
- Default symlink permissions: `0o777`

## Appendix A. Writer Guidance (Non-Normative)

This appendix suggests writer choices only. It does not define archive
conformance or reader behavior.

Recommended content-defined chunking parameters are a 64 KB minimum, 128 KB
average, 512 KB maximum, and 48-byte window.

**Recommended compression mapping:** a writer may map ProcessingFlags values
`1` through `7` to Zstandard levels `1`, `4`, `8`, `11`, `15`, `18`, and `22`,
respectively. A writer may sample 4096 bytes and require a 0.85 compression
ratio before compressing. These suggestions are non-normative.

## Appendix B. Conformance Examples and Vectors

Complete canonical and mutation vectors are intentionally not included in this
draft revision. They will be added here without duplicating the normative rules
in the main text.

**Validation index:** vector IDs are reserved for the forthcoming vector set.
Each completed vector will cite its authoritative rule and required result.

| Condition class | Authoritative section | Vector ID | Required result |
| --- | --- | --- | --- |
| Header and common encoding | Sections 3.1, 4.1 | Reserved | Reject archive |
| Directory framing and chain | Sections 4.3.1, 4.3.2 | Reserved | Reject archive |
| Entry paths and FileEntry combinations | Sections 4.3.3, 4.4.3 | Reserved | Reject archive |
| Block descriptors and local extents | Sections 4.2.2, 4.2.5 | Reserved | Reject archive |
| Content transforms and hashes | Sections 5.2, 5.3, 5.4 | Reserved | Reject archive |
| Unsupported optional capability | Section 8.2 | Reserved | Content unavailable |
