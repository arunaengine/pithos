# Pithos File Format Specification

**Version:** 1.0
**Status:** Draft
**Date:** July 2026
**Purpose:** Next-generation file format for scientific data management, optimized for object storage with built-in deduplication, encryption, and metadata support

## 1. Introduction

This document specifies the Pithos file format using the key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

Pithos is an append-only archive format designed for efficient storage and sharing of scientific data. It combines content-defined deduplication, convergent encryption, and flexible metadata support in a privacy-preserving architecture optimized for object storage systems.

The code examples in this document are only intended to illustrate the architecture. Optimized implementations of the individual structures may of course differ.

## 2. Core Design Principles

1. **Append-only architecture**: New data and metadata MUST be appended, never modifying existing content
2. **Content-addressed storage**: All blocks MUST be identified by Blake3 hashes enabling deduplication
3. **Privacy-preserving sharing**: Users MUST NOT be able to see who else has access to files
4. **Flexible metadata**: Metadata MUST be stored as regular files with special type markers
5. **Progressive enhancement**: Implementations MUST support the base format and MAY support optional features
6. **Limited recovery**: Recovery tools MAY treat block markers as untrusted candidates; directories provide block metadata
7. **Hierarchical organization**: Files use full paths from archive root; directories MUST be declared before their contents

## 3. File Structure and Encoding

A Pithos file MUST have the following structure:

```
[FileHeader]      // REQUIRED: Format identifier and version
[Block Data...]   // Zero or more data blocks with headers
[Directory]       // REQUIRED: Can repeat (append-only)
[Block Data...]   // Zero or more additional blocks
[Directory]       // REQUIRED: File MUST end with directory
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

#### 4.2.2 Block Index Entry

The hash-keyed block descriptor describes one block stored or referenced by a directory.

```rust
/// Block descriptor body; its hash is the key in Directory::blocks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndexEntry {
    pub offset: u64,             // Byte offset in file (varint encoded)
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
| `block_hash` | Exactly 32 bytes: BLAKE3 hash of the original block content |
| `offset` | ULEB128 `u64` |
| `stored_size` | ULEB128 `u64` |
| `original_size` | ULEB128 `u64` |
| `flags` | One ProcessingFlags byte: bits 0-2 compression level, bit 3 encryption enabled, bits 4-7 zero |
| `location` | One tag byte: `00` local, or `01` followed by a URL string for external |

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
    Local,                      // Block data at specified offset in this file
    External { url: String },   // URL to external storage
}
```

**Encoded Form**

| Tag | Variant | Bytes after the tag |
| --- | --- | --- |
| `00` | `Local` | None |
| `01` | `External` | `url` as a string |

Readers MUST reject unknown tags. A local block's offset and size describe its
location in this file; the block-boundary rules are specified separately.

#### 4.2.5 Local Block Boundaries and Recovery

A local block is `BLCK || stored_payload`. Its `offset` is the zero-based file
offset of the first byte of `BLCK`; `stored_size` counts only `stored_payload`.
The marker occupies bytes `offset` through `offset + 3`. The payload starts at
`offset + 4` and occupies exactly `stored_size` bytes; when nonempty, its last
byte is `offset + 4 + stored_size - 1`.

Readers locate local blocks from directory descriptors and MUST use checked
arithmetic for every range. Normal reading MUST NOT search payload bytes for
`BLCK`. Recovery tools MAY treat `BLCK` as an untrusted candidate only: the
marker alone provides no length, flags, or identity.

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
    pub blocks: Vec<([u8; 32], BlockIndexEntry)>,       // Block hash and body
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
selected chain MUST have exactly one root directory, whose parent tag is `00`.
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
Readers MUST validate the marker, embedded length, CRC, and exact parser consumption for the terminal directory before decrypting, merging, or otherwise using its metadata. Invalid directories MUST be rejected.

#### 4.3.1 Terminal Directory Lookup

To locate the terminal directory during normal reading:

1. Read the final 12 file bytes as `dir_len:u64be || crc32:u32be`.
2. Compute `directory_start = file_length - dir_len` using checked subtraction.
3. Require `dir_len` to be at least the smallest directory allowed by the finalized 1.0 encoding. The root stores ten standard relationships, so the 0.8 25-byte empty-directory minimum does not apply.
4. Parse the directory at `directory_start` and require it to end exactly at the end of the file.
5. Validate the marker, embedded length, CRC, and exact byte consumption before using metadata.

Normal reading MUST reject trailing bytes, truncation, underflow, a false marker, and a torn final append. It MUST NOT fall back to an older directory. Salvage is a separate mode; if it locates an older directory, it MUST label the result incomplete.

#### 4.3.2 Append Chains

Each Directory contains the entries introduced by its segment. To construct the
effective archive, readers merge the selected directory chain from its oldest
directory to its newest directory. An append adds file entries, block
descriptors, relationship definitions, and recipient grants. Version 1.0 has
no deletion, replacement, or tombstone.

File IDs and paths MUST be unique across the chain. Writers assign file ID 0
to the first file and assign each later file ID as the current maximum ID plus
1. Readers MUST accept unused file-ID gaps. A rename adds a file record with a
new file ID and path; the old record remains in the effective archive.

A repeated block hash in one directory is invalid. Across directories, a block
hash MAY reappear only when its `original_size` is the same. The descriptor in
the oldest directory remains the effective descriptor. Exact repeated
relationship definitions are allowed; conflicting definitions of one
relationship ID are invalid. Exact repeated recipient grants are allowed;
conflicting grants for the same sender public key and recipient public key are
invalid.

The root directory MUST store these ten standard relationship definitions in its
`relations` vector, in ascending relationship-ID order: `0 DESCRIBES`,
`1 ANNOTATES`, `2 DERIVED_FROM`, `3 SOURCE_OF`, `4 PREVIOUS_VERSION`,
`5 NEXT_VERSION`, `6 PART_OF`, `7 CONTAINS`, `8 INPUT_TO`, and
`9 OUTPUT_FROM`. Appended directories inherit these definitions and MAY repeat
one only when its relationship ID and stored name match exactly.

For example, three segments with parent order `root <- append-1 <- append-2`
merge as follows:

| Segment | Entries introduced | Final visible entries after `append-2` |
| --- | --- | --- |
| `root` | file ID 0, `data/a`; block `H` with `original_size` 4; the ten standard relationships | file ID 0, `data/a`; file ID 1, `data/b`; file ID 2, `results/a`; block `H` from `root`; block `J` |
| `append-1` | file ID 1, `data/b`; exact repeat of block `H` with `original_size` 4; recipient grant `G` | |
| `append-2` | file ID 2, `results/a`; block `J`; exact repeat of recipient grant `G` | |

#### 4.3.3 Directory Entry and Path Ordering

Directory entries MUST follow these ordering and path rules:

1. A directory entry MUST appear before entries for files or subdirectories within it.
2. Paths MUST be relative, have no leading `/`, and use forward slashes as separators.
3. The root directory is implicit and MUST NOT have an entry.
4. Readers and writers MUST validate this ordering.

**Example of valid ordering:**
```
data/                    (directory)
data/raw/                (directory - parent "data/" already exists)
data/raw/file1.csv       (file - parent "data/raw/" already exists)
data/processed/          (directory - parent "data/" already exists)
data/processed/file2.csv (file - parent "data/processed/" already exists)
docs/                    (directory)
docs/README.md           (file - parent "docs/" already exists)
data/raw/file1_v2.csv    (file - parent "data/raw/" already exists) -> Newer version of file1.csv
```

**Example of invalid ordering:**
```
data/raw/file1.csv       (ERROR: parent "data/raw/" not yet declared)
data/raw/                (too late - file already referenced this directory)
data/                    (too late - subdirectory already referenced this)
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

Readers MUST reject unknown tags. The block hash is the only block identity in a
decrypted block-list entry. A decrypted block list is a ULEB128 count followed
by that many `block_hash[32] || block_key[32]` pairs. A repeated block hash is
valid only when it has the same block key; readers MUST reject a conflicting
duplicate hash and block key.

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

**Standard relationship types:**

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

For example, a reference from `normalized.csv` to `raw.csv` with
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
/// Encryption section - privacy-preserving access control
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

### 4.6 Error Types

```rust
#[derive(Debug)]
pub enum PithosError {
    Io(#[from] io::Error),
    Conversion(String),
    SystemTimeError(#[from] SystemTimeError),
    StripPrefix(#[from] std::path::StripPrefixError),
    WalkDir(#[from] walkdir::Error),
    FastCDC(#[from] fastcdc::v2020::Error),
    Serialization(#[from] SerializationError),
    Deserialization(#[from] DeserializationError), 
    Crypt(#[from] CryptError),
    Crypt4GH(#[from] Crypt4GHError),
    Cipher(#[from] ChaChaPoly1305Error),
    Compression(#[from] ZstdError),
    UnsupportedFeature(String),
    InvalidBlockDataState(String),
    BlockHashNotFound([u8; 32]),
    FileNotFound(String),
    DuplicateFileId(String),
    RelationIdOccupied(u64),
    PathOccupied(String),
    InvalidFileType(String),
    NoMatchingRecipient,
    InvalidRecipientDataState(String),
    Other(String),
}
```

## 5. Content Processing

### 5.1 Content-Defined Chunking

Implementations SHOULD use content-defined chunking with recommended parameters:
- **min_size**: 64 KB
- **avg_size**: 128 KB
- **max_size**: 512 KB
- **window_size**: 48 bytes

### 5.2 Block Hashing

Each block identifier MUST be the full 32-byte default unkeyed BLAKE3 digest of the exact
plaintext chunk before compression or encryption. Readers MUST retrieve the stored block,
authenticate and decrypt it when encrypted, decompress it when compressed using the recorded
original size as the output bound, require the resulting plaintext length to equal the recorded
original size, compute the complete plaintext digest, and compare it with the block identifier
before releasing any output derived from that block.

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

An implementation MUST use a fresh nonce for every value encrypted under a
given key. It MUST authenticate and decrypt an encrypted value successfully
before using its plaintext or releasing output derived from it.

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

The current writer mapping is optional implementation guidance: `1` to Zstandard
level `1`, `2` to `4`, `3` to `8`, `4` to `11`, `5` to `15`, `6` to `18`, and
`7` to `22`. A writer MAY abandon unhelpful compression and store the plaintext
payload instead, but MUST then write compression value `0`. For example, a
writer MAY use a 4096-byte sample and a 0.85 compression-ratio threshold to
decide whether compression is helpful; this heuristic is not a compatibility
rule.

Conforming encoders need not produce byte-identical Zstandard output. A future
conformance appendix MUST provide decode-direction vectors containing stored
compressed bytes, `original_size`, the expected plaintext, and its expected
32-byte BLAKE3 hash. These vectors MUST decode to the expected plaintext with
different supported Zstandard versions.

## 6. Operations Overview

### 6.1 Reading Operations

1. Read and validate file header
2. Locate and validate the terminal directory using the direct lookup in Section 4.3.1
3. Validate directory ordering
4. Build block index
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

1. Implementations MUST verify the complete plaintext block size and hash after authenticated
   decryption and decompression, and before releasing output derived from the block
2. Directory CRC32 values MUST be validated
3. Convergent encryption reveals when identical files exist (accepted trade-off)
4. External block URLs MUST use HTTPS in production environments
5. Path traversal attacks MUST be prevented through validation

## 8. Implementation Requirements

### 8.1 Base Reader and Writer

A base reader supports the version 1.0 structure, including its required
validation, and can read local blocks whose ProcessingFlags have compression
value `0` and encryption bit `0`. It supports decrypted BlockDataState lists.
A base writer can create an archive containing only such local blocks and an
empty Directory `encryption` vector.

The following table defines the optional capabilities. A reader discovers a
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
and an empty Directory `encryption` vector. This differs from the current 0.8
writer, which requires encrypted file block lists and encrypted recipient
lists, although it can disable block-payload encryption.

### 8.3 Platform-Specific Considerations

#### Symlinks
- Unix systems: Create proper symbolic links
- Windows: Handle symlinks according to platform capabilities

#### Permissions
- Unix: Preserve full permission bits
- Windows: Map Unix permissions to Windows ACLs where possible

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
