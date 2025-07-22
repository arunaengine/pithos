# PITHOS File Format Specification

**Version:** 1.0
**Status:** Draft
**Date:** July 2025
**Purpose:** Next-generation file format for scientific data management, optimized for object storage with built-in deduplication, encryption, and metadata support

## 1. Introduction

This document specifies the PITHOS file format using the key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

PITHOS is an append-only archive format designed for efficient storage and sharing of scientific data. It combines content-defined deduplication, convergent encryption, and flexible metadata support in a privacy-preserving architecture optimized for object storage systems.

## 2. Core Design Principles

1. **Append-only architecture**: New data and metadata MUST be appended, never modifying existing content
2. **Content-addressed storage**: All blocks MUST be identified by Blake3 hashes enabling deduplication
3. **Privacy-preserving sharing**: Users MUST NOT be able to see who else has access to files
4. **Flexible metadata**: Metadata MUST be stored as regular files with special type markers
5. **Progressive enhancement**: Implementations MUST support the base format and MAY support optional features
6. **Emergency recovery**: Block markers MUST enable reconstruction even with corrupted directories
7. **Hierarchical organization**: Files use full paths from archive root; directories MUST be declared before their contents

## 3. File Structure

A PITHOS file MUST have the following structure:

```
[FileHeader]                    // REQUIRED: Format identifier and version
[Block Data...]                 // Zero or more data blocks with headers
[Directory + EncryptionSection] // REQUIRED: Can repeat (append-only)
[Block Data...]                 // Zero or more additional blocks
[Directory + EncryptionSection] // REQUIRED: File MUST end with directory
```

## 4. Core Data Structures

### 4.1 File Header

Every PITHOS file MUST begin with a FileHeader:

```rust
/// File header - appears once at the beginning of every PITHOS file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4],    // MUST be b"PITH"
    pub version: u16,      // Format version (e.g., 0x0100 for 1.0)
}
```

### 4.2 Block Storage

#### 4.2.1 Block Header

Each block MUST be preceded by a minimal header for emergency scanning:

```rust
/// Minimal block header - just for emergency scanning
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub marker: [u8; 4],   // MUST be b"BLCK"
}
```

#### 4.2.2 Block Index Entry

Complete block metadata MUST be stored in the directory:

```rust
/// Block index entry - single source of truth for block hashes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndexEntry {
    pub index: u64,              // Unique sequential identifier (varint encoded)
    pub hash: [u8; 32],          // Full Blake3 hash of original content
    pub offset: u64,             // Byte offset in file (varint encoded)
    pub stored_size: u64,        // Size as stored (compressed/encrypted) (varint)
    pub original_size: u64,      // Original uncompressed size (varint)
    pub flags: ProcessingFlags,  // Compression, encryption settings
    pub location: BlockLocation, // Where block data resides
}

/// Processing flags packed into single byte
bitflags::bitflags! {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProcessingFlags: u8 {
        // Bits 0-2: Compression level (0=none, 1-7=implementation-defined)
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

/// Block storage location
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockLocation {
    Local,                      // Block data at specified offset in this file
    External { url: String },   // URL to external storage
}
```

### 4.3 Directory Structure

The directory MUST contain all file and block metadata:

```rust
/// Directory - lists all files and blocks in this segment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub identifier: [u8; 8],                            // MUST be b"PITHOSDR"
    pub parent_directory_offset: Option<(u64, u64)>,    // Previous directory (start, len) (varint, backwards chain)
    pub files: Vec<FileEntry>,                          // Files in this segment
    pub blocks: Vec<BlockIndexEntry>,                   // Blocks in this segment
    pub relations: Vec<(u64, String)>                   // Relation idx, relationname / id
    pub encryption: Vec<EncryptionSection>,
    pub dir_len: u64,
    //pub encryption_section_offset: u64,               // Offset to encryption section (varint)
    pub crc32: u32,                                     // CRC32 of all preceding fields
}
```

### 4.4 File Representation

#### 4.4.1 File Types

Files MUST be classified by type:

```rust
/// File types (u8 representation for efficiency)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Data = 0,        // Regular data file (default)
    Metadata = 1,    // Metadata file (RO-Crate, DataCite, etc.)
    Directory = 2,   // Directory entry
    Symlink = 3,     // Symbolic link
    // Values 4-255 reserved for future use
}
```

#### 4.4.2 File Entry

Each file MUST be represented by a FileEntry:

```rust


pub enum BlockDataState {
    Encrypted(Vec<u8>), // Chacha + nonce
    Decrypted(Vec<(u64, [u8; 32])) // Index / Shake256 hash
}



/// File entry - describes a single file, directory, or symlink
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub file_id: u64,                    // Sequential unique identifier (varint)
    pub path: String,                    // Full path from archive root (UTF-8)
    pub file_type: FileType,             // Type of entry
    pub block_data: BlockDataState,
    pub created: u64,                    // Unix timestamp (seconds since epoch)
    pub modified: u64,                   // Unix timestamp (seconds since epoch)
    pub file_size: u64,                  // Total size in bytes (varint)
    pub permissions: u32,                // Unix-style permissions
    // TODO: Uid / guid ?
    pub references: Vec<Reference>,      // Data->Metadata references only
    pub symlink_target: Option<String>,  // Target path for symlinks
}
```

#### 4.4.3 File References

References MUST be one-way from metadata to data files:

```rust
/// Simplified reference structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub target_file_id: u64,    // Target file ID (varint)
    pub relationship: u64,      // Relationship type (varint)
}
```

**Standard relationship types:**
- `DESCRIBES = 0`: Metadata describing target
- `ANNOTATES = 1`: Additional annotations
- `DERIVED_FROM = 2`: Derived from target
- `SOURCE_OF = 3`: Source of target
- `PREVIOUS_VERSION = 4`: Previous version
- `NEXT_VERSION = 5`: Next version
- `PART_OF = 6`: Part of collection
- `CONTAINS = 7`: Contains target
- `INPUT_TO = 8`: Input to process
- `OUTPUT_FROM = 9`: Output from process
- Custom relationships start at `1000`

### 4.5 Encryption Section

Encryption sections MUST follow each directory:

```rust
/// Encryption section - privacy-preserving access control
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionSection {
    pub sender_public_key: [u8; 32],           // X25519 public key
    pub recipients: Vec<RecipientSection>,     // Per-recipient data
}

pub enum RecipientData {
    Encrypted(Vec<u8>), // Chacha + nonce
    Decrypted(Vec<(u64, [u8; 32])) // Fileindex / Shake256 hash
}


/// Per-recipient encrypted data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSection {
    pub recipient_public_key: [u8; 32],  // Recipient's X25519 public key
    pub recipient_data: RecipientData,         // Encrypted FileKeyEntry list
}
```

### 4.6 Error Types

```rust
#[derive(Debug)]
pub enum FormatError {
    // Format errors
    InvalidMagic,
    UnsupportedVersion(u16),
    UnknownFileType(u8),
    InvalidUtf8,
    VarintOverflow,
    VarintIncomplete,
    StringTruncated,

    // Validation errors
    InvalidBlockIndex(u64),
    FileNotFound,
    DataFileWithReferences,
    NonMetadataFileWithReferences,
    SymlinkWithoutTarget,
    NonSymlinkWithTarget,
    InvalidBlocksForFileType,
    MissingBlocks,
    InvalidOperation,

    // Path errors
    EmptyPath,
    PathTraversal,
    AbsolutePathNotAllowed,
    InvalidSymlinkTarget,
    MissingParentDirectory {
        path: String,
        parent: String,
        index: usize,
    },

    // IO errors
    IoError(std::io::Error),
}
```

## 5. Encoding Specifications

### 5.1 Integer Encoding

All integer fields marked as "varint" MUST use unsigned LEB128 encoding.

### 5.2 String Encoding

All strings MUST be encoded as UTF-8 with a varint length prefix.

### 5.3 Byte Order

All multi-byte values not using varint encoding MUST use big-endian byte order.

### 5.4 Directory Entry Ordering Requirements

**CRITICAL**: Directory entries MUST follow strict ordering rules to ensure proper extraction:

1. **Parent Before Child Rule**: A directory entry MUST appear before any entries for files or subdirectories within it
2. **Path Format**: All paths MUST be relative (no leading `/`) and use forward slashes as separators
3. **Root Directory**: The root directory is implicit and MUST NOT have an entry
4. **Validation**: Implementations MUST validate ordering during both writing and reading

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

**Example of INVALID ordering:**
```
data/raw/file1.csv       (ERROR: parent "data/raw/" not yet declared)
data/raw/                (too late - file already referenced this directory)
data/                    (too late - subdirectory already referenced this)
```

## 6. Content Processing

### 6.1 Content-Defined Chunking

Implementations SHOULD use content-defined chunking with recommended parameters:
- **min_size**: 64 KB
- **avg_size**: 128 KB
- **max_size**: 512 KB
- **window_size**: 48 bytes

### 6.2 Block Hashing

All block hashes MUST use Blake3.

### 6.3 Convergent Encryption

Content keys MUST be derived deterministically using SHAKE256.

### 6.4 Compression

Implementations SHOULD support:
- Level 0: No compression
- Levels 1-3: Fast compression (e.g., Zstd levels 1-3)
- Levels 4-6: Balanced compression (e.g., Zstd levels 4-9)
- Level 7: Maximum compression (e.g., Zstd level 19+)

## 7. Operations Overview

### 7.1 Reading Operations

1. Read and validate file header
2. Find last directory by scanning from end
3. Validate directory ordering
4. Build block index
5. Extract files by reading referenced blocks

### 7.2 Writing Operations

1. Write file header
2. Process files in correct directory order
3. Chunk content using content-defined chunking
4. Deduplicate blocks by hash
5. Write directory and encryption sections
6. Validate complete structure

### 7.3 Directory Tree Operations

When archiving directory trees:
1. Process directories before their contents
2. Maintain relative path structure
3. Preserve file metadata (permissions, timestamps)
4. Handle symlinks appropriately per platform

## 8. Security Considerations

1. Implementations MUST verify block hashes before decompression/decryption
2. CRC32 values MUST be validated for directories and encryption sections
3. Convergent encryption reveals when identical files exist (accepted trade-off)
4. External block URLs MUST use HTTPS in production environments
5. Path traversal attacks MUST be prevented through validation

## 9. Implementation Requirements

### 9.1 Mandatory Features

Implementations MUST support:
- Reading and writing base format (version 1.0)
- Blake3 hashing
- Varint encoding/decoding
- CRC32 calculation
- UTF-8 string handling
- All four file types (Data, Metadata, Directory, Symlink)
- Directory ordering validation (parents before children)
- Path format validation (relative paths only)

### 9.2 Optional Features

Implementations MAY support:
- Compression (levels 1-7)
- Encryption (ChaCha20-Poly1305)
- External block storage
- Content-defined chunking

### 9.3 Platform-Specific Considerations

#### Symlinks
- Unix systems: Create proper symbolic links
- Windows: Handle symlinks according to platform capabilities

#### Permissions
- Unix: Preserve full permission bits
- Windows: Map Unix permissions to Windows ACLs where possible

#### Path Separators
- Archives use forward slashes (`/`) internally
- Convert to platform-appropriate separators on extraction

## 10. Future Extensions

The format reserves space for future extensions:
- FileType values 4-255
- ProcessingFlags bits 4-7
- Custom relationship types starting at 1000

Extensions MUST maintain backwards compatibility for reading.

## 11. Constants and Identifiers

### 11.1 Magic Values

- File Header: `b"PITH"`
- Block Header: `b"BLCK"`
- Directory: `b"PITHOSDR"`
- Encryption Section: `b"PITHOSEN"`

### 11.2 Version Numbers

- Version 1.0: `0x0100`

### 11.3 Default Values

- Current timestamp: Unix seconds since epoch
- Default file permissions: `0o644`
- Default directory permissions: `0o755`
- Default symlink permissions: `0o777`
