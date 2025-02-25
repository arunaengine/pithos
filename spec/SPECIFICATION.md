# The Pithos File Format Specification

This document contains the formal description for the Pithos (`.pto`) file format. Pithos is a modern file format that enables secure compression and encryption while maintaining efficient indexing for large multi-gigabyte files. It is specifically optimized for use with object storage solutions like S3, Azure Blob Storage, and similar cloud storage systems.

## Goals

* **Built-in encryption** - Secures data at rest without requiring additional application layers, providing native protection for sensitive information through dual-hash convergent encryption
* **Portable format** - Ensures consistent operation across different operating systems, hardware architectures, and programming environments
* **Included multi-specification metadata** - Supports comprehensive metadata structures adhering to multiple industry standards for improved interoperability
* **Built-in compression** - Natively integrates data compression within the format, reducing storage requirements and transmission times without external tools, uses "smart" compression that automatically decides if compression is necessary
* **Configurable Random IO** - Supports efficient retrieval of specific data segments without reading entire files, enabling targeted access operations
* **Optimized for Object storage** - Designed specifically for modern object storage systems, with considerations for cloud environments, distributed storage paradigms, and scalable data management

## Non-goals

* **Universal backward compatibility** - The format prioritizes modern functionality over compatibility with legacy systems and older file format versions
* **Minimal file size for small data** - Not optimized for extremely small files where the metadata overhead may be proportionally significant
* **Real-time streaming** - Not designed for continuous data streaming applications requiring minimal latency

## 1. Format Overview

Pithos uses a container-based approach where files, directories, and metadata are stored as objects within a unified structure. The format supports dynamic block sizing, built-in encryption and compression, and optimized random I/O operations.

### 1.1 File Structure

A Pithos file consists of the following components:

```
+-----------------------------------+
| Magic Number (8 bytes)            |
+-----------------------------------+
| Format Version (2 bytes)          |
+-----------------------------------+
| Block Data                        |
|   +-------------------------------+
|   | Block 1 (Data/Metadata)       |
|   +-------------------------------+
|   | Block 2 (Data/Metadata)       |
|   +-------------------------------+
|   | ...                           |
|   +-------------------------------+
|   | Block N (Data/Metadata)       |
+-----------------------------------+
| Segmented Directory Section       |
+-----------------------------------+
| Central Directory                 |
+-----------------------------------+
| Encryption Section                |
+-----------------------------------+
```

### 1.2 Magic Number and Version

The file begins with an 8-byte magic number: `0x5049 5448 4F53` (ASCII "PITHOS").

The version field is a 2-byte unsigned integer representing the major and minor version (e.g., 0x0100 for version 1.0).

## 2. Block Structure

### 2.1 Basic Block Structure

Each block has a simple structure:

```
+-----------------------------------+
| Block Start Marker ("BLCK")       |
+-----------------------------------+
| Block Index (varint)              |
+-----------------------------------+
| Type & Flags (1 byte)             |
+-----------------------------------+
| Block Length (varint)             |
+-----------------------------------+
| Block Data (encrypted)            |
+-----------------------------------+
```

The Type & Flags byte efficiently encodes both block type and features in a single byte, with the first 4 bits representing the block type and the last 4 bits encoding feature flags.

### 2.2 Block Type and Flags

Block types and features are encoded using bit flags for efficient storage:

1. **Type Flags** (First 4 bits):
   - 0x0: Data block
   - 0x1: Metadata block
   - 0x2: Directory entry
   - 0x3: Symlink
   - 0x4: Extended attribute
   - 0x5: Deduplication reference
   - 0x6: External content reference
   - 0x7-0xF: Reserved for future use

2. **Feature Flags** (Last 4 bits):
   - Bit 4: Compression enabled (0=no, 1=yes)
   - Bit 5: Encryption enabled (0=no, 1=yes)
   - Bit 6: Extended metadata present (0=no, 1=yes)
   - Bit 7: Reference type for external/deduplication (0=internal, 1=external)

This compact representation allows a single byte to encode both the block type and its key features.

## 3. Content Chunking and Deduplication

### 3.1 SuperCDC Chunking Algorithm

The SuperCDC algorithm used in Pithos is an enhanced version of content-defined chunking with the following characteristics:

1. **Improved Boundary Selection**:
   - Uses a two-stage rolling hash approach (primary and secondary hash functions)
   - Primary hash (Gear hash) for fast candidate boundary detection
   - Secondary hash (polynomial hash) for boundary quality evaluation
   - Results in more stable chunk boundaries when content is modified

2. **Normalized Chunk Size**:
   - Minimum size: 64KB
   - Target size: 128KB
   - Maximum size: 256KB
   - Normalizing factor adjusts boundary selection probability based on distance from previous boundary

3. **Content-Aware Chunking**:
   - Adaptive window size based on content entropy
   - Boundary selection bias toward natural content boundaries (headers, section breaks, etc.)
   - Special handling for highly repetitive content

4. **Performance Optimizations**:
   - SIMD-accelerated rolling hash computation when available
   - Early rejection of unlikely boundary candidates
   - Efficient bit manipulation techniques for hash calculations

5. **Implementation Advantages**:
   - 30-40% fewer chunk splits during content modification compared to FastCDC
   - Better deduplication rates for mixed content types
   - More predictable chunk distribution with fewer outliers

### 3.2 Content Deduplication

Pithos uses content-defined chunking and secure deduplication:

1. **Secure Deduplication with Dual Hashing**:
   - Blake3 hash stored in block index for deduplication and content identification
   - SHAKE256 used exclusively for encryption key derivation (never stored)
   - First encryption layer using SHAKE256-derived keys (identical content = identical ciphertext)
   - Second encryption layer protects access to content keys

2. **Client-Side Security**:
   - All encryption performed client-side
   - No server-side secrets required
   - "Blind" storage where provider cannot access content

## 4. Encryption

### 4.1 Dual-Hash Security Model

Pithos implements a sophisticated dual-hash security approach:

1. **Cryptographic Isolation**:
   - **Blake3**: Used for deduplication and content verification
   - **SHAKE256**: Used exclusively for encryption key derivation
   - Complete separation between deduplication and encryption domains

2. **Blake3 Implementation Details**:
   - 16-byte truncated hash stored in block index
   - Public, visible to storage provider for deduplication
   - Computation optimized with SIMD acceleration when available
   - Provides integrity verification and content addressing

3. **SHAKE256 Key Derivation**:
   - Input: Raw block content (before compression)
   - Output: 64 bytes of cryptographic material
   - Never stored or transmitted
   - Implementation uses parallel permutation-based hashing

4. **Security Properties**:
   - Known plaintext attacks prevented by cryptographic domain separation
   - Deduplication leakage limited to existence of identical blocks
   - Brute force attacks infeasible due to large key space
   - Dictionary attacks mitigated by unique content and two-layer encryption

### 4.2 SHAKE256 Key Derivation for ChaCha20-Poly1305

The key derivation process is as follows:

1. **Compute SHAKE256 Hash**:
   - Input the block content into SHAKE256
   - Request 64 bytes of output from SHAKE256 (XOF - extensible output function)

2. **Key Generation from Hash Output**:
   - First 32 bytes: Used as the ChaCha20-Poly1305 encryption key
   - Next 12 bytes: Used as the nonce for ChaCha20-Poly1305
   - Remaining 20 bytes: Reserved for additional cryptographic material if needed

3. **Encryption Details**:
   - ChaCha20-Poly1305 requires a 32-byte key and 12-byte nonce
   - SHAKE256 directly produces both without additional KDF steps
   - The resulting key and nonce are deterministic for identical content

### 4.3 Encryption Process

1. For each block:
   - Calculate Blake3 content hash for deduplication and integrity verification (stored in block index)
   - Input the block content into SHAKE256
   - Extract 64 bytes from SHAKE256:
     * First 32 bytes: ChaCha20-Poly1305 encryption key
     * Next 12 bytes: ChaCha20-Poly1305 nonce
     * Remaining 20 bytes: Reserved for future use
   - Encrypt block data with ChaCha20-Poly1305 using the derived key and nonce
   - Generate a random file-specific key for each file
   - Encrypt the SHAKE256-derived key with the file key (second layer)
   - Store encrypted keys in file metadata (protected by file key)

## 5. Compression

### 5.1 Data Block Optimizations

Pithos incorporates several optimizations for data blocks:

1. **Smart Compression**:
   - Data sampling to detect compressibility (first 4KB and random 4KB samples)
   - Compression ratio estimation before full compression
   - Skip compression for detected incompressible data (already compressed media, encrypted content)
   - Dynamic compression level selection based on content type:
     * Text, documents, source code: Higher compression levels (zstd levels 9-19)
     * Mixed content: Medium compression levels (zstd levels 3-8)
     * Structured data: Lower compression levels (zstd levels 1-2)

2. **Delta Compression**:
   - For file versions with similar content
   - Store only the differences between versions
   - Significantly reduces storage for frequently updated files
   - Implemented via reference blocks with embedded delta instructions

3. **Dictionary Compression**:
   - Shared compression dictionaries for similar file types
   - Dictionaries built from content samples during initial creation
   - Significant improvement for small, similar files
   - Dictionary IDs stored in block flags for appropriate decompression

### 5.2 Compression Algorithm

Pithos exclusively uses Zstandard (zstd) for compression:

- **Algorithm**: Zstandard (zstd) is the only supported compression algorithm
- **Compression Levels**: Supports compression levels 1-19, with higher levels providing better compression at the cost of speed
- **Default Level**: Level 3 is recommended as the default, offering a good balance between speed and compression ratio

Zstandard was selected for the Pithos format because it provides:
- Excellent compression ratios
- High-speed decompression
- Configurable compression speed/ratio trade-off
- Dictionary support for improved compression of small files
- Wide platform support and active maintenance

## 6. Metadata

### 6.1 Metadata Architecture

Pithos implements a rich metadata system:

1. **Schema-Based Metadata**:
   - Default: Schema.org vocabulary for semantic richness
   - Alternative schemas: Dublin Core, XMP, EXIF
   - Custom schemas supported with namespace definition
   - Schema version tracked for compatibility

2. **Metadata Block Structure**:
   ```
   +-----------------------------------+
   | Metadata Type ID (2 bytes)        |
   +-----------------------------------+
   | Schema Version (2 bytes)          |
   +-----------------------------------+
   | Metadata Content (JSON, compressed)|
   +-----------------------------------+
   ```

3. **Metadata Types**:
   - 0x0001: Core file metadata (timestamps, permissions, etc.)
   - 0x0002: Content descriptive metadata (title, author, etc.)
   - 0x0003: Technical metadata (format, dimensions, etc.)
   - 0x0004: Provenance metadata (origin, processing history)
   - 0x0005: Rights metadata (license, copyright)
   - 0x0006: Custom application-specific metadata
   - 0x0007: Structural metadata (relationships between blocks)

4. **Metadata Indexing**:
   - Fast lookup via metadata type and schema
   - Optional full-text indexing of descriptive metadata
   - Hierarchical organization for complex metadata structures

5. **Metadata Compression and Storage**:
   - Efficient JSON compression using zstd dictionary compression
   - Common metadata patterns stored in shared dictionaries
   - Serialization optimized for size without sacrificing readability
   - Metadata blocks stored and encrypted like regular data blocks

### 6.2 Core Metadata

Each file contains core metadata including:
- Creation timestamp
- Modification timestamp
- Owner information
- Permissions
- File size
- Content type
- Block sizing model
- Encryption details
- Compression details

## 7. Directory Structure

### 7.1 Segmented Directory

The segmented directory enables partial updates:

```
+-----------------------------------+
| Segment Start Marker (8 bytes)    |
| "PITHOSSG"                        |
+-----------------------------------+
| Segment Size (8 bytes)            |
+-----------------------------------+
| Segment Version (4 bytes)         |
+-----------------------------------+
| Update Type (1 byte)              |
+-----------------------------------+
| File Entries                      |
+-----------------------------------+
| Block Index Updates               |
+-----------------------------------+
| Next Segment Offset (8 bytes)     |
| (0 if none)                       |
+-----------------------------------+
```

The segmented directory allows:
1. **Incremental Updates**: New segments can be added without rewriting the entire directory
2. **Update Chaining**: Segments form a linked list through "Next Segment Offset" pointers
3. **Differential Updates**: Only changed entries are included in new segments
4. **Change History**: The complete history of changes is preserved

Update types include:
- 0x00: Initial segment
- 0x01: File addition
- 0x02: File modification
- 0x03: File deletion
- 0x04: Block addition
- 0x05: Directory update

### 7.2 Central Directory

The central directory serves as a consolidated index that summarizes all segments:

```
+-----------------------------------+
| Central Directory Identifier      |
| (8 bytes: "PITHOSCD")             |
+-----------------------------------+
| Directory Size (8 bytes)          |
+-----------------------------------+
| Number of Files (4 bytes)         |
+-----------------------------------+
| Number of Blocks (8 bytes)        |
+-----------------------------------+
| File Entries                      |
|   +-------------------------------+
|   | File Entry 1                  |
|   +-------------------------------+
|   | File Entry 2                  |
|   +-------------------------------+
|   | ...                           |
+-----------------------------------+
| Block Index                       |
+-----------------------------------+
| Segmented Directory Root (8 bytes)|
+-----------------------------------+
| Encryption Section Offset (8 bytes)|
+-----------------------------------+
| CRC32 Checksum (4 bytes)          |
+-----------------------------------+
```

### 7.3 File Entries

```
+-----------------------------------+
| File ID (8 bytes)                 |
+-----------------------------------+
| Filename Length (2 bytes)         |
+-----------------------------------+
| Filename                          |
+-----------------------------------+
| Feature Flags (2 bytes)           |
+-----------------------------------+
| Block Count (4 bytes)             |
+-----------------------------------+
| Encrypted Block Index List        |
+-----------------------------------+
| Encrypted Block Keys List         |
+-----------------------------------+
| File Metadata Offset (8 bytes)    |
+-----------------------------------+
```

File entries use a compact 2-byte feature flags field to encode file properties while still supporting the full range of features.

### 7.4 Feature Flags (Per File)

A 16-bit bitfield indicating which features are used for each specific file:
- Bit 0: Encryption enabled
- Bit 1: Compression enabled
- Bit 2: Random I/O optimization
- Bit 3: Extended metadata
- Bit 4: Content-defined chunking enabled
- Bit 5: Deduplication used
- Bit 6: External references used
- Bit 7: Versioning enabled
- Bit 8: Delta compression used
- Bit 9: Custom metadata schema
- Bit 10: Virtual file (references only)
- Bit 11: Append-only
- Bit 12-15: Reserved for future use

### 7.5 Block Index

```
+-----------------------------------+
| Block Index (varint)              |
+-----------------------------------+
| Block Type Marker (1 byte)        |
+-----------------------------------+
| Blake3 Content Hash (16 bytes)    |
| OR Reference ID (variable)        |
+-----------------------------------+
| Block Offset (varint)             |
+-----------------------------------+
| Raw Size (varint)                 |
+-----------------------------------+
| Uncompressed Size (varint)        |
+-----------------------------------+
| Flags (1 byte)                    |
+-----------------------------------+
```

The Block Index structure has been optimized:

1. **Block Type Marker**:
   - 0x00: Normal block (followed by 16-byte Blake3 hash)
   - 0x01: Internal reference (followed by 4-byte target block index)
   - 0x02: External reference (followed by 2-byte network ID + variable length hash)

2. **Flags** (bit-packed into a single byte):
   - Bits 0-1: Compression type (0=none, 1=zstd, 2=lz4, 3=reserved)
   - Bits 2-3: Compression level (0=low, 1=medium, 2=high, 3=max)
   - Bits 4-5: Encryption type (0=none, 1=ChaCha20-Poly1305, 2-3=reserved)
   - Bits 6-7: Special handling (0=none, 1=dictionary compressed, 2=append-friendly, 3=reserved)

## 8. External Content References

Pithos supports efficient references to external content-addressable storage:

1. **Compact Reference Format**:
   ```
   +-----------------------------------+
   | Network ID (2 bytes)              |
   +-----------------------------------+
   | Hash Algorithm (4 bits)           |
   | Hash Length (4 bits)              |
   +-----------------------------------+
   | Content Hash (variable length)    |
   +-----------------------------------+
   | URI Template Length (1 byte)      |
   | (0 if none)                       |
   +-----------------------------------+
   | URI Template (optional)           |
   +-----------------------------------+
   ```

2. **Network ID Encoding**:
   - 0x0001: IPFS
   - 0x0002: Hypercore
   - 0x0003: Git object storage
   - 0x0004: S3-compatible object storage
   - 0x0005: Other Pithos archives
   - 0x0006: Filecoin
   - 0x0007: Arweave
   - 0x0008: Storj
   - 0x0009-0xFFFF: Reserved or custom networks

3. **Hash Algorithm Encoding** (4 bits):
   - 0x0: Blake3 (default)
   - 0x1: SHA-256
   - 0x2: SHA-3
   - 0x3: IPFS multihash
   - 0x4: Git SHA-1
   - 0x5-0xF: Reserved or custom hash algorithms

4. **Hash Length Encoding** (4 bits):
   - 0x0: 16 bytes
   - 0x1: 20 bytes
   - 0x2: 32 bytes
   - 0x3: 64 bytes
   - 0x4-0xE: Reserved
   - 0xF: Variable length (followed by length byte)

## 9. Encryption Section

### 9.1 File-Based Encryption Section

The encryption section has a file-centric structure:

```
+-----------------------------------+
| Encryption Section Identifier     |
| (8 bytes: "PITHOSEN")             |
+-----------------------------------+
| Encryption Section Size (8 bytes) |
+-----------------------------------+
| Version (2 bytes)                 |
+-----------------------------------+
| File Count (4 bytes)              |
+-----------------------------------+
| File Encryption Entries           |
|   +-------------------------------+
|   | File Entry 1                  |
|   +-------------------------------+
|   | File Entry 2                  |
|   +-------------------------------+
|   | ...                           |
+-----------------------------------+
```

### 9.2 File Encryption Entries

Each file encryption entry contains:

```
+-----------------------------------+
| File ID (8 bytes)                 |
+-----------------------------------+
| Recipient Count (2 bytes)         |
+-----------------------------------+
| Recipient Entries                 |
|   +-------------------------------+
|   | Recipient Entry 1             |
|   +-------------------------------+
|   | Recipient Entry 2             |
|   +-------------------------------+
|   | ...                           |
+-----------------------------------+
```

### 9.3 Recipient Entries

Each recipient entry contains:

```
+-----------------------------------+
| Entry Start Marker                |
| (4 bytes: "RCPT")                 |
+-----------------------------------+
| Entry Size (4 bytes)              |
+-----------------------------------+
| Recipient ID (16 bytes)           |
+-----------------------------------+
| Recipient Public Key (32 bytes)   |
+-----------------------------------+
| Encrypted File Key (32 bytes)     |
+-----------------------------------+
```

This file-centric approach provides:
- Clear separation of access by file
- Simple addition of new recipients for specific files
- Support for virtual files that reference blocks from other files
- Efficient block-level deduplication even with encryption

## 10. Random I/O and Access Optimization

Pithos provides efficient random access to encrypted data:

1. **Index-Based Random Access**:
   - Direct block lookup via central directory
   - Delta-compressed block offsets and sizes for space efficiency
   - Efficient logical-to-physical address mapping

2. **Block Access Modes**:
   - **Sequential**: Optimized for full file reads/writes
   - **Random**: Optimized for seeking and partial access
   - **Hybrid**: Balanced approach for mixed access patterns

3. **Access Pattern Optimization**:
   - Block placement strategy based on expected access pattern
   - Related blocks stored contiguously for sequential access
   - Index optimization for frequently accessed blocks

4. **Range Request Efficiency**:
   - Optimized for cloud storage range requests
   - Minimal HTTP requests for multi-block retrievals
   - Block sizing aligned with common range request patterns

## 11. Security Features

1. **Zero-Knowledge Encryption**: Only authorized recipients can decrypt
2. **File-Block Relationship Protection**: Prevents proof-of-possession attacks
3. **Content Verification**: Integrity checking via Blake3 content hashes
4. **Multiple Recipients**: Efficient sharing with targeted access control
5. **Secure Deduplication**: Dual-hash approach allows deduplication while protecting content
6. **Cryptographic Isolation**: Separate hash functions for identification and encryption
7. **Client-Side Control**: No dependency on server-side secrets or trusted third parties
8. **Deterministic Encryption**: SHAKE256 extensible output provides both key and nonce deterministically
9. **Minimized Metadata**: Streamlined block headers with no redundant information

## 12. Implementation Considerations

### 12.1 Writing Process

The Pithos format is designed for efficient sequential writing, following these steps:

1. Write the file header (magic number and version)
2. For each block:
   a. Generate a sequential Block Index
   b. Calculate SuperCDC boundaries
   c. Check for duplicate content if deduplication is enabled
   d. Write the block header with the Block Index, type flags, and length
   e. Encrypt and write the block data
   f. Calculate the Blake3 Content Hash of the data (to be stored in the central directory)
3. Build the block index mapping Block Indices to Content Hashes
4. Write the segmented directory with file and block information
5. Write the central directory with consolidated index information
6. Write the encryption section with hierarchical key management

### 12.2 Adding Recipients to Files

To add a new recipient to an existing encrypted Pithos file:

1. Obtain the file key using an existing recipient's credentials
2. Create a new recipient entry for the file:
   - Generate a unique recipient ID
   - Include the new recipient's public key
   - Encrypt the file key with the new recipient's public key
3. Append this new recipient entry to the file's section in the encryption section

### 12.3 Memory Management

- Block size caps to prevent excessive memory usage
- Streaming operations where possible
- Memory-mapped I/O support for efficient access

### 12.4 Multithreading

- Thread-safe design for concurrent operations
- Parallel compression/decompression
- Parallel encryption/decryption

## 13. Future Considerations

- Support for distributed storage backends
- Integration with content-addressable storage systems
- Advanced deduplication strategies
- Transparent cloud tiering support
- Blockchain-based integrity verification
- Selective partial encryption for mixed-security content
