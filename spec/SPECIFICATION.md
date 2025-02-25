# The Pithos file format

This document contains the formal description for the pithos (`.pto`) file format. A file format that enables compression and encryption while still maintaining a resonable performant indexing solution for large multi-gigabyte files. Optimized for usage with object storage solutions, like S3.


## Goals

* **Built-in encryption** - Secures data at rest without requiring additional application layers, providing native protection for sensitive information
* **Portable format** - Ensures consistent operation across different operating systems, hardware architectures, and programming environments
* **Included multi-specification metadata** - Supports comprehensive metadata structures adhering to multiple industry standards for improved interoperability
* **Built-in compression** - Natively integrates data compression within the format, reducing storage requirements and transmission times without external tools, uses "smart" compression that automatically decides if compression is necessary
* **Configurable Random IO** - Supports efficient retrieval of specific data segments without reading entire files, enabling targeted access operations
* **Optimized for Object storage** - Designed specifically for modern object storage systems, with considerations for cloud environments, distributed storage paradigms, and scalable data management

## Non-goals

* **Universal backward compatibility** - The format prioritizes modern functionality over compatibility with legacy systems and older file format versions
* **Minimal file size for small data** - Not optimized for extremely small files where the metadata overhead may be proportionally significant
* **Real-time streaming** - Not designed for continuous data streaming applications requiring minimal latency

## Pithos File Format Specification

## 1. Introduction

Pithos is a modern file format designed for secure, efficient data storage with a focus on object storage systems and cloud environments. It prioritizes security, portability, flexible metadata, and intelligent data handling while maintaining efficient random access capabilities.

## 2. Format Overview

Pithos uses a container-based approach where files, directories, and metadata are stored as objects within a unified structure. The format supports dynamic block sizing, built-in encryption and compression, and optimized random I/O operations.

## 3. File Structure

### 3.1 General Layout

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
| Central Directory                 |
+-----------------------------------+
```

### 3.2 Magic Number and Version

The file begins with an 8-byte magic number: `0x5049 5448 4F53 0A0D` (ASCII "PITHOS\n\r").

The version field is a 2-byte unsigned integer representing the major and minor version (e.g., 0x0100 for version 1.0).

## 4. Block Structure

### 4.1 Block Structure

Each block has a simple structure:

```
+-----------------------------------+
| Block Start Marker (4 bytes)      |
| "BLCK"                            |
+-----------------------------------+
| Block Index (varint)              |
+-----------------------------------+
| Block Type (1 byte)               |
+-----------------------------------+
| Block Length (varint)             |
+-----------------------------------+
| Encryption Nonce (12 bytes)       |
| (if encrypted)                    |
+-----------------------------------+
| Block Data                        |
+-----------------------------------+
```

- **Block Start Marker**: The ASCII string "BLCK" (0x424C434B) for easy identification of block boundaries
- **Block Index**: A variable-length integer providing a sequential identifier for the block, simplifying initial write operations
- **Block Type**: Identifies the type of data contained in the block
- **Block Length**: A variable-length integer specifying the total length of the block data
- **Encryption Nonce**: Only present when the block is encrypted, contains the 12-byte nonce used for ChaCha20-Poly1305 encryption

The content hash is not stored with the block itself but is calculated during writing and stored in the central directory.

### 4.2 Block Types

- 0x00: Data block
- 0x01: Metadata block
- 0x02: Directory entry
- 0x03: Symlink
- 0x04: Extended attribute
- 0x05-0xFF: Reserved for future use

### 4.3 Content Hashing

Pithos uses the Blake3 cryptographic hash function for content integrity and deduplication:

1. **Algorithm**: Blake3 is selected for its combination of speed, security, and simplicity
2. **Hash Size**: 16 bytes (128 bits) is used as the standard hash size, providing a good balance between collision resistance and space efficiency
3. **Hashing Scope**: The hash covers only the block data, not the header
4. **Storage Location**: Content hashes are stored exclusively in the central directory, not with the blocks themselves

Blake3 offers several advantages for the Pithos format:
- Extremely high performance (faster than MD5 and SHA-1)
- Strong security properties
- Resistance to length extension attacks
- Parallelizable computation for large blocks
- Incremental updates for streaming operations

### 4.4 Block Sizing Models

Pithos supports three block sizing models:

- **Constant**: Fixed block size (specified in bytes)
- **Full**: No blocking, each file is a single block
- **Dynamic**: Variable block sizes optimized for the content

The block sizing model is selected per file and stored in the file's metadata.

## 5. Encryption

### 5.1 Encryption Scheme

Pithos implements the crypt4gh encryption scheme with modifications to support unlimited blocks and controlled memory usage:

1. X25519 for key exchange
2. ChaCha20-Poly1305 for authenticated encryption
3. Support for multiple recipients (multiple public keys)

### 5.2 Encryption Process

1. Generate a random 12-byte nonce for each block
2. Store the nonce at the beginning of the block header
3. Generate a random segment key for each encrypted block
4. Encrypt the block data using ChaCha20-Poly1305 with the segment key and the stored nonce
5. Encrypt the segment key with each recipient's public key
6. Store the encrypted segment keys in the central directory's encryption section

This approach provides:
- Per-block encryption with unique nonces
- Zero-knowledge encryption where only authorized recipients can decrypt
- Efficient random access to encrypted blocks
- Centralized key management in the central directory

### 5.3 Block Size Limitations

To prevent excessive memory usage, encrypted blocks are limited to 64MB by default. Larger files are automatically split into multiple blocks.

### 5.4 Block Recovery

The Block Start Marker ("BLCK") combined with the consistent nonce placement enables recovery of encrypted blocks even if the central directory is corrupted. During recovery operations, the file can be scanned for the "BLCK" marker to identify potential block boundaries and verify integrity using the Blake3 Content Hash.

## 6. Compression

### 6.1 Compression Algorithm

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

### 6.2 Smart Compression

The format implements "smart" compression that:
1. Samples data to determine compressibility
2. Skips compression for already compressed data (images, videos, etc.)
3. Adjusts zstd compression level based on data characteristics and desired performance profile
4. Tracks compression ratio and adjusts strategy for subsequent blocks

## 7. Metadata

### 7.1 Core Metadata

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

### 7.2 Extended Metadata

Pithos supports multiple metadata specifications through a flexible structure:
- Schema.org (default metadata schema)
- Dublin Core
- XMP
- EXIF
- Custom schema with namespace definition

The Schema.org vocabulary is the default metadata schema in Pithos, providing a comprehensive set of structured data schemas that are widely used across the internet. This enables rich semantic descriptions of file content with standardized properties for various types of data and documents.

### 7.3 Metadata Storage

Metadata is stored as regular blocks (type 0x01) interspersed with data blocks throughout the file. This allows:
- Metadata to be treated as a first-class citizen
- Efficient updates to metadata without file reorganization
- Appropriate encryption and compression of metadata
- Logical grouping of related metadata with its data

Metadata blocks follow the same block structure as data blocks and can be referenced through the central directory just like any other block.

## 8. Directory Structure

### 8.1 Directory Entries

Directories are represented as special blocks containing:
- Directory name
- Creation timestamp
- Modification timestamp
- Owner information
- Permissions
- List of contained files/directories (IDs and names)

### 8.2 Symlinks

Symlinks are implemented as special blocks containing:
- Link name
- Target path
- Creation timestamp
- Owner information

## 9. Central Directory and Encryption Information

### 9.1 File Structure End

The end of a Pithos file contains two distinct components:

```
+-----------------------------------+
| Central Directory                 |
+-----------------------------------+
| Encryption Section                |
+-----------------------------------+
```

This separation allows for extending the encryption section by appending new recipient information without modifying the central directory.

### 9.2 Central Directory Structure

The central directory contains all essential file and block mapping information:

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
| Encryption Section Offset (8 bytes)|
+-----------------------------------+
| CRC32 Checksum (4 bytes)          |
+-----------------------------------+
```

The "Encryption Section Offset" field points to the beginning of the separate encryption section that follows the central directory.

### 9.3 File Entries

Each file entry contains:

```
+-----------------------------------+
| File ID (8 bytes)                 |
+-----------------------------------+
| Filename Length (2 bytes)         |
+-----------------------------------+
| Filename                          |
+-----------------------------------+
| Feature Flags (4 bytes)           |
+-----------------------------------+
| Block Count (4 bytes)             |
+-----------------------------------+
| Block Index List                  |
+-----------------------------------+
| File Metadata Offset (8 bytes)    |
+-----------------------------------+
```

### 9.4 Feature Flags (Per File)

A 4-byte bitfield indicating which features are used for each specific file:
- Bit 0: Encryption enabled
- Bit 1: Compression enabled
- Bit 2: Random I/O optimization
- Bit 3: Extended metadata
- Bit 4: Dynamic block sizing
- Bit 5: Symlinks supported
- Bit 6-31: Reserved for future use

### 9.5 Block Index

The block index contains comprehensive information for each block:

```
+-----------------------------------+
| Block Index (varint)              |
+-----------------------------------+
| Blake3 Content Hash (16 bytes)    |
+-----------------------------------+
| Block Offset (varint)             |
+-----------------------------------+
| Raw Size (varint)                 |
+-----------------------------------+
| Uncompressed Size (varint)        |
+-----------------------------------+
| Compression Flag (1 byte)         |
+-----------------------------------+
| Encryption Type (1 byte)          |
+-----------------------------------+
```

- **Compression Flag**: 0x00 for no compression, 0x01 for zstd compression

Delta compression is applied to sequential block offsets and sizes to minimize space. Variable-length integers (varints) are used to efficiently encode values of different magnitudes.

During file creation, blocks are initially referenced by their Block Index, which is later mapped to the Blake3 Content Hash after the block is completely written.

### 9.6 Encryption Section

The encryption section follows the central directory and uses a fully appendable structure for recipient management:

```
+-----------------------------------+
| Encryption Section Identifier     |
| (8 bytes: "PITHOSEN")             |
+-----------------------------------+
| Encryption Section Size (8 bytes) |
+-----------------------------------+
| Version (2 bytes)                 |
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

Each recipient entry is self-contained and follows this format:

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
| Block Key Entries Count (4 bytes) |
+-----------------------------------+
| Block Key Entries                 |
|   +-------------------------------+
|   | Block Index (varint)          |
|   +-------------------------------+
|   | Encrypted Key (32 bytes)      |
|   +-------------------------------+
|   | ...                           |
+-----------------------------------+
```

This structure eliminates any upfront recipient count, allowing for true append-only recipient addition.

### 9.7 Encryption Section Extensibility

The encryption section is designed for pure append-only recipient addition:

1. **No Recipient Count**: The design deliberately omits any upfront count of recipients, eliminating the need to update any header when adding recipients
   
2. **Self-Contained Entries**: Each recipient entry contains all necessary information for that recipient to decrypt all blocks they have access to
   
3. **Append Process**:
   - To add a new recipient, simply append a new recipient entry to the end of the encryption section
   - No existing data needs to be modified or rewritten
   - The new entry contains the recipient's public key and all block keys encrypted for that recipient
   
4. **Reading Process**:
   - Readers scan through all recipient entries until they find one matching their recipient ID
   - Once found, they can extract all block keys they have access to
   - No need to process other recipient entries
   
This approach allows for unlimited recipients to be added over time without any file rewrites.

## 10. Random I/O Optimization

### 10.1 Enhanced Block Index

For efficient random I/O, Pithos uses a delta-compressed block index in the central directory that maps logical file offsets to physical block locations. The delta compression works as follows:

1. Store the first block offset as an absolute value
2. For subsequent blocks, store only the difference from the previous block
3. Use variable-length encoding (varint) to efficiently represent both small and large deltas

This approach provides:
1. Direct access to any block without scanning the entire file
2. Minimal index size through efficient compression
3. Parallel reads of non-contiguous blocks
4. Efficient range queries

### 10.2 Block Size Tracking

The block index tracks both raw (compressed) and uncompressed sizes for each block:

1. Raw size: Actual size of the block as stored on disk (after compression if applicable)
2. Uncompressed size: Original size of the block data before compression

Both sizes are stored using delta-compressed varints to minimize space usage while supporting efficient random access calculations.

### 10.3 Access Modes

Three access modes are supported:
- **Sequential**: Optimized for reading/writing the entire file sequentially
- **Random**: Optimized for accessing arbitrary portions of the file
- **Hybrid**: Balanced approach for mixed access patterns

## 11. Extensibility

### 11.1 Append Operations

New content can be added to a Pithos file by appending blocks to the end of the file and updating the central directory. This allows for:
1. Adding new files without rewriting the entire archive
2. Updating metadata without changing file data
3. Progressive creation of large archives

### 11.2 Versioning

The format supports versioning through:
1. Block-level versioning (multiple blocks with the same logical ID but different versions)
2. Metadata versioning
3. Format versioning for future specification updates

## 12. Implementation Considerations

### 12.1 Memory Management

- Block size caps to prevent excessive memory usage
- Streaming operations where possible
- Memory-mapped I/O support for efficient access

### 12.2 Multithreading

- Thread-safe design for concurrent operations
- Parallel compression/decompression
- Parallel encryption/decryption

## 13. Implementation Considerations

### 13.1 Writing Process

The Pithos format is designed for efficient sequential writing, following these steps:

1. Write the file header (magic number and version)
2. For each block:
   a. Generate a sequential Block Index
   b. Write the block header with the Block Index, type, and length
   c. If encrypted, generate and write the encryption nonce
   d. Write the block data
   e. Calculate the Blake3 Content Hash of the data (to be stored in the central directory)
3. Build the block index mapping Block Indices to Content Hashes
4. Write the central directory with all metadata and block information
5. Write the encryption section with recipient keys and encrypted segment keys
   
This approach allows writers to process blocks sequentially without needing to seek backward in the file to update headers with content hashes.

### 13.2 Adding Recipients

To add new recipients to an existing encrypted Pithos file:

1. Obtain the block encryption keys using an existing recipient's credentials
2. Create a new recipient entry:
   - Generate a unique recipient ID
   - Include the new recipient's public key
   - Encrypt each block key with the new recipient's public key
   - Package these keys with their corresponding block indices
3. Append this new recipient entry to the end of the encryption section

No other modifications to the file are needed. This is a true append-only operation that doesn't require rewriting any existing content or updating any counts or offsets.

### 13.3 Processing Encryption During Reading

When reading an encrypted Pithos file:

1. Locate the encryption section using the offset in the central directory
2. Scan through recipient entries looking for one matching the reader's recipient ID
3. If found, extract the encrypted block keys
4. As blocks are read, use the appropriate decrypted key and the nonce stored in the block header to decrypt the content

This process is efficient as readers only need to process their own recipient entry, not the entire encryption section.

## 14. Future Considerations

- Support for distributed storage backends
- Integration with content-addressable storage systems
- Advanced deduplication strategies
- Transparent cloud tiering support
