//! X25519 Key Management Module
//!
//! This module provides functionality for generating, parsing, and converting X25519 keys
//! between x25519-dalek types and PEM-encoded PKCS#8 format.
//!
//! # Examples
//!
//! ```rust
//! use pithos_lib::helpers::x25519_keys::*;
//!
//! // Generate a new private key
//! let private_key = generate_private_key().unwrap();
//! let public_key = x25519_dalek::PublicKey::from(&private_key);
//!
//! // Convert to PEM format
//! let private_pem = private_key_to_pem_bytes(&private_key).unwrap();
//! let public_pem = public_key_to_pem_bytes(&public_key).unwrap();
//!
//! // Parse from PEM format
//! let parsed_private = private_key_from_pem_bytes(&private_pem).unwrap();
//! let parsed_public = public_key_from_pem_bytes(&public_pem).unwrap();
//! ```

use pkcs8::der::pem::PemLabel;
use pkcs8::der::EncodePem;
use pkcs8::spki::AlgorithmIdentifier;
use pkcs8::{
    der, Document, LineEnding, ObjectIdentifier, PrivateKeyInfo, SecretDocument,
    SubjectPublicKeyInfoRef,
};
use rand::rngs::OsRng;
use std::str::FromStr;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

const X25519_PKCS8_DER_HEADER: [u8; 16] = [
    0x30, 0x2E, // SEQUENCE (30), length 46 (2E)
    0x02, 0x01, 0x00, // INTEGER (02), length (01) version 0 (00)
    0x30, 0x05, // SEQUENCE (30), for algorithm identifier, length 5 (05)
    0x06, 0x03, 0x2B, 0x65, 0x6E, // OID for X25519 (1.3.101.110)
    0x04, 0x22, // OCTET STRING, length 34 (0x22)
    0x04, 0x20, // Inner OCTET STRING, length 32 (raw key follows)
];

const X25519_PUBLIC_KEY_DER_HEADER: [u8; 12] = [
    0x30, 0x2A, // SEQUENCE, length 42
    0x30, 0x05, // SEQUENCE for algorithm identifier
    0x06, 0x03, 0x2B, 0x65, 0x6E, // OID for X25519 (1.3.101.110)
    0x03, 0x21, // BIT STRING, length 33
    0x00, // Unused bits (always 0)
];

/// Custom error type for cryptographic operations
#[derive(Error, Debug)]
pub enum CryptError {
    /// Invalid PEM format or structure
    #[error("Invalid PEM format: {0}")]
    InvalidPemFormat(String),
    /// Invalid private key data
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    /// Invalid public key data
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    /// PKCS#8 encoding/decoding error
    #[error("PKCS#8 error: {0}")]
    Pkcs8Error(String),
    /// Key generation failure
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
}

/// Generate a new X25519 private key using cryptographically secure randomness
///
/// # Returns
///
/// Returns a `StaticSecret` that can be used for X25519 key agreement operations.
///
/// # Examples
///
/// ```rust
/// use pithos_lib::helpers::x25519_keys::generate_private_key;
/// let private_key = generate_private_key().unwrap();
/// let public_key = x25519_dalek::PublicKey::from(&private_key);
/// ```
pub fn generate_private_key() -> Result<StaticSecret, CryptError> {
    let secret = StaticSecret::random_from_rng(OsRng);
    Ok(secret)
}

/// Derive a shared secret using X25519 key agreement
///
/// # Arguments
///
/// * `private_key` - The local party's X25519 private key (`StaticSecret`)
/// * `public_key` - The remote party's X25519 public key (`PublicKey`)
///
/// # Returns
///
/// Returns a 32-byte shared secret as a `[u8;32]`.
///
/// # Examples
///
/// ```rust
/// use pithos_lib::helpers::x25519_keys::{generate_private_key, derive_shared_key};
/// use x25519_dalek::PublicKey;
///
/// let private_a = generate_private_key().unwrap();
/// let public_a = PublicKey::from(&private_a);
/// let private_b = generate_private_key().unwrap();
/// let public_b = PublicKey::from(&private_b);
///
/// let shared_ab = derive_shared_key(&private_a, &public_b);
/// let shared_ba = derive_shared_key(&private_b, &public_a);
/// assert_eq!(shared_ab, shared_ba);
/// ```
pub fn derive_shared_key(private_key: &StaticSecret, public_key: &PublicKey) -> [u8; 32] {
    let shared = private_key.diffie_hellman(public_key);
    shared.to_bytes()
}

/// Convert an X25519 private key to PEM-encoded PKCS#8 bytes
///
/// # Arguments
///
/// * `key` - The StaticSecret to convert
///
/// # Returns
///
/// Returns a Vec<u8> containing the PEM-encoded private key data.
///
/// # Examples
///
/// ```rust
/// use pithos_lib::helpers::x25519_keys::*;
/// let private_key = generate_private_key().unwrap();
/// let pem_bytes = private_key_to_pem_bytes(&private_key).unwrap();
/// println!("{}", String::from_utf8_lossy(&pem_bytes));
/// ```
pub fn private_key_to_pem_bytes(key: &StaticSecret) -> Result<Vec<u8>, CryptError> {
    // Serialize private key as nested OCTET STRING
    let mut private_key = [0u8; 34];
    private_key[0] = 0x04;
    private_key[1] = 0x20;
    private_key[2..].copy_from_slice(key.as_bytes());

    let private_key_info = PrivateKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid: ObjectIdentifier::from_str("1.3.101.110").unwrap(),
            parameters: None, // X25519 has no parameters
        },
        private_key: &private_key,
        public_key: None,
    };

    let secret_document = SecretDocument::encode_msg(&private_key_info)
        .map_err(|e| CryptError::Pkcs8Error(e.to_string()))?;

    let pem = secret_document
        .to_pem(PrivateKeyInfo::PEM_LABEL, LineEnding::LF)
        .map_err(|e| CryptError::Pkcs8Error(e.to_string()))?;
    Ok(pem.as_bytes().to_vec())
}

/// Parse an X25519 private key from PEM-encoded PKCS#8 bytes
///
/// # Arguments
///
/// * `pem_data` - The PEM-encoded private key bytes
///
/// # Returns
///
/// Returns a StaticSecret parsed from the PEM data.
///
/// # Examples
///
/// ```rust
/// use pithos_lib::helpers::x25519_keys::*;
/// let private_key = generate_private_key().unwrap();
/// let pem_bytes = private_key_to_pem_bytes(&private_key).unwrap();
/// let private_key = private_key_from_pem_bytes(&pem_bytes).unwrap();
/// ```
pub fn private_key_from_pem_bytes(pem_data: &[u8]) -> Result<StaticSecret, CryptError> {
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| CryptError::InvalidPemFormat(format!("Invalid UTF-8: {}", e)))?;

    let (label, doc) = SecretDocument::from_pem(pem_str)
        .map_err(|e| CryptError::InvalidPemFormat(e.to_string()))?;
    PrivateKeyInfo::validate_pem_label(label)
        .map_err(|e| CryptError::InvalidPemFormat(e.to_string()))?;

    let key_bytes = match doc.as_bytes() {
        bytes if bytes.len() == 48 && bytes[..16] == X25519_PKCS8_DER_HEADER => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[16..]);
            key
        }
        _ => {
            return Err(CryptError::InvalidPrivateKey(
                "Invalid private key".to_string(),
            ));
        }
    };

    Ok(StaticSecret::from(key_bytes))
}

/// Convert an X25519 public key to PEM-encoded SubjectPublicKeyInfo bytes
///
/// # Arguments
///
/// * `key` - The PublicKey to convert
///
/// # Returns
///
/// Returns a Vec<u8> containing the PEM-encoded public key data.
///
/// # Examples
///
/// ```rust
/// use pithos_lib::helpers::x25519_keys::*;
/// let private_key = generate_private_key().unwrap();
/// let public_key = x25519_dalek::PublicKey::from(&private_key);
/// let pem_bytes = public_key_to_pem_bytes(&public_key).unwrap();
/// ```
pub fn public_key_to_pem_bytes(key: &PublicKey) -> Result<Vec<u8>, CryptError> {
    let key_bytes = key.as_bytes();

    // Create SubjectPublicKeyInfo
    let public_key_info = SubjectPublicKeyInfoRef {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.3.101.110"), // X25519 OID
            parameters: None,
        },
        subject_public_key: der::asn1::BitStringRef::from_bytes(key_bytes)
            .map_err(|e| CryptError::Pkcs8Error(e.to_string()))?,
    };

    let pem_string = public_key_info
        .to_pem(LineEnding::LF)
        .map_err(|e| CryptError::Pkcs8Error(e.to_string()))?;

    Ok(pem_string.into_bytes())
}

/// Parse an X25519 public key from PEM-encoded SubjectPublicKeyInfo bytes
///
/// # Arguments
///
/// * `pem_data` - The PEM-encoded public key bytes
///
/// # Returns
///
/// Returns a PublicKey parsed from the PEM data.
///
/// # Examples
///
/// ```rust
/// use pithos_lib::helpers::x25519_keys::*;
/// let private_key = generate_private_key().unwrap();
/// let public_key = x25519_dalek::PublicKey::from(&private_key);
/// let pem_bytes = public_key_to_pem_bytes(&public_key).unwrap();
/// let public_key = public_key_from_pem_bytes(&pem_bytes).unwrap();
/// ```
pub fn public_key_from_pem_bytes(pem_data: &[u8]) -> Result<PublicKey, CryptError> {
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| CryptError::InvalidPemFormat(format!("Invalid UTF-8: {}", e)))?;

    let (label, doc) =
        Document::from_pem(pem_str).map_err(|e| CryptError::InvalidPemFormat(e.to_string()))?;

    SubjectPublicKeyInfoRef::validate_pem_label(label)
        .map_err(|e| CryptError::InvalidPemFormat(e.to_string()))?;

    let public_key_bytes = match doc.as_bytes() {
        bytes if bytes.len() == 44 && bytes[..12] == X25519_PUBLIC_KEY_DER_HEADER => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[12..]);
            key
        }
        _ => return Err(CryptError::InvalidPublicKey("Invalid format".to_string())),
    };

    Ok(PublicKey::from(public_key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::PublicKey;

    #[test]
    fn test_generate_private_key() {
        let key = generate_private_key().expect("Failed to generate private key");
        // Verify we can derive a public key
        let _public_key = PublicKey::from(&key);
    }

    #[test]
    fn test_derive_shared_key() {
        let private_a = generate_private_key().unwrap();
        let public_a = PublicKey::from(&private_a);
        let private_b = generate_private_key().unwrap();
        let public_b = PublicKey::from(&private_b);

        let shared_ab = derive_shared_key(&private_a, &public_b);
        let shared_ba = derive_shared_key(&private_b, &public_a);

        // The shared secrets should be equal
        assert_eq!(shared_ab, shared_ba);

        // The shared secret should be 32 bytes
        assert_eq!(shared_ab.len(), 32);
    }

    #[test]
    fn test_private_key_round_trip() {
        let original_key = generate_private_key().expect("Failed to generate key");

        // Convert to PEM
        let pem_bytes = private_key_to_pem_bytes(&original_key).expect("Failed to convert to PEM");
        println!(
            "{}",
            String::from_utf8(pem_bytes.clone()).expect("Failed to convert to string")
        );

        // Parse back from PEM
        let parsed_key = private_key_from_pem_bytes(&pem_bytes).expect("Failed to parse from PEM");

        // Verify keys are equivalent by comparing derived public keys
        let original_public = PublicKey::from(&original_key);
        let parsed_public = PublicKey::from(&parsed_key);

        assert_eq!(original_public.as_bytes(), parsed_public.as_bytes());
    }

    #[test]
    fn test_public_key_round_trip() {
        let private_key = generate_private_key().expect("Failed to generate key");
        let original_public = PublicKey::from(&private_key);

        // Convert to PEM
        let pem_bytes =
            public_key_to_pem_bytes(&original_public).expect("Failed to convert to PEM");

        // Parse back from PEM
        let parsed_public =
            public_key_from_pem_bytes(&pem_bytes).expect("Failed to parse from PEM");

        assert_eq!(original_public.as_bytes(), parsed_public.as_bytes());
    }

    #[test]
    fn test_pem_format_validation() {
        let private_key = generate_private_key().expect("Failed to generate key");
        let pem_bytes = private_key_to_pem_bytes(&private_key).expect("Failed to convert");
        let pem_str = String::from_utf8(pem_bytes).expect("Invalid UTF-8");

        assert!(pem_str.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem_str.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_public_pem_format_validation() {
        let private_key = generate_private_key().expect("Failed to generate key");
        let public_key = PublicKey::from(&private_key);
        let pem_bytes = public_key_to_pem_bytes(&public_key).expect("Failed to convert");
        let pem_str = String::from_utf8(pem_bytes).expect("Invalid UTF-8");

        assert!(pem_str.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem_str.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_invalid_pem_format() {
        let invalid_pem = b"this is not valid PEM data";
        let result = private_key_from_pem_bytes(invalid_pem);
        assert!(result.is_err());

        let result = public_key_from_pem_bytes(invalid_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_utf8() {
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let result = private_key_from_pem_bytes(&invalid_utf8);
        assert!(matches!(result, Err(CryptError::InvalidPemFormat(_))));
    }

    #[test]
    fn test_multiple_key_generation_uniqueness() {
        let key1 = generate_private_key().expect("Failed to generate key1");
        let key2 = generate_private_key().expect("Failed to generate key2");

        let public1 = PublicKey::from(&key1);
        let public2 = PublicKey::from(&key2);

        // Keys should be different
        assert_ne!(public1.as_bytes(), public2.as_bytes());
    }

    #[test]
    fn test_error_display() {
        let error = CryptError::InvalidPemFormat("test message".to_string());
        assert_eq!(format!("{}", error), "Invalid PEM format: test message");

        let error = CryptError::KeyGenerationError("generation failed".to_string());
        assert_eq!(
            format!("{}", error),
            "Key generation error: generation failed"
        );
    }

    // Property-based testing
    #[test]
    fn test_many_round_trips() {
        for _ in 0..100 {
            let private_key = generate_private_key().expect("Failed to generate key");
            let public_key = PublicKey::from(&private_key);

            // Test private key round trip
            let private_pem =
                private_key_to_pem_bytes(&private_key).expect("Failed to encode private key");

            let parsed_private =
                private_key_from_pem_bytes(&private_pem).expect("Failed to parse private key");
            let parsed_public_from_private = PublicKey::from(&parsed_private);

            // Test public key round trip
            let public_pem =
                public_key_to_pem_bytes(&public_key).expect("Failed to encode public key");
            let parsed_public =
                public_key_from_pem_bytes(&public_pem).expect("Failed to parse public key");

            assert_eq!(public_key.as_bytes(), parsed_public_from_private.as_bytes());
            assert_eq!(public_key.as_bytes(), parsed_public.as_bytes());
        }
    }
}
