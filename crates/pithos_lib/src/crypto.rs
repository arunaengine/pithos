//! Current Pithos cryptographic roles and protocol operations.
//!
//! The byte formats deliberately remain in the established protocol: every sealed value is
//! `nonce || ciphertext || tag` and always uses empty associated data. Version 1.1 derives
//! recipient grant keys with HKDF and adds unique block keys and AES-256-GCM block payloads.

use crate::format::header::FormatVersion;
use aes_gcm::Aes256Gcm;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{
        self, Aead, AeadCore, AeadInOut, Generate, Payload,
        consts::{U12, U16},
    },
};
use digest::{ExtendableOutput, Update, XofReader};
use hkdf::Hkdf;
use pkcs8::der::EncodePem;
use pkcs8::der::pem::PemLabel;
use pkcs8::{
    Document, LineEnding, ObjectIdentifier, PrivateKeyInfoRef, SecretDocument,
    SubjectPublicKeyInfoRef, der,
};
use sha2::Sha256;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const X25519_PKCS8_DER_HEADER: [u8; 16] = [
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20,
];
const X25519_PUBLIC_KEY_DER_HEADER: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00,
];

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key document")]
    InvalidKeyDocument,
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("X25519 public key does not produce a contributory shared secret")]
    NonContributoryPublicKey,
    #[error("key document encoding failed")]
    KeyDocumentEncoding,
    #[error("encrypted payload is too short")]
    EncryptedPayloadTooShort,
    #[error("cipher initialization failed")]
    CipherInitialization,
    #[error("payload authentication failed")]
    AuthenticationFailed,
}

/// An owned X25519 private key. Its debug representation and errors never include bytes.
pub struct PrivateKey([u8; 32]);

/// An X25519 public key suitable for a Pithos recipient or sender identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

macro_rules! secret_role {
    ($name:ident) => {
        pub(crate) struct $name([u8; 32]);

        impl $name {
            // SharedSecret does not construct directly, but this uniform role macro
            // supplies the constructor used by FileKey and BlockKey.
            #[allow(dead_code)]
            pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            // SharedSecret is recovered only through derive_shared, while FileKey
            // and BlockKey need this decoded-key-to-owned-key conversion.
            #[allow(dead_code)]
            pub(crate) fn from_protocol(bytes: &[u8; 32]) -> Self {
                Self(*bytes)
            }

            pub(crate) fn expose_for_protocol(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl ZeroizeOnDrop for $name {}

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

secret_role!(FileKey);
secret_role!(BlockKey);
secret_role!(SharedSecret);

impl PrivateKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random().to_bytes())
    }

    /// Takes 32 raw X25519 private key bytes. Consumes and wipes the supplied container.
    /// The returned key wipes its bytes on drop. Callers must wipe other copies.
    pub fn from_raw(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(*bytes)
    }

    /// Duplicate a secret only when a distinct owner is required by an API boundary.
    pub fn duplicate(&self) -> Self {
        Self(self.0)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(DalekPublicKey::from(&StaticSecret::from(self.0)).to_bytes())
    }

    pub fn from_private_pem_bytes(pem: &[u8]) -> Result<Self, CryptoError> {
        // `SecretDocument` owns the decoded DER; no ordinary String retains private PEM bytes.
        let pem = std::str::from_utf8(pem).map_err(|_| CryptoError::InvalidKeyDocument)?;
        let (label, document) =
            SecretDocument::from_pem(pem).map_err(|_| CryptoError::InvalidKeyDocument)?;
        PrivateKeyInfoRef::validate_pem_label(label)
            .map_err(|_| CryptoError::InvalidKeyDocument)?;
        let bytes = document.as_bytes();
        if bytes.len() != 48 || bytes[..16] != X25519_PKCS8_DER_HEADER {
            return Err(CryptoError::InvalidPrivateKey);
        }
        let mut secret = Self([0; 32]);
        secret.0.copy_from_slice(&bytes[16..]);
        Ok(secret)
    }

    pub fn to_private_pem_bytes(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut private_key = Zeroizing::new([0u8; 34]);
        private_key[0] = 0x04;
        private_key[1] = 0x20;
        private_key[2..].copy_from_slice(&self.0);
        let private_key = der::asn1::OctetStringRef::new(&private_key[..])
            .map_err(|_| CryptoError::KeyDocumentEncoding)?;
        let info = PrivateKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: ObjectIdentifier::from_str("1.3.101.110").expect("X25519 OID is valid"),
                parameters: None,
            },
            private_key,
            public_key: None,
        };
        let document =
            SecretDocument::encode_msg(&info).map_err(|_| CryptoError::KeyDocumentEncoding)?;
        document
            .to_pem(PrivateKeyInfoRef::PEM_LABEL, LineEnding::LF)
            .map(|pem| Zeroizing::new(pem.as_bytes().to_vec()))
            .map_err(|_| CryptoError::KeyDocumentEncoding)
    }

    pub(crate) fn as_dalek_static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.0)
    }

    pub(crate) fn into_dalek_static_secret(self) -> StaticSecret {
        StaticSecret::from(self.0)
    }

    #[cfg(test)]
    pub(crate) fn from_dalek_static_secret(key: &StaticSecret) -> Self {
        Self(key.to_bytes())
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for PrivateKey {}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateKey([REDACTED])")
    }
}

impl PublicKey {
    /// Accepts 32 raw X25519 public key bytes that pass the same checks as a PEM public key.
    pub fn from_raw(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        validate_x25519_public_key(&bytes)?;
        Ok(Self(bytes))
    }

    /// The 32 raw X25519 public key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_public_pem_bytes(pem: &[u8]) -> Result<Self, CryptoError> {
        let pem = std::str::from_utf8(pem).map_err(|_| CryptoError::InvalidKeyDocument)?;
        let (label, document) =
            Document::from_pem(pem).map_err(|_| CryptoError::InvalidKeyDocument)?;
        SubjectPublicKeyInfoRef::validate_pem_label(label)
            .map_err(|_| CryptoError::InvalidKeyDocument)?;
        let bytes = document.as_bytes();
        if bytes.len() != 44 || bytes[..12] != X25519_PUBLIC_KEY_DER_HEADER {
            return Err(CryptoError::InvalidPublicKey);
        }
        let mut key = [0; 32];
        key.copy_from_slice(&bytes[12..]);
        validate_x25519_public_key(&key)?;
        Ok(Self(key))
    }

    pub fn to_public_pem_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let info = SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: ObjectIdentifier::new_unwrap("1.3.101.110"),
                parameters: None,
            },
            subject_public_key: der::asn1::BitStringRef::from_bytes(&self.0)
                .map_err(|_| CryptoError::KeyDocumentEncoding)?,
        };
        info.to_pem(LineEnding::LF)
            .map(|pem| pem.into_bytes())
            .map_err(|_| CryptoError::KeyDocumentEncoding)
    }

    pub(crate) fn into_dalek_public_key(self) -> DalekPublicKey {
        DalekPublicKey::from(self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicKey(..)")
    }
}

pub fn generate_private_key() -> PrivateKey {
    PrivateKey::generate()
}

pub fn parse_private_pem(pem: &[u8]) -> Result<PrivateKey, CryptoError> {
    PrivateKey::from_private_pem_bytes(pem)
}

pub fn parse_public_pem(pem: &[u8]) -> Result<PublicKey, CryptoError> {
    PublicKey::from_public_pem_bytes(pem)
}

pub fn serialize_public_pem(key: &PublicKey) -> Result<Vec<u8>, CryptoError> {
    key.to_public_pem_bytes()
}

pub(crate) fn derive_shared(
    private: &[u8; 32],
    public: &[u8; 32],
) -> Result<SharedSecret, CryptoError> {
    let private = StaticSecret::from(*private);
    let shared = private.diffie_hellman(&DalekPublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(CryptoError::NonContributoryPublicKey);
    }
    Ok(SharedSecret(shared.to_bytes()))
}

/// HKDF info prefix of a version 1.1 recipient grant; the sender and recipient keys follow.
const GRANT_KEY_INFO: &[u8] = b"pithos 1.1 recipient grant";

/// Wrapping key of one recipient grant. Version 1.0 uses the raw shared secret. Version 1.1
/// derives a key per grant with HKDF-SHA256, salted with the grant nonce, bound to both keys.
pub(crate) fn grant_wrapping_key(
    version: FormatVersion,
    shared: SharedSecret,
    sender: &[u8; 32],
    recipient: &[u8; 32],
    nonce: &[u8; 12],
) -> SharedSecret {
    match version {
        FormatVersion::V0_7 | FormatVersion::V1_0 => shared,
        FormatVersion::V1_1 => {
            let mut info = Zeroizing::new([0u8; GRANT_KEY_INFO.len() + 64]);
            info[..GRANT_KEY_INFO.len()].copy_from_slice(GRANT_KEY_INFO);
            info[GRANT_KEY_INFO.len()..GRANT_KEY_INFO.len() + 32].copy_from_slice(sender);
            info[GRANT_KEY_INFO.len() + 32..].copy_from_slice(recipient);
            let mut key = SharedSecret([0; 32]);
            Hkdf::<Sha256>::new(Some(&nonce[..]), shared.expose_for_protocol())
                .expand(&info[..], &mut key.0)
                .expect("32 bytes is a valid HKDF-SHA256 output length");
            key
        }
    }
}

/// The nonce stored at the start of a sealed value, needed before its key can be derived.
pub(crate) fn sealed_nonce(payload: &[u8]) -> Result<[u8; 12], CryptoError> {
    if payload.len() < 15 {
        return Err(CryptoError::EncryptedPayloadTooShort);
    }
    let mut nonce = [0; 12];
    nonce.copy_from_slice(&payload[..12]);
    Ok(nonce)
}

pub(crate) fn validate_x25519_public_key(public: &[u8; 32]) -> Result<(), CryptoError> {
    // Low-order public keys produce the identity for every clamped X25519 scalar.
    let probe = StaticSecret::from([0; 32]).diffie_hellman(&DalekPublicKey::from(*public));
    if probe.was_contributory() {
        Ok(())
    } else {
        Err(CryptoError::NonContributoryPublicKey)
    }
}

pub(crate) fn derive_block_key(plaintext: &[u8]) -> BlockKey {
    let mut shake = shake::Shake256::default();
    shake.update(plaintext);
    let mut key = BlockKey([0; 32]);
    shake.finalize_xof().read(&mut key.0);
    key
}

pub(crate) fn block_hash(plaintext: &[u8]) -> [u8; 32] {
    *blake3::hash(plaintext).as_bytes()
}

/// BLAKE3 key derivation context of the identity subkey of a unique block key.
const BLOCK_IDENTITY_CONTEXT: &str = "pithos 1.1 block identity";

/// A fresh random key for one unique-key block.
pub(crate) fn random_block_key() -> BlockKey {
    BlockKey(Key::generate().into())
}

/// The keyed block hash of a unique-key block, keyed with a subkey of its block key.
pub(crate) fn keyed_block_hash(key: &BlockKey, plaintext: &[u8]) -> [u8; 32] {
    let subkey = Zeroizing::new(blake3::derive_key(BLOCK_IDENTITY_CONTEXT, &key.0));
    *blake3::keyed_hash(&subkey, plaintext).as_bytes()
}

pub(crate) fn seal_block_with_nonce(
    key: &BlockKey,
    plaintext: &[u8],
    nonce: [u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    seal_empty_aad(key.expose_for_protocol(), plaintext, nonce)
}

pub(crate) fn open_block(
    key: &BlockKey,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_empty_aad(key.expose_for_protocol(), payload)
}

/// BLAKE3 key derivation context of the AES-256-GCM payload key of a block key.
const AES_PAYLOAD_CONTEXT: &str = "pithos 1.1 aes-256-gcm payload";

fn aes_payload_key(key: &BlockKey) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(AES_PAYLOAD_CONTEXT, &key.0))
}

pub(crate) fn seal_block_aes_with_nonce(
    key: &BlockKey,
    plaintext: &[u8],
    nonce: [u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    seal_with::<Aes256Gcm>(&aes_payload_key(key), plaintext, nonce)
}

pub(crate) fn open_block_aes(
    key: &BlockKey,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_with::<Aes256Gcm>(&aes_payload_key(key), payload)
}

pub(crate) fn seal_file_block_list_with_nonce(
    key: &FileKey,
    plaintext: &[u8],
    nonce: [u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    seal_empty_aad(key.expose_for_protocol(), plaintext, nonce)
}

/// Opens a sealed block list inside its own buffer, so the plaintext needs no second buffer.
pub(crate) fn open_file_block_list(
    key: &FileKey,
    payload: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if payload.len() < 15 {
        return Err(CryptoError::EncryptedPayloadTooShort);
    }
    let len = payload
        .len()
        .checked_sub(28)
        .ok_or(CryptoError::AuthenticationFailed)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_for_protocol())
        .map_err(|_| CryptoError::CipherInitialization)?;
    let mut buffer = Zeroizing::new(payload);
    let (nonce, sealed) = buffer.split_at_mut(12);
    let (message, tag) = sealed.split_at_mut(len);
    let nonce: [u8; 12] = (&*nonce).try_into().expect("12-byte nonce");
    let tag = aead::Tag::<ChaCha20Poly1305>::try_from(&*tag).expect("16-byte tag");
    cipher
        .decrypt_inout_detached(&Nonce::from(nonce), b"", message.into(), &tag)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    buffer.copy_within(12..12 + len, 0);
    buffer.truncate(len);
    Ok(buffer)
}

pub(crate) fn wrap_recipient_list_with_nonce(
    key: &SharedSecret,
    plaintext: &[u8],
    nonce: [u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    seal_empty_aad(key.expose_for_protocol(), plaintext, nonce)
}

pub(crate) fn unwrap_recipient_list(
    key: &SharedSecret,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_empty_aad(key.expose_for_protocol(), payload)
}

pub(crate) fn random_nonce() -> [u8; 12] {
    Nonce::generate().into()
}

#[cfg(feature = "crypt4gh")]
pub(crate) fn seal_crypt4gh_payload(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal_empty_aad(key, plaintext, random_nonce())
}

fn seal_empty_aad(
    key: &[u8; 32],
    plaintext: &[u8],
    nonce: [u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    seal_with::<ChaCha20Poly1305>(key, plaintext, nonce)
}

fn open_empty_aad(key: &[u8; 32], payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_with::<ChaCha20Poly1305>(key, payload)
}

fn seal_with<C: KeyInit + Aead + AeadCore<NonceSize = U12>>(
    key: &[u8; 32],
    plaintext: &[u8],
    nonce: [u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::CipherInitialization)?;
    let ciphertext = cipher
        .encrypt(
            &aead::Nonce::<C>::from(nonce),
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut payload = Vec::with_capacity(12 + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

/// Decrypts into a buffer of exactly the plaintext size, so it keeps no capacity for the tag.
fn open_with<C: KeyInit + AeadInOut + AeadCore<NonceSize = U12, TagSize = U16>>(
    key: &[u8; 32],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if payload.len() < 15 {
        return Err(CryptoError::EncryptedPayloadTooShort);
    }
    let len = payload
        .len()
        .checked_sub(28)
        .ok_or(CryptoError::AuthenticationFailed)?;
    let (nonce, sealed) = payload.split_at(12);
    let (message, tag) = sealed.split_at(len);
    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::CipherInitialization)?;
    let nonce: [u8; 12] = nonce.try_into().expect("12-byte nonce");
    let tag = aead::Tag::<C>::try_from(tag).expect("16-byte tag");
    let mut plaintext = Zeroizing::new(message.to_vec());
    cipher
        .decrypt_inout_detached(
            &aead::Nonce::<C>::from(nonce),
            b"",
            plaintext.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(plaintext)
}

#[cfg(test)]
mod zeroization_tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn owned_secret_roles_have_drop_zeroization_contracts() {
        assert_zeroize_on_drop::<PrivateKey>();
        assert_zeroize_on_drop::<FileKey>();
        assert_zeroize_on_drop::<BlockKey>();
        assert_zeroize_on_drop::<SharedSecret>();
        assert_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
    }

    #[test]
    fn aead_ciphers_wipe_keys() {
        assert_zeroize_on_drop::<Aes256Gcm>();
        assert_zeroize_on_drop::<ChaCha20Poly1305>();
    }
}
