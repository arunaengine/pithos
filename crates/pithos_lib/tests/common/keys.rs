use pithos_lib::crypto::{PrivateKey, PublicKey};

#[allow(dead_code)] // Integration targets compile this shared module independently.
pub fn private_key(name: &str) -> PrivateKey {
    pithos_lib::crypto::parse_private_pem(
        &std::fs::read(format!("tests/data/keys/{name}_private.pem")).unwrap(),
    )
    .unwrap()
}

#[allow(dead_code)] // Integration targets compile this shared module independently.
pub fn public_key(name: &str) -> PublicKey {
    pithos_lib::crypto::parse_public_pem(
        &std::fs::read(format!("tests/data/keys/{name}_public.pem")).unwrap(),
    )
    .unwrap()
}
