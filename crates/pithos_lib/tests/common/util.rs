use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
use std::fs::{File, Permissions, create_dir_all, read_to_string, set_permissions};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn load_test_keys() -> (StaticSecret, PublicKey, PublicKey) {
    // Read sender private key
    let sender_pem_content = read_to_string("tests/data/keys/sender_private.pem").unwrap();
    let writer_key = private_key_from_pem_bytes(sender_pem_content.as_bytes()).unwrap();

    // Read recipient 1 public key
    let recipient1_pem_content = read_to_string("tests/data/keys/recipient1_public.pem").unwrap();
    let reader_key_01 = public_key_from_pem_bytes(recipient1_pem_content.as_bytes()).unwrap();

    // Read recipient 2 public key
    let recipient2_pem_content = read_to_string("tests/data/keys/recipient2_public.pem").unwrap();
    let reader_key_02 = public_key_from_pem_bytes(recipient2_pem_content.as_bytes()).unwrap();

    (writer_key, reader_key_01, reader_key_02)
}

    // Read recipient public key
    let recipient_pem_content =
        std::fs::read_to_string("tests/data/recipient1_public.pem").unwrap();
    let reader_key_01 = pithos_lib::helpers::x25519_keys::public_key_from_pem_bytes(
        recipient_pem_content.as_bytes(),
    )
    .unwrap();

    (writer_key, reader_key_01)
}
