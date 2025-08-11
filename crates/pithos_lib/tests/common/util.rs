use x25519_dalek::{PublicKey, StaticSecret};

pub fn load_test_keys() -> (StaticSecret, PublicKey) {
    // Read sender private key
    let sender_pem_content = std::fs::read_to_string("tests/data/sender_private.pem").unwrap();
    let writer_key =
        pithos_lib::helpers::x25519_keys::private_key_from_pem_bytes(sender_pem_content.as_bytes())
            .unwrap();

    // Read recipient public key
    let recipient_pem_content =
        std::fs::read_to_string("tests/data/recipient1_public.pem").unwrap();
    let reader_key_01 = pithos_lib::helpers::x25519_keys::public_key_from_pem_bytes(
        recipient_pem_content.as_bytes(),
    )
    .unwrap();

    (writer_key, reader_key_01)
}
