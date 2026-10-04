use pithos_lib::archive::WriteOptions;
use pithos_lib::crypto::PrivateKey;

#[allow(dead_code)]
pub fn options() -> WriteOptions {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    WriteOptions::new(sender, vec![recipient])
}
