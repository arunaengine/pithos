use pithos_lib::archive::{ArchiveWriter, WriteOptions};
use pithos_lib::crypto::PrivateKey;

fn main() {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let writer = ArchiveWriter::create(Vec::new(), WriteOptions::new(sender, vec![recipient]))
        .unwrap();
    let incomplete = writer.into_incomplete().unwrap_err();
    let _ = incomplete.into_writer();
}
