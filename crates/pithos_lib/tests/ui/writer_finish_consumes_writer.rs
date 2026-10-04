use pithos_lib::archive::{ArchiveWriter, WriteOptions};
use pithos_lib::crypto::PrivateKey;

fn main() {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let writer = ArchiveWriter::create(Vec::new(), WriteOptions::new(sender, vec![recipient])).unwrap();
    let first = writer.finish();
    let second = writer.finish();
    let _ = (first, second);
}
