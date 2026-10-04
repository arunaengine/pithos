use pithos_lib::archive::{ArchivePath, ArchiveWriter, EntryMetadata, WriteOptions};
use pithos_lib::crypto::PrivateKey;

fn main() {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let mut writer = ArchiveWriter::create(Vec::new(), WriteOptions::new(sender, vec![recipient])).unwrap();
    let _sink = writer.finish().unwrap();
    let _ = writer.add_directory(ArchivePath::new("after").unwrap(), EntryMetadata::new(0, 0, 0));
}
