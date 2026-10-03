//! A minimal decoder for the block descriptors of a terminal directory.

/// Returns the processing flags of every block descriptor in the terminal directory.
pub fn block_flags(archive: &[u8]) -> Vec<u8> {
    let footer = &archive[archive.len() - 12..archive.len() - 4];
    let directory_len = u64::from_be_bytes(footer.try_into().unwrap()) as usize;
    let mut reader = Reader(&archive[archive.len() - directory_len..]);
    assert_eq!(reader.take(8), b"PITHOSDR");
    if reader.byte() == 1 {
        reader.varint();
        reader.varint();
    }
    for _ in 0..reader.varint() {
        reader.varint();
        reader.string();
        reader.byte();
        match reader.byte() {
            0 => reader.string(),
            1 => {
                let count = reader.varint();
                reader.take(64 * count);
            }
            2 => {
                for _ in 0..reader.varint() {
                    reader.varint();
                    reader.string();
                }
            }
            tag => panic!("unknown block list tag {tag}"),
        }
        for _ in 0..4 {
            reader.varint();
        }
        for _ in 0..reader.varint() {
            reader.varint();
            reader.varint();
        }
        if reader.byte() == 1 {
            reader.string();
        }
    }
    (0..reader.varint())
        .map(|_| {
            reader.take(32);
            for _ in 0..3 {
                reader.varint();
            }
            let flags = reader.byte();
            if reader.byte() == 1 {
                reader.string();
            }
            flags
        })
        .collect()
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        head
    }

    fn byte(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn varint(&mut self) -> usize {
        let mut value = 0;
        for shift in (0..64).step_by(7) {
            let byte = self.byte();
            value |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
        }
        panic!("varint is too long")
    }

    fn string(&mut self) {
        let len = self.varint();
        self.take(len);
    }
}
