use digest::{ExtendableOutput, Update, XofReader};
use shake::Shake256;

pub struct Hasher {
    blake3: blake3::Hasher,
    shake256: Shake256,
}

pub struct Hashes {
    pub blake3: blake3::Hash,
    pub shake256: [u8; 32],
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    #[tracing::instrument(level = "trace", skip())]
    pub fn new() -> Self {
        Hasher {
            blake3: blake3::Hasher::new(),
            shake256: Shake256::default(),
        }
    }

    #[tracing::instrument(level = "trace", skip(self, bytes))]
    pub fn update(&mut self, bytes: &[u8]) {
        self.blake3.update(bytes);
        self.shake256.update(bytes);
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn finalize(&mut self) -> Hashes {
        let mut key_buf = [0u8; 32];
        self.shake256.clone().finalize_xof().read(&mut key_buf);

        Hashes {
            blake3: self.blake3.finalize(),
            shake256: key_buf,
        }
    }
}
