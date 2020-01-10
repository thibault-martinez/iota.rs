// TODO Replace with bee impl when available
use iota_crypto::{subseed, HashMode};

// TODO Replace constants

pub struct Seed([i8; 243]);

impl Seed {
    // TODO Template on sponge/hash type
    pub fn subseed(&self, index: u64) -> Self {
        // TODO Replace with bee impl when available
        let subseed = subseed(HashMode::Kerl, &self.0, index as usize).unwrap();

        Seed::from_bytes(&subseed).unwrap()
    }

    // TODO String ?
    pub fn from_bytes(bytes: &[i8]) -> Result<Self, String> {
        let mut seed = [0; 243];

        // TODO Check bytes
        seed.copy_from_slice(bytes);

        Ok(Seed(seed))
    }

    pub fn to_bytes(&self) -> &[i8] {
        &self.0
    }
}
