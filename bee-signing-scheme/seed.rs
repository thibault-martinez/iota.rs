// TODO Replace with bee impl when available
use iota_crypto::{subseed, HashMode};

// TODO Replace constants

pub struct Seed([i8; 243]);

impl Seed {
    // TODO Template on sponge/hash type
    pub fn subseed(&self, index: u64) -> Self {
        // TODO Replace with bee impl when available
        let subseed = subseed(HashMode::Kerl, &self.0, index as usize).unwrap();

        Self::from_bytes_unchecked(&subseed)
    }

    // TODO String ?
    pub fn from_bytes(bytes: &[i8]) -> Result<Self, String> {
        // TODO Check bytes

        Ok(Self::from_bytes_unchecked(bytes))
    }

    fn from_bytes_unchecked(bytes: &[i8]) -> Self {
        let mut seed = [0; 243];

        seed.copy_from_slice(bytes);

        Seed(seed)
    }

    pub fn to_bytes(&self) -> &[i8] {
        &self.0
    }
}
