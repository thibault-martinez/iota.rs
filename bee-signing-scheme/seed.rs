// TODO Replace with bee impl when available
use iota_crypto::{subseed, HashMode, Sponge};

// TODO Replace constants

// TODO: documentation
pub struct Seed([i8; 243]);

#[derive(Debug)]
// TODO: documentation
pub enum SeedError {
    InvalidSeedError,
}

// TODO: documentation
impl Seed {
    // TODO: documentation
    pub fn subseed<S: Sponge + Default>(&self, index: u64) -> Self {
        // TODO Replace with bee impl when available
        let subseed = subseed(HashMode::Kerl, &self.0, index as usize).unwrap();

        Self::from_bytes_unchecked(&subseed)
    }

    // TODO: documentation
    pub fn from_bytes(bytes: &[i8]) -> Result<Self, SeedError> {
        // TODO Check bytes

        Ok(Self::from_bytes_unchecked(bytes))
    }

    // TODO: documentation
    fn from_bytes_unchecked(bytes: &[i8]) -> Self {
        let mut seed = [0; 243];

        seed.copy_from_slice(bytes);

        Seed(seed)
    }

    // TODO: documentation
    pub fn to_bytes(&self) -> &[i8] {
        &self.0
    }
}
