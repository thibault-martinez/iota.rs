use iota_crypto::{subseed, HashMode};

pub struct Seed([i8; 243]);

impl Seed {
    pub fn subseed(&self, index: u64) -> Self {
        let subseed = subseed(HashMode::Kerl, &self.0, index as usize).unwrap();

        Seed::from_bytes(&subseed)
    }
    pub fn from_bytes(bytes: &[i8]) -> Self {
        let mut seed = [0; 243];

        seed.copy_from_slice(bytes);

        Seed(seed)
    }
    pub fn to_bytes(&self) -> &[i8] {
        &self.0
    }
}
