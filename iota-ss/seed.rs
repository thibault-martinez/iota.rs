pub struct Seed([i8; 243]);

impl Seed {
    pub fn from_bytes(bytes: &[i8]) -> Self {
        let mut seed = [0; 243];

        seed.copy_from_slice(bytes);

        Seed(seed)
    }
    pub fn to_bytes(&self) -> &[i8] {
        &self.0
    }
}
