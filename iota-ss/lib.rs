use iota_crypto::Sponge;

mod wots_v1;
// mod mss_v1;

// TODO: documentation
pub trait PrivateKeyGenerator<S: Sponge> {
    type PrivateKey;

    fn generate(&self, seed: &[i8], index: usize, sponge: S) -> Self::PrivateKey;
}

// TODO: documentation
pub trait PrivateKey<S: Sponge> {
    type PublicKey;
    type Signature;

    fn generate_public_key(&self, sponge: S) -> Self::PublicKey;
    // TODO: Why mut ?
    fn sign(&mut self, message: &[i8], sponge: S) -> Self::Signature;
}

// TODO: documentation
pub trait PublicKey<S: Sponge> {
    type Signature;

    fn verify(&self, message: &[i8], signature: &Self::Signature, sponge: S) -> bool;
    // TODO: FROM/INTO instead ?
    fn key(&self) -> &[i8];
}

// TODO: documentation
pub trait Signature {
    fn size(&self) -> usize;
}

// TODO: documentation
pub trait RecoverableSignature<S: Sponge> {
    type PublicKey;

    fn recover_public_key(&self, message: &[i8], sponge: S) -> Self::PublicKey;
}

// TODO: remove
fn all_equal(xs: &[i8], ys: &[i8]) -> bool {
    for (x, y) in xs.iter().zip(ys.iter()) {
        if x != y {
            return false;
        }
    }

    true
}
