// mod ed25519;
mod mss_v1;
mod wots_v1;

// TODO: documentation
pub trait PrivateKeyGenerator {
    type PrivateKey;

    fn generate(&self, seed: &[i8], index: usize) -> Self::PrivateKey;
}

// TODO: documentation
pub trait PrivateKey {
    type PublicKey;
    type Signature;

    fn generate_public_key(&self) -> Self::PublicKey;
    // TODO: Why mut ?
    fn sign(&mut self, message: &[i8]) -> Self::Signature;
}

// TODO: documentation
pub trait PublicKey {
    type Signature;

    fn verify(&self, message: &[i8], signature: &Self::Signature) -> bool;
    // TODO: FROM/INTO instead ?
    fn to_bytes(&self) -> &[i8];
}

// TODO: documentation
pub trait Signature {
    fn size(&self) -> usize;
    // TODO: FROM/INTO instead ?
    fn to_bytes(&self) -> &[i8];
}

// TODO: documentation
pub trait RecoverableSignature {
    type PublicKey;

    fn recover_public_key(&self, message: &[i8]) -> Self::PublicKey;
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