// TODO clean use
use super::*;
use iota_crypto::{subseed, HashMode, Sponge};
use std::marker::PhantomData;

// TODO state as Vec<i8> ?
// TODO constants

#[derive(Default)]
pub struct WotsV1PrivateKeyGeneratorBuilder<S> {
    #[allow(dead_code)] // TODO
    security_level: Option<u8>,
    _sponge: PhantomData<S>,
}

#[derive(Default, Debug)]
pub struct WotsV1PrivateKeyGenerator<S> {
    security_level: u8,
    _sponge: PhantomData<S>,
}

pub struct WotsV1PrivateKey<S> {
    state: Vec<i8>,
    _sponge: PhantomData<S>,
}

pub struct WotsV1PublicKey<S> {
    state: Vec<i8>,
    _sponge: PhantomData<S>,
}

pub struct WotsV1Signature<S> {
    state: Vec<i8>,
    _sponge: PhantomData<S>,
}

impl<S: Sponge> WotsV1PrivateKeyGeneratorBuilder<S> {
    #[allow(dead_code)] // TODO
    pub fn security_level(&mut self, security_level: u8) -> &mut Self {
        self.security_level = Some(security_level);
        self
    }

    #[allow(dead_code)] // TODO
    pub fn build(&mut self) -> Result<WotsV1PrivateKeyGenerator<S>, String> {
        match self.security_level {
            Some(security_level) => match security_level {
                1 | 2 | 3 => Ok(WotsV1PrivateKeyGenerator {
                    security_level: security_level,
                    _sponge: PhantomData,
                }),
                _ => Err("Invalid security level, possible values are 1, 2 or 3".to_owned()),
            },
            None => Err("Security level has not been set".to_owned()),
        }
    }
}

impl<S: Sponge> crate::PrivateKeyGenerator for WotsV1PrivateKeyGenerator<S> {
    type PrivateKey = WotsV1PrivateKey<S>;

    // TODO validate seed + tests
    // TODO type of index ?
    fn generate(&self, seed: &[i8], index: usize) -> Self::PrivateKey {
        let mut sponge = S::default();
        // TODO replace with custom impl
        let subseed = subseed(HashMode::Kerl, &seed, index).unwrap();
        let mut state = vec![0; self.security_level as usize * 6561];

        sponge.absorb(&subseed).unwrap();

        for s in 0..self.security_level {
            sponge
                .squeeze(&mut state[s as usize * 6561..(s as usize + 1) * 6561])
                .unwrap();
        }

        sponge.reset();

        Self::PrivateKey {
            state: state,
            _sponge: PhantomData,
        }
    }
}

impl<S: Sponge> crate::PrivateKey for WotsV1PrivateKey<S> {
    type PublicKey = WotsV1PublicKey<S>;
    type Signature = WotsV1Signature<S>;

    fn generate_public_key(&self) -> Self::PublicKey {
        let mut sponge = S::default();
        let mut hashed_private_key = self.state.clone();
        let mut digests = vec![0; (self.state.len() / 6561) * 243];
        let mut hash = vec![0; 243];

        for chunk in hashed_private_key.chunks_mut(243) {
            for _ in 0..26 {
                sponge.absorb(chunk).unwrap();
                sponge.squeeze(chunk).unwrap();
                sponge.reset();
            }
        }

        for (i, chunk) in hashed_private_key.chunks(6561).enumerate() {
            sponge.absorb(chunk).unwrap();
            sponge
                .squeeze(&mut digests[i * 243..(i + 1) * 243])
                .unwrap();
            sponge.reset();
        }

        sponge.absorb(&digests).unwrap();
        sponge.squeeze(&mut hash).unwrap();
        sponge.reset();

        Self::PublicKey {
            state: hash,
            _sponge: PhantomData,
        }
    }

    // TODO: enforce hash size ?
    fn sign(&mut self, message: &[i8]) -> Self::Signature {
        let mut sponge = S::default();
        let mut signature = self.state.clone();

        for (i, chunk) in signature.chunks_mut(243).enumerate() {
            let val = message[i * 3] + message[i * 3 + 1] * 3 + message[i * 3 + 2] * 9;

            for _ in 0..(13 - val) {
                sponge.absorb(chunk).unwrap();
                sponge.squeeze(chunk).unwrap();
                sponge.reset();
            }
        }

        Self::Signature {
            state: signature,
            _sponge: PhantomData,
        }
    }
}

/////////////////////////

impl<S: Sponge> crate::PublicKey for WotsV1PublicKey<S> {
    type Signature = WotsV1Signature<S>;

    // TODO: enforce hash size ?
    fn verify(&self, message: &[i8], signature: &Self::Signature) -> bool {
        all_equal(&signature.recover_public_key(message).state, &self.state)
    }

    fn to_bytes(&self) -> &[i8] {
        &self.state
    }
}

impl<S: Sponge> WotsV1Signature<S> {
    #[allow(dead_code)] // TODO
    pub fn new(state: &[i8]) -> Self {
        // TODO check size
        Self {
            state: state.to_vec(),
            _sponge: PhantomData,
        }
    }
}

// TODO default impl ?
impl<S: Sponge> crate::Signature for WotsV1Signature<S> {
    fn size(&self) -> usize {
        self.state.len()
    }
    fn to_bytes(&self) -> &[i8] {
        &self.state
    }
}

impl<S: Sponge> crate::RecoverableSignature for WotsV1Signature<S> {
    type PublicKey = WotsV1PublicKey<S>;

    fn recover_public_key(&self, message: &[i8]) -> Self::PublicKey {
        let mut sponge = S::default();
        let mut hash = [0; 243];
        let mut state = self.state.clone();
        let mut digests = Vec::new();

        for (i, chunk) in state.chunks_mut(243).enumerate() {
            let val = message[i * 3] + message[i * 3 + 1] * 3 + message[i * 3 + 2] * 9;

            for _ in 0..(val - -13) {
                sponge.absorb(chunk).unwrap();
                sponge.squeeze(chunk).unwrap();
                sponge.reset();
            }
        }

        for chunk in state.chunks_mut(6561) {
            sponge.absorb(&chunk).unwrap();
            sponge.squeeze(&mut hash).unwrap();
            sponge.reset();
            digests.extend_from_slice(&hash);
        }

        sponge.absorb(&digests).unwrap();
        sponge.squeeze(&mut hash).unwrap();
        sponge.reset();

        Self::PublicKey {
            state: hash.to_vec(),
            _sponge: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use iota_conversion::Trinary;
    use iota_crypto::{Curl, Kerl};
    const SEED: &str =
        "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

    #[test]
    fn wots_v1_generator_missing_security_level_test() {
        assert_eq!(
            WotsV1PrivateKeyGeneratorBuilder::<Kerl>::default()
                .build()
                .unwrap_err(),
            "Security level has not been set"
        );
    }

    #[test]
    fn wots_v1_generator_invalid_security_level_test() {
        assert_eq!(
            WotsV1PrivateKeyGeneratorBuilder::<Kerl>::default()
                .security_level(0)
                .build()
                .unwrap_err(),
            "Invalid security level, possible values are 1, 2 or 3"
        );
        assert_eq!(
            WotsV1PrivateKeyGeneratorBuilder::<Kerl>::default()
                .security_level(4)
                .build()
                .unwrap_err(),
            "Invalid security level, possible values are 1, 2 or 3"
        );
    }

    #[test]
    fn wots_v1_generator_valid_test() {
        assert_eq!(
            WotsV1PrivateKeyGeneratorBuilder::<Kerl>::default()
                .security_level(1)
                .build()
                .is_ok(),
            true
        );
        assert_eq!(
            WotsV1PrivateKeyGeneratorBuilder::<Kerl>::default()
                .security_level(2)
                .build()
                .is_ok(),
            true
        );
        assert_eq!(
            WotsV1PrivateKeyGeneratorBuilder::<Kerl>::default()
                .security_level(3)
                .build()
                .is_ok(),
            true
        );
    }

    fn wots_v1_generic_complete_test<S: Sponge>() {
        let seed_trits = &SEED.trits();

        for security in 1..4 {
            for index in 0..5 {
                let private_key_generator = WotsV1PrivateKeyGeneratorBuilder::<S>::default()
                    .security_level(security)
                    .build()
                    .unwrap();
                // TODO mut ?
                let mut private_key = private_key_generator.generate(&seed_trits, index);
                let public_key = private_key.generate_public_key();
                let bytes = public_key.to_bytes();
                // println!("{:?}", public_key.to_bytes().trytes());
                let signature = private_key.sign(seed_trits);
                let recovered_public_key = signature.recover_public_key(seed_trits);
                assert!(all_equal(
                    public_key.to_bytes(),
                    recovered_public_key.to_bytes()
                ));
                let valid = public_key.verify(seed_trits, &signature);
                assert!(valid);
            }
        }
    }

    // #[test]
    // fn wots_v1_kerl_complete_test() {
    //     wots_v1_generic_complete_test::<Kerl>();
    // }
    // #[test]
    // fn wots_v1_curl_complete_test() {
    //     wots_v1_generic_complete_test::<Curl>();
    // }
}
