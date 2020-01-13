// TODO Replace with bee impl when available
use iota_crypto::Sponge;
// TODO ?
use super::*;

// TODO Replace constants

/// The minimum value a trit can have
pub const MIN_TRIT_VALUE: i8 = -1;
/// The maximum value a trit can have
pub const MAX_TRIT_VALUE: i8 = 1;

// TODO: documentation
pub struct Seed([i8; 243]);

#[derive(Debug, PartialEq)]
// TODO: documentation
pub enum SeedError {
    InvalidSeedError,
}

// TODO: documentation
impl Seed {
    // TODO: documentation
    // TODO: tests
    pub fn subseed<S: Sponge + Default>(&self, index: u64) -> Self {
        let mut sponge = S::default();
        let mut subseed_preimage = self.0.to_vec();
        let mut subseed = [0; 243];

        for _ in 0..index {
            for trit in &mut subseed_preimage {
                *trit += 1;
                if *trit > MAX_TRIT_VALUE {
                    *trit = MIN_TRIT_VALUE;
                } else {
                    break;
                }
            }
        }

        sponge.absorb(&subseed_preimage).unwrap();
        sponge.squeeze(&mut subseed).unwrap();
        sponge.reset();

        Self::from_bytes_unchecked(&subseed)
    }

    // TODO: documentation
    // TODO: tests
    pub fn from_bytes(bytes: &[i8]) -> Result<Self, SeedError> {
        for byte in bytes {
            match byte {
                -1 | 0 | 1 => continue,
                _ => return Err(SeedError::InvalidSeedError),
            }
        }

        Ok(Self::from_bytes_unchecked(bytes))
    }

    // TODO: documentation
    // TODO: tests
    fn from_bytes_unchecked(bytes: &[i8]) -> Self {
        let mut seed = [0; 243];

        seed.copy_from_slice(bytes);

        Seed(seed)
    }

    // TODO: documentation
    // TODO: tests
    pub fn to_bytes(&self) -> &[i8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    // TODO needed ?
    use super::*;
    // TODO remove
    use iota_conversion::Trinary;
    // TODO remove
    use iota_crypto::{Curl, Kerl};

    const SEED: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9";

    fn seed_subseed_generic_test<S: Sponge + Default>(seed_string: &str, subseed_strings: &[&str]) {
        let seed = Seed::from_bytes(&seed_string.trits()).unwrap();

        for (i, subseed_string) in subseed_strings.iter().enumerate() {
            let subseed = seed.subseed::<S>(i as u64);

            assert!(slice_eq(subseed.to_bytes(), &subseed_string.trits()));
        }
    }

    #[test]
    fn seed_subseed_curl81_test() {
        seed_subseed_generic_test::<Curl>(
            SEED,
            &[
                "PKKJZREHPYHNIBWAPYEXHXEAFZCI99UWZNKBOCCECFTDUXG9YGYDAGRLUBJVKMYNWPRCPYENACHOYSHJO",
                "EM9CGOOPJNDODXNHATOQTKLPV9SCMMDHMZIBQUZJCUBCPVAGP9AIEAKYAXOYTEUXRKZACVXRHGWNW9TNC",
                "RRJNNVVOJEGYSXWUDUBVZSYSSWXLIAYUPIEAFSWUDDDEFCTRBBTMODUSXASEONBJOAREKLARUOUDHWKZF",
                "XNW9XBGHM9ZVPSV9BXMFRB9MKODAXKEPPSTGX9PFEDNTVZPJUQGGQ9JCOZRMABQQNQBAURFKVJUZTYUQV",
                "MMJRVEANOJUYWEGF9NNJUJVVZTGXKRWGXGVXRNRNDHPNMWVDGRHRH9FGODYVYWSVABUYZEVCJXUZZLYQB",
                "PCOAKZFKIWGDTTQSBWZABUCIIEFADQQFHCJYTOFVEURSEQZHQCORMMBDKVRGNATYINDDWMGZBUGKLUZOR",
                "CMDZYS9GCHCFFOHPMIPDKRASMFSUXJPDWUWYNMHLHBXUPUPPLEKCSBWSKUG9TKTCRXHJHIA9BVWKAGEHG",
                "TAIMONWQMIXTMCGYMBGIDOZF9FOUPBIEIYYPQZYNMORHGNNLAPWCSMAKVLREZLGDS9XGTXNYYYQYUWRPM",
                "VTKERDSFSJGLZF9UJHXJKFXIXFYSPNVSBHBMAZXXCJCBJHLDEEDMNPBRFJ9PCLNNSZYFLMRJQAYRMHVWL",
                "YVGEVYOLICOIDRYBHP99JQZZJKVYZDPHFCQKJAN9BCEZCMWIEUJIRZWNAZNUMNDMT9JUCDGBSGXDUYQJC",
            ],
        );
    }

    // TODO Will be activated when Curl27 is a proper type
    // #[test]
    // fn seed_subseed_curl27_test() {
    //     seed_subseed_generic_test::<Curl>(
    //         SEED,
    //         &[
    //             "ITTFAEIWTRSFQGZGLGUMLUTHFXYSCLXTFYMGVTTDSNNWFUCKBRPSOBERNLXIYCNCEBKUV9QIXI9BDCKSM",
    //             "W9YWLOQQJMENWCDBLBKYBNJJDGFKFBGYEBSIBPKUAGNIV9TJWRRAQPAEKBLIYVLGHPIIDYQYP9QNSPFTY",
    //             "X9WMLHFSJYEWNLVSGTVGWMAPNUSFMXQPTMCPUML9RCMAJQVUYMTJJHKT9HO9NSNGAEMKGDBHE9KZNMBPZ",
    //             "YNTUYQNJWJPK99YE9NOMGNKF9YRBJX9EH9UZWLMISXQRQLLZRKHFOPTW9PIERIPXK9ZDUPLSLZOEFUWXF",
    //             "URBRFVWBAGHM9WTWSZZLRBMNGMNNRJRBGBLDEBBSZTGMWELW9JHXFSFNLRKPI9MLYELEZEDYIPKGE9CRO",
    //             "XMGTGBZBINHC9ZPKRBHZFLUP9CEWULNCMVUAVVUXRDHU9OILDOORKPLRIWZQDNRFGSWMJAVYZWGDXMZNW",
    //             "KFEGWPGWLAHWQXGCHKHDDVAZEISLYMGQLRRZBCJWXWKK9JIJKHXRDV9NMYIFTAGKXU9GLACAQUCXBLMH9",
    //             "BMUAOOZBHPUOVHRWPX9KWUCZSXWXWPMKOMGNAZOXLDMAHBBVMDLXQ9IVPOPIOFPWHZSMRKBOBLCUEVUXX",
    //             "GLVXLLOFYERJWBECYRXVPCFXK9GUDCHBEZYMTPMUDOYEQCIAPCAACKSOL9ADEGSTBQRIBJIWTCJYVUIRW",
    //             "FOPHLVKCYHZLLCCOUWBPMQQAWHVRBGJBKQGPQXOTOEWTOCVZQCJXDCBLG9SEZBUVYPIIRTTP9CJPXWKKW",
    //         ],
    //     );
    // }

    #[test]
    fn seed_subseed_kerl_test() {
        seed_subseed_generic_test::<Kerl>(
            SEED,
            &[
                "APSNZAPLANAGSXGZMZYCSXROJ9KUX9HVOPODQHMWNJOCGBKRIOOQKYGPFAIQBYNIODMIWMFKJGKRWFFPY",
                "PXQMW9VMXGYTEPYPIASGPQ9CAQUQWNSUIIVHFIEAB9C9DHNNCWSNJKSBEAKYIBCYOZDDTQANEKPGJPVIY",
                "ZUJWIFUVFGOGDNMTFDVZGTWVCBVIK9XQQDQEKJSKBXNGLFLLIPTVUHHPCPKNMBFMATPYJVOH9QTEVOYTW",
                "OCHUZGFIX9VXXMBJXPKAPZHXIOCLAEKREMCKQIYQPXQQLRTOEUQRCZIYVSLUTJQGISGDRDSCERBOEEI9C",
                "GWTMVQWHHCYFXVHGUYYZHUNXICJLMSOZVBAZOIZIWGBRAXMFDUBLP9NVIFEFFRARYIHNGPEBLNUECABKW",
                "XWIYCHCVZEXOPXCQEJUGPMGVAIYBULVHWDD9YWMAZNJQEISHOBMYFHZKCBT9GWCSRQSFURKF9I9ITWEUC",
                "XRBHXHE9IVEDFHQPNNMYOPXOLPXRBSYCGQNMRFKYENRJZLZAVMFLUCWWCNBFPKOSHF9UPMFFEWAWAHJP9",
                "IP9DGBVAPNHHDP9CXOBYRLTYVJCQYUUWNWGNFUSDRKFIIAVPYPQDASDULPJBBEBOQATDHV9PVXYIJFQTA",
                "XSGWTBAECBMTKEHXNYAVSYRPLASPJSHPIWROHRLDFUEKISEMCMXYGRZMPZCEAKZ9UKQBA9LEQFXWEMZPD",
                "JXCAHDZVVCMGIGWJFFVDRFCHKBVAWTSLWIPZYGBECFXJQPDNDYJTEYCBHSRPDMPFEPWZUMDEIPIBW9SI9",
            ],
        );
    }

    #[test]
    fn seed_to_bytes_from_bytes_test() {
        let seed = Seed::from_bytes(&SEED.trits()).unwrap();

        for i in 0..10 {
            let subseed_1 = seed.subseed::<Kerl>(i as u64);
            let subseed_2 = Seed::from_bytes(subseed_1.to_bytes()).unwrap();

            assert!(slice_eq(subseed_1.to_bytes(), subseed_2.to_bytes()));
        }
    }

    #[test]
    fn seed_from_bytes_invalid_test() {
        let seed_trits = &mut SEED.trits();

        seed_trits[100] = 42;

        match Seed::from_bytes(&seed_trits) {
            Ok(_) => unreachable!(),
            Err(err) => assert_eq!(err, SeedError::InvalidSeedError),
        }
    }
}
