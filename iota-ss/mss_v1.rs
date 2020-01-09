use super::*;
use iota_conversion::Trinary;
use iota_crypto::Sponge;
use std::marker::PhantomData;
use wots_v1::*;

#[derive(Default)]
pub struct MssV1PrivateKeyGeneratorBuilder<S, G> {
    #[allow(dead_code)] // TODO
    depth: Option<usize>,
    #[allow(dead_code)] // TODO
    generator: Option<G>,
    _sponge: PhantomData<S>,
}

pub struct MssV1PrivateKeyGenerator<S, G> {
    depth: usize,
    generator: G,
    _sponge: PhantomData<S>,
}

pub struct MssV1PrivateKey<S, K> {
    depth: usize,
    index: usize,
    keys: Vec<K>,
    tree: Vec<i8>,
    _sponge: PhantomData<S>,
}

pub struct MssV1PublicKey<S, K> {
    state: Vec<i8>,
    depth: usize,
    _sponge: PhantomData<S>,
    _key: PhantomData<K>,
}

pub struct MssV1Signature<S> {
    state: Vec<i8>,
    index: usize,
    _sponge: PhantomData<S>,
}

impl<S, G> MssV1PrivateKeyGeneratorBuilder<S, G>
where
    S: Sponge,
    G: PrivateKeyGenerator,
{
    #[allow(dead_code)] // TODO
    pub fn depth(&mut self, depth: usize) -> &mut Self {
        self.depth.replace(depth);
        self
    }

    #[allow(dead_code)] // TODO
    pub fn generator(&mut self, generator: G) -> &mut Self {
        self.generator.replace(generator);
        self
    }

    #[allow(dead_code)] // TODO
    pub fn build(&mut self) -> MssV1PrivateKeyGenerator<S, G> {
        MssV1PrivateKeyGenerator {
            depth: self.depth.unwrap(),
            // TODO: WHAT
            generator: self.generator.take().unwrap(),
            _sponge: PhantomData,
        }
    }
}

impl<S, G> crate::PrivateKeyGenerator for MssV1PrivateKeyGenerator<S, G>
where
    S: Sponge,
    G: PrivateKeyGenerator,
    <G as PrivateKeyGenerator>::PrivateKey: PrivateKey,
    <<G as PrivateKeyGenerator>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
{
    type PrivateKey = MssV1PrivateKey<S, G::PrivateKey>;

    fn generate(&self, seed: &[i8], _: usize) -> Self::PrivateKey {
        let mut sponge = S::default();
        let mut keys = Vec::new();
        let mut tree = vec![0; ((1 << self.depth) - 1) * 243];

        // TODO: subseed
        // TODO: reserve ?

        for key_index in 0..(1 << (self.depth - 1)) {
            let ots_private_key = self.generator.generate(seed, key_index);
            let ots_public_key = ots_private_key.generate_public_key();
            let tree_index = (1 << (self.depth - 1)) + key_index - 1;

            keys.push(ots_private_key);
            tree[tree_index * 243..(tree_index + 1) * 243]
                .copy_from_slice(ots_public_key.to_bytes());
        }

        for depth in (0..self.depth - 1).rev() {
            for i in 0..(1 << depth) {
                let index = (1 << depth) + i - 1;
                let left_index = index * 2 + 1;
                let right_index = left_index + 1;
                sponge
                    .absorb(&tree[left_index * 243..(left_index + 1) * 243])
                    .unwrap();
                sponge
                    .absorb(&tree[right_index * 243..(right_index + 1) * 243])
                    .unwrap();
                sponge
                    .squeeze(&mut tree[index * 243..(index + 1) * 243])
                    .unwrap();
                sponge.reset();
            }
        }

        MssV1PrivateKey {
            depth: self.depth,
            index: 0,
            keys: keys,
            tree: tree,
            _sponge: PhantomData,
        }
    }
}

impl<S, K> crate::PrivateKey for MssV1PrivateKey<S, K>
where
    S: Sponge,
    K: PrivateKey,
    <K as PrivateKey>::PublicKey: PublicKey,
    <K as PrivateKey>::Signature: Signature,
{
    type PublicKey = MssV1PublicKey<S, K::PublicKey>;
    type Signature = MssV1Signature<S>;

    fn generate_public_key(&self) -> Self::PublicKey {
        // TODO return or generate ?
        Self::PublicKey::new(&self.tree[0..243], self.depth)
    }

    fn sign(&mut self, message: &[i8]) -> Self::Signature {
        let ots_private_key = &mut self.keys[self.index];
        let ots_signature = ots_private_key.sign(message);
        let mut state = vec![0; ots_signature.size() + 6561];
        let mut tree_index = (1 << (self.depth - 1)) + self.index - 1;
        let mut sibling_index;
        let mut i = 0;

        // TODO PAD TO 6561
        state[0..ots_signature.size()].copy_from_slice(ots_signature.to_bytes());

        while tree_index != 0 {
            if tree_index % 2 != 0 {
                sibling_index = tree_index + 1;
                tree_index = tree_index / 2;
            } else {
                sibling_index = tree_index - 1;
                tree_index = (tree_index - 1) / 2;
            }

            state[ots_signature.size() + i * 243..ots_signature.size() + (i + 1) * 243]
                .copy_from_slice(&self.tree[sibling_index * 243..(sibling_index + 1) * 243]);
            i = i + 1;
        }

        self.index = self.index + 1;

        MssV1Signature::from_bytes(&state).index(self.index - 1)
    }
}

impl<S, K> MssV1PublicKey<S, K>
where
    S: Sponge,
    K: PublicKey,
{
    pub fn new(state: &[i8], depth: usize) -> Self {
        Self {
            state: state.to_vec(),
            depth: depth,
            _sponge: PhantomData,
            _key: PhantomData,
        }
    }
}

impl<S, K> crate::PublicKey for MssV1PublicKey<S, K>
where
    S: Sponge,
    K: PublicKey,
    <K as PublicKey>::Signature: Signature + RecoverableSignature,
    <<K as PublicKey>::Signature as RecoverableSignature>::PublicKey: PublicKey,
{
    type Signature = MssV1Signature<S>;

    fn verify(&self, message: &[i8], signature: &Self::Signature) -> bool {
        let mut sponge = S::default();
        let ots_signature = K::Signature::from_bytes(
            &signature.state[0..((signature.state.len() / 6561) - 1) * 6561],
        );
        let siblings = &signature.state.chunks(6561).last().unwrap();
        // let siblings = &signature.state[((signature.state.len() / 6561) - 1) * 6561..];
        let ots_public_key = ots_signature.recover_public_key(message);
        let mut hash = [0; 243];

        hash.copy_from_slice(ots_public_key.to_bytes());

        let mut j = 1;
        for (i, sibling) in siblings.chunks(243).enumerate() {
            if self.depth - 1 == i {
                break;
            }

            if signature.index & j != 0 {
                sponge.absorb(sibling).unwrap();
                sponge.absorb(&hash).unwrap();
            } else {
                sponge.absorb(&hash).unwrap();
                sponge.absorb(sibling).unwrap();
            }
            sponge.squeeze(&mut hash).unwrap();
            sponge.reset();

            j <<= 1;
        }

        all_equal(&hash, &self.state)
    }

    fn to_bytes(&self) -> &[i8] {
        &self.state
    }
}

impl<S: Sponge> MssV1Signature<S> {
    pub fn index(mut self, index: usize) -> Self {
        self.index = index;
        self
    }
}

// TODO default impl ?
impl<S: Sponge> crate::Signature for MssV1Signature<S> {
    fn size(&self) -> usize {
        self.state.len()
    }
    fn from_bytes(bytes: &[i8]) -> Self {
        Self {
            state: bytes.to_vec(),
            index: 0,
            _sponge: PhantomData,
        }
    }
    fn to_bytes(&self) -> &[i8] {
        &self.state
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use iota_conversion::Trinary;
    use iota_crypto::{Curl, Kerl};

    #[test]
    fn mss_v1_kerl_sec_3_test() {
        const PUBLIC_KEY: &str =
            "IDSWNWLGPFLAQADAEYUINRS9MBEMCYARHXHVSBOZDOBHPIPNVYUFFTQLNYGDZKKTEBHYOQXVQVHXBGXH9";
        const HASH: &str =
            "NNZLXQKRAQBEUKNGVTKAHIIJUGSNNNNCASGGPNBJHKGTH9EGEAJZPKYL9WTNVYHFKDSQYERI9AYUFHYB9";
        const DEPTH: usize = 8;
        const INDEX: usize = 4;
        const SIGNATURE: &str = "PGCWBHJEXWRBTMSIWGIDRXWNFTYGTTXPEAHWEFXKXGH9VA9JARHWUHUYEOOYENBHKNF9WLIFOH9HGQJVDOMSJ9XWTOVUDVDJBDCSKOYHM9QQFEHHMGUMXNBTWVBDCBBCAGEAKCWMHUUGBIXURKNMUSQTWQVRYGQAS9SJFAXLWXALFRWJUFNS9LDMOVUFVPHBZPDLYD9DKSWDY9TUOCCQQM9JXMTJRLRWEUBAQLJCOYJTASG9QBXKKGDTRWHQGATGSWDEEZUU9EJQACNU9CHIUIQRGLWGHFF9ABGE9SGYFRANEOZJLRHCYRWI9IT9FGYMKYGYMYDWRUOFMDGIR9EYNMIHWDBAJRBBYBBRL9YAWDGWUVGWLMKKVJQAAFVOTYMQNBAGZZFLVP9HHENEFZC9DPLOABBV9FKJCYJ9OH9BTBNEQTJSJICBWHUQVHSOISVIIRCUUEVJLJNLZUGBQUDXTUNS9HQYXHNAQWTQIWYYERXQKFZBEJGRDJJLZUNNTZDDEIYZBFWFF9ENLLS9TNPFXJARPBMYFOAQEP9GYBRNAAFOPBRSTOKPCUZQLQAMNWHVKZHVPHDLDRORAUTLQKZNPTIAERPPMDD99WTVZGGJWCLVOWXIJHEKAKINBSQQEBFIWTFIZINBGEOI9IRNCVY9QBQECCDCTOTAOEUCLJCM9MSNXJMHHNFGIBLT9KDMASEGKFPOAQQ9ZFXUSRCNZTGPOXHDWTGUAL9JYLMOOKLWCTNC9UKMEFSBZSV9DXBYTOHNMUEAJTHJNVBMCYIEDOICPHROXUVMA9UREPMUCPBPJDELBJEBZYOR9D9TKLEQ9G9GXRXPSDBDZXTTUAKJSAIRCFTCTQFRLUDQBPRXIYCDAXCUOZIGZKCZRWXSLLZLAJTCDCEUIPYASTQOLMSEYEIMVBEGKOBAPYJZMHPGSXPFUGYLWGZZPBVCBKZBBCSPGEGBZAJQUCHSMSNW9HFEDYHOJAUJBJSKYFSMTWTTF9HGERJZIYMMLYBRVLJLCQFMXNXUPILZSERKSNMVTLMSKJZRIAVN9IRIBNBYLU9MW9EVPBEESKHOWTETUTZRHKM9BKWRFLZGIREKNC9KSKHBPRLCHCIEXPZEXILOYXBOPFLMWHSCN9JWUGZPWCWFSBNFFOKBQKPIJSUXNN9UZQQDKKEWZQDRXPDYQJHPBZJTOLQEFDWCKFPQELRFWTVBZVVZTAXDRQIGJVFNBM9TZCKRE9WDFTFVPV9RYIIUDIOIPYUG9UZCSVTJCLLSAFQJKPZGTTQLQYIAYGWJUMARKHSXKGCOXKKBBVUSPZZETMAGQBPAH9WUXLUJQGZKQUYUWMPCFCHMNGNQL9XNMFVEKMIPVTBXLBNKGDFVLLHNAREIC9HLZHNZYMBJHWAGESNDANOLPXHE9CVDQPVJBQHLTZLOEBSHZPMTAMLDTTNVYJWGOXCSGUEFIMLY9CNCLJSAUDLMRRFXSESMPMXDZRVTHZGLKJCHUYHNBNGBUOPISW9TAGGJY9FUQVLX9BRDJGRQ9BHCMLCZPJZFLCFBPDCIHAGJNNT9OKHSRBHPPNPNFFKYBUTXKUOTHH9ASBNDCYTUQOJWMYUDFDGBRPRSKKHQIOERZPWZWWZQLSORYDOU9QV9UW9NZFVBGUCFBNGGJSPYDVPXO9ZBDR9WYJIYDRNKIJQTJCJOOAEQT9OTADGBDAZACMTWKWFDMSS9BGLSNKZVFTKDQDNSGBACUVFCQBJXMVNPIY9RUR9IUWTDUJFQWTJTWUQYNSSZB9QWGDPXJWNUSKWUYBVIC9BSMNHQVKXSOUSJUBZDOUOMEXAX9KDEWZSWRJZNQDBCXQZFEZJMCMPMOA9ZVCHLQDUCMFDNIFCHOSIJIPCKTFOPVUTZCTZWAWBIGMQRRQGCNQYMAYZXDPXBFAKVDEPMJUXPMRLEMXUMFNSMGHZ9MSEWKYPWOUPSIOZTEJYUFLRVHXCMCTQX9IVNKMTQYQCHW9VSSSXJBOJPBGBIDIIKNRUQBDZUSOMOSWRZCGBLZZWNJQFRUWPBPXHMPVGOEZATZSDRLULE9ECFUMNPWELRL9AAJCONHTXMXSSIXNQBCNNLGREGDPRDWBNOVCOJVTKDPVRAYLXMFMZHABVZXZAIKUJGHYGYQWTBIDFHLBCLRASI9MTFFFHLJOYSIOSGPFKPUDYAXVRVXGDERBTZIAEG9UFXMWDGOCMXZSOHSCAPPYKWUJQLXJCIKJOP9NJJXRLCDEBUWMAKTNLVSJEZNTDVRPXWWKEZXIKBWEQRIR9RDIKXNPTIKNQWWOMIAECGNCYWY9LDSZQBVAOIJFWBYFYKXPLWPNWGDVMOVTNYMH9ZLYUBXPCOWOHJEHBTWEX9XNBWKOTGKWYCTIIKTZSUJPPXNXZOS9USOUIPOAZFWZRMQKKOWSSRMMTIVYQHRIODKXAKPH9FSJNQ9ZUEJNUMHPOPINIUZGNAIDBWEDSGPDPXRWLNKCMJCGYQBDWIGULQKYKLPHQQDDHBWNRVEBXJDSBGWSXEJFBYVVNOIOOQOTKLJYVDVRQUZCVKFBPROB9VVSHLAEKEEJLQHHNZDQLNAKEHBVPDSKGNHXTZNA9WUXBTK99SZXZYRHHHGRZIRLRQEVQSGPVHIOPKP9T9AGGJBTFASXWMKAOFUUZYMRHBUXRBZAO9SGMACE9CXLXCQADLITOI9AWXSUXUPAYFVNIMUZAGCJLZGCKX9IFJQKSNAAG9YBZRJBGJFWBSYCYV99GOSLLMSAXJNQWMCCQWBARLWDDRXUYBUIKHTAOGWWXLTZKOCBYIGBKVFCHDAPQIBBMJFPCQMQCWZYAMGWRBTMBJNDCXP9ADBXSUBAROQYODUWKDSXFMPKANYEJYESWNCHVDKCDBCQXXCRRENIIABYT9WUMDWRVRPSLLS99HYAACBKEWJQXXEWMHXFAEPVQD9KTDZFIWTGBLEBWAYAHVRNLGKPHXFNFLSFWRIKX99OTIUQVFYA9YPJAJJEYGXFSINSXDGNPUKPERLCCSCPHU9WKCGNWMCQRXBTWRRXACOVLKPWSHOXKLRIRWBDMEEUJOOALMYZLIWPHSCWXHV9RNHTFAUSPRHZMR9OAJWFWQENFOFCPMVJEPBQAS9LJWDUP9WKFDWOZRREWX9TSNCCDCHNMVBYGCIF9VVVBWRKDRGJNQQLIP9CABUZRISLUJIZTWIEXGDLMBVIFVEUWSDGTRVLGOPTEUOWUY99G9OEKUFIORYCXXQMTSL9MCVUQJWMVTSVSEMXREZHBIETUVNNUACCVFUECTCKWMUUCLXOEY9LQFAYGUKWGFZWXTTVCXVYJYCRCCARSKWMIGBZONSJIAACSNZUFBVBASXEXHXIJEQTEANIDZSREFIUOEVRSKUGFHMNV9ZQDUFBZAXNHZLZTH9YSVRWNEXAZVXPYIPRSNRHNZUJPALZQHUO9QLAS9RX9QBIXMAGIRNM9GUUYOGUBQOXXLKQEZPZMHKNCITFOYBEUKAXHJLRRMMVF9SLJZDGQAM9UXQ9VMVLIHFUVSNLBVVMDLYULLELHMTFTWCNUEXXQFDIJSNWUDWYLWAXEUSVOJFCCCYZFLQNFFRTPOTVVUALPYZCTUSEQOKVHCTZETMDMFSNSNGDTUCEGJYYZTXGRMUZJTWCULIZWUIBOVJAISLCGJ9MFOJIDZROGYYXHEXAIIWOAVEJWXVVQEKZXVIT99LBOIKGZWNX9OPTPLSOQPEAOIRKYIMLXHYLPVPXG9AKFIOFBFEBLASXYENQ9WXIMKILNNJOAJHWODVRBGNCBGWT9BHZZYDPJXQQHSO9CNDSPNZZEIPVIMNAPVCSXTTFGJSRVDYTMIQAKFPUEZAT9AKAQDBMP9FKXLQZUDDSMKVK9ZKVWDAPAINQYCYHOFGOUCFRBLUYB9HGVWJPKQXLXF9JKQJLNMROEGCPFGXUSAIJNQ9YLVCCPUDJNJPNWLMYVDQPQXBTDEWMQVZYWDVKBTVEF9VOKDVHVZDZRWFK9WTMYU9ATRQJSKFDWXNPRDHQAYNGWXYFDKSIHFNA9UGGMVNCDMTZPEFBJAHGHMMDHEQLA9IGVDUGBQHJQORJ9ZWNEUJPVWVFDXKWDWLUHEVE9PYVYSMYPSYU9ZSMACZUAXCSAEJNVHOJGBRFYARSFZMYESXLNQOAB9HOH9VGQJTSAURKCMPYUFWZGEPHP9PUVFNHSCCHVVTGWYHLLVKIZCROMYQIYOCAHPONKRPEGJPKWTNQ9LIKTSHMKPESEZEPJETUUO99JDHXAUJIFEZCJLDGDTKZNLNEUSFYBWXHJILLHILNRXZKYAJDYYPNIJHIYXZ9RJKAGYLEVKVQDAIOCHGEKPQPCZOLSDXNFVFBDVCKKN9ZXJDSXGC9MMLCZGOBGDACJAHCOKJBDSTGANCAKNEVVTKARLTCPFRSGPPFPDIEDMCUEEFOGWUUXXQEPULAIFOEINWPDCMFXOJXCLQITCCMAUUDLGXDJDLVMOFEADOWJDVIXBBSINQMLGXGILLMHWIVHDBDTIHWOEETQZPJOSSWNWJYYGEDGMSNNJUDYTOATBYCACKRICFQALDFLDZGKFKCCLWZIKGWOGMEVKOITUUDCZCBQEDXWYGV9XARB9CKWNLCKVOZBWZAKAMAWNMLVGYDFQOARCUN9CA9YAKIZDBSFZXZRZJABWZLZGGNAXVOHZMXXMTCQZWIMSYYGS9QA9KLXYHLUFEGIFUVLAHKOINTMFMJZFUUWZKRT9GZZGSAWWCFUZUYNJXPWPKKYYZVUBCWSMWZFJEFZHDTLVACXIYPPFYWCFUDHZGTSOJPKNOADZPQPMYCJGSZRKANUOZRGKD9UAFAKUSDDPPPJORELCGTNZZQDBKZYWUBKM9GKGIBOJANBZFQMZKNVMLNZPQFFFVXYYUBHXQPBQZHCCZIP9Y99PIHURWQTJIJMA9L9UQIOMCWJLVCFTRQ9DNOWJKBEAANBCMLXX9DFYVDLVIYWAYPISVVYSMHYHHQMOVHMHLWPDWWMFYBUHNVSDU9BP9CSZVCLU9MEBETEJRNEQ9XPNGRPCMQSRNBZA9HUWBRCLEJEJZYVVFWGY9QMGCLYRVC9YBBKVDQNZDBTJGS9YZOH9XLNQFKPVWHEFPWOWOEPMRVBATFBOZAWIYVTPJMBCCBVSLBZTCXWQNGWLPCYXWHHHVUAAMABPWGIXMPIRPCWMKRPY9VYEGAHSIKDJT9GEXSPKFGUZWJBKRIGQSYUFFIRXWXFENFFHDHYROGHPVFHUXMMQETAHWJGJSVUUV9Z9CPWUTRDE9OYZAJXGXEJONLEUNSACYMXQBIBGELXFULFBU9AISG9IQSPASNHU9OWHILBVGYJAMEYMZOKMNFDBPMMORLENRVUOVZEBETIASNTBOHXUWAPAVJCZZGJUYAPTPREPLJOEW9OTD9DMALQOGUDZAKOYHEFALMNKGCKWECEQMSGDA9VPVHFEMYEVVHC9HVXQKQJABAYEGLFJVDWNCSOOPURHMYPGSWKSDFMCGTSZRYVQAKMATIRRGVIYHHTXATCXQHEJWOJMEVDXV9QCRGTGYQYDWCEJMRGSCHZOTERVNBDNCKZWUDZPXOOWDUXZ9GYQKNVUNZKUGOMPWDWGTTXGJIQ9XUOGKCEWMDKFYXIBUSAUGYJYJYUVEMAIKEXPLEBKMUEBECVIGYXJUQLISTYSXLQ9RNIHWVDWLXCXCYCUK9TAGBBFXCIYLOPRKZCKTDSMQVCUXU9WQCQ9GKPCN9PKUQYUAJDIAJKNTDWJH9PPGYGN9PVRKRMUBZZCW9SVGPLRRZDRADYMWGXWMWAFWLVGKVRI9WQGZIUHOXQJUCIBXQBB9VZNXDKT9ONCYCFZMTNHPJMJPUJZDWSPQLRAZNGV9QTKNYBZDSUQIPLVSQZHEOLUPFPRAXRHJSXADGQDBEVNPMVEC9TCYAGZSZASMGJLRZYWOKLUZULZZXTCBLZUQND9VPFJJHEDLOTRINEBFMPWSGDHKEOQACITVNPNTXKKQWCZLC9PYUHGSQEATWZRGZPELGOWUYVIHDYQPGJXAL9O9XNODA9GLDBYXXVPURQTQSWXZRWYRHOIQUUCRBZYTKSGSOMAXHRZSTUP9HRIMHNIBQJFCUBIWHIXHUWXATPHSVIFXMWJKKOBFMICGJGFJKLDPCVLFGHILHLIKFSDOPYFHEWVPGQISJQHKV9HBLKWX9JGDSUZWBUTPOHAINLBFNMUTEQ9NFFBKFSCZELK9XIXFTDZFQIYVIEULYEOEWMQWHZJZQR9SDBIOCXEPHXMCWCQSFCSDWY9QTJRDJDRFVJUCPBMRHIADTC9KZNDNUVDYSKQEDUX9BLFFNPNS9OCQHCHNMDYBRTOJNWAGWKLSTEAQHYCYEEYPKRUFPTWEWXMOQE9UKZYXHBFBHOHNDRYVTW9JKBIUZFF9OOFKFHPVCFYAEDUYSRMKKDCEOGNIJQYCYKVVUHUZRWMJFHVGTYFVFNXOIRXXZHBGMFQJEBUPSBKLAY9QTJZNIWMHYIQLVWF9TQMM9ZEDDKCCPEKDMJCJCKGDICZKINBYZGBCEUXAFMGWZTF9TUMVAEELCKMBESECIMAAVDRJWJBYEWDVB9HPVWNYUPUMOEFJETRHKD9N9KOAZRBFOQCXXMUBFPAVWZEEJ9FPOTLMLEMZ9EEJWKYMHDVXYFTKLRRCHWDWSCJTODJWIHWMFUTKGFLPDTFEYGCFAATPX9MTX9YCFWXWRMLZBNAAFOZMYUQZ9JYUXFQUXI9XKYVCTL9BIKJJPSVILKNDOHZWQQBG9QINKZPVG9EDU9WFVUZZQXZTCWWLHWIFQW9ECOJVGNYZFPXQAMKTVPEMAVLBQKUCBCQVFQFBDKATSOZGOQZJUKMOYZYHKECFQCR9NFEYCLFKFUMTSFZVYZYBFZQC9SAYIXTIPQJSKHTFEZ9NKPOYGRSOXROPRPGEJH9JPTLSI9VWQODQQZMAABCN9NNDUNO9WGWBSHLOXMTFWNTAFXAAMXBS9IHOPEPBRIBGDLKFCTEPSQWOZVKWJKZNGSTVYVJYKPCBUSIOY9FRPXCVBPCFMSKYDDXKYJJWMXMXDPZNAUNCKRCWDIHWGZUMUPMRBZKHSXEZSWWLXXVLLQBSVJFQWNSJZIA999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999";

        let mss_v1_public_key =
            MssV1PublicKey::<Kerl, WotsV1PublicKey<Kerl>>::new(&PUBLIC_KEY.trits(), DEPTH);
        let mss_v1_signature = MssV1Signature::<Kerl>::from_bytes(&SIGNATURE.trits()).index(INDEX);
        let mss_v1_valid = mss_v1_public_key.verify(&HASH.trits(), &mss_v1_signature);

        assert!(mss_v1_valid);
    }

    fn mss_v1_generic_gen_test<S, G>(generator: G)
    where
        S: Sponge,
        G: Default,
        G: PrivateKeyGenerator,
        <G as PrivateKeyGenerator>::PrivateKey: PrivateKey,
        <<G as PrivateKeyGenerator>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
        <<G as PrivateKeyGenerator>::PrivateKey as PrivateKey>::Signature:
            Signature + RecoverableSignature,
        <<<G as PrivateKeyGenerator>::PrivateKey as PrivateKey>::PublicKey as PublicKey>::Signature:
            Signature + RecoverableSignature,
        <<<<G as PrivateKeyGenerator>::PrivateKey as PrivateKey>::PublicKey as PublicKey>::Signature as RecoverableSignature>::PublicKey: PublicKey
    {
        const SEED: &str =
            "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";
        const DEPTH: usize = 4;
        let seed_trits = &SEED.trits();

        // todo try with not recover
        let mss_v1_private_key_generator = MssV1PrivateKeyGeneratorBuilder::<S, G>::default()
            .depth(DEPTH)
            .generator(generator)
            .build();
        let mut mss_v1_private_key = mss_v1_private_key_generator.generate(seed_trits, 0);
        let mss_v1_public_key = mss_v1_private_key.generate_public_key();

        for _ in 0..(1 << DEPTH - 1) {
            let mss_v1_signature = mss_v1_private_key.sign(seed_trits);
            let mss_v1_valid = mss_v1_public_key.verify(seed_trits, &mss_v1_signature);
            assert!(mss_v1_valid);
            //  TODO invalid test
        }
    }

    #[test]
    fn mss_v1_gen_kerl_kerl_test() {
        for s in 1..4 {
            let wots_v1_kerl_private_key_generator =
                WotsV1PrivateKeyGeneratorBuilder::<Kerl>::default()
                    .security_level(s)
                    .build()
                    .unwrap();
            mss_v1_generic_gen_test::<Kerl, WotsV1PrivateKeyGenerator<Kerl>>(
                wots_v1_kerl_private_key_generator,
            );
        }
    }

    #[test]
    fn mss_v1_gen_curl_curl_test() {
        for s in 1..4 {
            let wots_v1_kerl_private_key_generator =
                WotsV1PrivateKeyGeneratorBuilder::<Curl>::default()
                    .security_level(s)
                    .build()
                    .unwrap();
            mss_v1_generic_gen_test::<Curl, WotsV1PrivateKeyGenerator<Curl>>(
                wots_v1_kerl_private_key_generator,
            );
        }
    }

    #[test]
    fn mss_v1_gen_curl_kerl_test() {
        for s in 1..4 {
            let wots_v1_kerl_private_key_generator =
                WotsV1PrivateKeyGeneratorBuilder::<Kerl>::default()
                    .security_level(s)
                    .build()
                    .unwrap();
            mss_v1_generic_gen_test::<Curl, WotsV1PrivateKeyGenerator<Kerl>>(
                wots_v1_kerl_private_key_generator,
            );
        }
    }
    #[test]
    fn mss_v1_gen_kerl_curl_test() {
        for s in 1..4 {
            let wots_v1_kerl_private_key_generator =
                WotsV1PrivateKeyGeneratorBuilder::<Curl>::default()
                    .security_level(s)
                    .build()
                    .unwrap();
            mss_v1_generic_gen_test::<Kerl, WotsV1PrivateKeyGenerator<Curl>>(
                wots_v1_kerl_private_key_generator,
            );
        }
    }
}
