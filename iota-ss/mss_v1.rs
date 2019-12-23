use std::marker::PhantomData;
use super::*;
use iota_conversion::Trinary;

pub struct MssV1PrivateKey<S, K> {
    keys: Vec<K>,
    tree: Vec<i8>,
    depth: usize,
    index: usize,
    _sponge: PhantomData<S>,
    _key: PhantomData<K>
}

pub struct MssV1PublicKey<S, K> {
    state: Vec<i8>,
    depth: usize,
    _sponge: PhantomData<S>,
    _key: PhantomData<K>
}

pub struct MssV1Signature<S> {
    state: Vec<i8>,
    index: usize,
    _sponge: PhantomData<S>
}

impl<S, G> MssV1PrivateKey<S, G>
    where S: Sponge,
          G: PrivateKeyGenerator<S>,
          <G as PrivateKeyGenerator<S>>::PrivateKey: PrivateKey<S>,
          // WTF
          <<G as PrivateKeyGenerator<S>>::PrivateKey as PrivateKey<S>>::PublicKey: PublicKey<S> {

    pub fn new(seed: &[i8], depth: usize, generator: G, mut sponge: S) -> Self {
        // let mut state = vec![0; ((1 << depth) - 1) * 243];
        // dep on size
        // let mut keys = vec![0; ((1 << (depth - 1))) * 6561];
        // let mut keys = vec![0; ((1 << (depth - 1))) * 6561];
        let mut keys = Vec::new();

        for i in 0..(1 << (depth - 1)) {
            // TODO security
            // TODO clone
            // TODO TYPE
            // let ots_private_key = WotsV1PrivateKey::new(seed, i, security, sponge.clone());
            let ots_private_key = generator.generate(seed, i, sponge.clone());
            // let ots_public_key = ots_private_key.generate_public_key(sponge.clone());
            // let index = (1 << (depth - 1)) + i - 1;
            // TODO size
            // keys[i * 6561.. (i + 1) * 6561].copy_from_slice(ots_private_key.key());
            keys.append(ots_private_key);
            // state[index * 243.. (index + 1) * 243].copy_from_slice(ots_public_key.key());
            // println!("Seed index {:?} node index {:?}", i, index);
        }

        // for d in (0..depth - 1).rev() {
        //     println!("d = {:} n = {:}", d, (1 << d));
        //     for i in 0..(1 << d) {
        //         let index = (1 << d) + i - 1;
        //         let left_index = index * 2 + 1;
        //         let right_index = left_index + 1;
        //         sponge.absorb(&state[left_index * 243.. (left_index + 1) * 243]).unwrap();
        //         sponge.absorb(&state[right_index * 243.. (right_index + 1) * 243]).unwrap();
        //         sponge.squeeze(&mut state[index * 243.. (index + 1) * 243]).unwrap();
        //         sponge.reset();
        //         println!("i = {:} l = {:}, r = {:}", index, left_index, right_index);
        //     }
        //     // let index = (1 << (d - 1)) + i - 1;
        //
        // }
        //
        // println!("{:?}", state[0..243].to_vec().trytes());

        Self {
            keys: keys,
            tree: vec![0; ((1 << depth) - 1) * 243],
            depth: depth,
            index: 0,
            _sponge: PhantomData,
            _key: PhantomData
        }
    }
}

impl<S, K> PrivateKey<S> for MssV1PrivateKey<S, K>
    where S: Sponge,
          K: PrivateKey<S>,
          <K as PrivateKey<S>>::PublicKey: PublicKey<S> {

    type PublicKey = MssV1PublicKey<S, K::PublicKey>;
    type Signature = MssV1Signature<S>;

    fn generate_public_key(&self, sponge: S) -> Self::PublicKey {
        // TODO return or generate ?
        Self::PublicKey::new(&self.tree[0..243], self.depth)
    }

    fn sign(&mut self, message: &[i8], sponge: S) -> Self::Signature {
        let state = Vec::new();

        // let ots_private_key = WotsV1PrivateKey::new(seed, self.index, 1, sponge.clone());
        // let ots_signature = ots_private_key.sign(message, sponge.clone());

        self.index = self.index + 1;

        MssV1Signature::new(&state, self.index - 1)
    }

    // fn key(&self) -> &[i8] {
    //     &self.keys
    // }
}

impl<S, K> MssV1PublicKey<S, K>
    where S: Sponge, K: PublicKey<S> {

    pub fn new(state: &[i8], depth: usize) -> Self {
        Self {
            state: state.to_vec(),
            depth: depth,
            _sponge: PhantomData,
            _key: PhantomData
        }
    }
}

impl<S, K> PublicKey<S> for MssV1PublicKey<S, K>
    where S: Sponge, K: PublicKey<S> {

    type Signature = MssV1Signature<S>;

    fn verify(&self, message: &[i8], signature: &Self::Signature, mut sponge: S) -> bool {
        let security = (signature.state.len() / 6561) - 1;
        // From template type
        let ots_signature = WotsV1Signature::new(&signature.state[0..security * 6561]);
        let siblings = &signature.state[security * 6561..(security + 1) * 6561];
        // Clone ?
        let ots_public_key = ots_signature.recover_public_key(message, sponge.clone());
        let mut hash = [0; 243];

        hash.copy_from_slice(ots_public_key.key());

        let mut j = 1;
        for (i, sibling) in siblings.chunks(243).enumerate() {

            if signature.index & j != 0 {
                sponge.absorb(sibling).unwrap();
                sponge.absorb(&hash).unwrap();
            }
            else {
                sponge.absorb(&hash).unwrap();
                sponge.absorb(sibling).unwrap();
            }
            sponge.squeeze(&mut hash).unwrap();
            sponge.reset();

            j <<= 1;
            if (i >= self.depth - 1) {
                break;
            }
        }

        all_equal(&hash, &self.state)
    }

    fn key(&self) -> &[i8] {
        &self.state
    }
}

impl<S: Sponge> MssV1Signature<S> {

    pub fn new(state: &[i8], index: usize) -> Self {
        Self {
            state: state.to_vec(),
            index: index,
            _sponge: PhantomData,
        }
    }
}

// TODO default impl ?
impl<S: Sponge> Signature for MssV1Signature<S> {
    fn size(&self) -> usize {
        self.state.len()
    }
}

#[cfg(test)]
mod tests {

    use iota_crypto::{Kerl, Curl};
    use iota_conversion::Trinary;
    use super::*;

    #[test]
    fn mss_v1_kerl_sec_3_test() {

        const PUBLIC_KEY: &str = "IDSWNWLGPFLAQADAEYUINRS9MBEMCYARHXHVSBOZDOBHPIPNVYUFFTQLNYGDZKKTEBHYOQXVQVHXBGXH9";
        const HASH: &str = "NNZLXQKRAQBEUKNGVTKAHIIJUGSNNNNCASGGPNBJHKGTH9EGEAJZPKYL9WTNVYHFKDSQYERI9AYUFHYB9";
        const DEPTH: usize = 7;
        const INDEX: usize = 4;
        const SIGNATURE: &str = "PGCWBHJEXWRBTMSIWGIDRXWNFTYGTTXPEAHWEFXKXGH9VA9JARHWUHUYEOOYENBHKNF9WLIFOH9HGQJVDOMSJ9XWTOVUDVDJBDCSKOYHM9QQFEHHMGUMXNBTWVBDCBBCAGEAKCWMHUUGBIXURKNMUSQTWQVRYGQAS9SJFAXLWXALFRWJUFNS9LDMOVUFVPHBZPDLYD9DKSWDY9TUOCCQQM9JXMTJRLRWEUBAQLJCOYJTASG9QBXKKGDTRWHQGATGSWDEEZUU9EJQACNU9CHIUIQRGLWGHFF9ABGE9SGYFRANEOZJLRHCYRWI9IT9FGYMKYGYMYDWRUOFMDGIR9EYNMIHWDBAJRBBYBBRL9YAWDGWUVGWLMKKVJQAAFVOTYMQNBAGZZFLVP9HHENEFZC9DPLOABBV9FKJCYJ9OH9BTBNEQTJSJICBWHUQVHSOISVIIRCUUEVJLJNLZUGBQUDXTUNS9HQYXHNAQWTQIWYYERXQKFZBEJGRDJJLZUNNTZDDEIYZBFWFF9ENLLS9TNPFXJARPBMYFOAQEP9GYBRNAAFOPBRSTOKPCUZQLQAMNWHVKZHVPHDLDRORAUTLQKZNPTIAERPPMDD99WTVZGGJWCLVOWXIJHEKAKINBSQQEBFIWTFIZINBGEOI9IRNCVY9QBQECCDCTOTAOEUCLJCM9MSNXJMHHNFGIBLT9KDMASEGKFPOAQQ9ZFXUSRCNZTGPOXHDWTGUAL9JYLMOOKLWCTNC9UKMEFSBZSV9DXBYTOHNMUEAJTHJNVBMCYIEDOICPHROXUVMA9UREPMUCPBPJDELBJEBZYOR9D9TKLEQ9G9GXRXPSDBDZXTTUAKJSAIRCFTCTQFRLUDQBPRXIYCDAXCUOZIGZKCZRWXSLLZLAJTCDCEUIPYASTQOLMSEYEIMVBEGKOBAPYJZMHPGSXPFUGYLWGZZPBVCBKZBBCSPGEGBZAJQUCHSMSNW9HFEDYHOJAUJBJSKYFSMTWTTF9HGERJZIYMMLYBRVLJLCQFMXNXUPILZSERKSNMVTLMSKJZRIAVN9IRIBNBYLU9MW9EVPBEESKHOWTETUTZRHKM9BKWRFLZGIREKNC9KSKHBPRLCHCIEXPZEXILOYXBOPFLMWHSCN9JWUGZPWCWFSBNFFOKBQKPIJSUXNN9UZQQDKKEWZQDRXPDYQJHPBZJTOLQEFDWCKFPQELRFWTVBZVVZTAXDRQIGJVFNBM9TZCKRE9WDFTFVPV9RYIIUDIOIPYUG9UZCSVTJCLLSAFQJKPZGTTQLQYIAYGWJUMARKHSXKGCOXKKBBVUSPZZETMAGQBPAH9WUXLUJQGZKQUYUWMPCFCHMNGNQL9XNMFVEKMIPVTBXLBNKGDFVLLHNAREIC9HLZHNZYMBJHWAGESNDANOLPXHE9CVDQPVJBQHLTZLOEBSHZPMTAMLDTTNVYJWGOXCSGUEFIMLY9CNCLJSAUDLMRRFXSESMPMXDZRVTHZGLKJCHUYHNBNGBUOPISW9TAGGJY9FUQVLX9BRDJGRQ9BHCMLCZPJZFLCFBPDCIHAGJNNT9OKHSRBHPPNPNFFKYBUTXKUOTHH9ASBNDCYTUQOJWMYUDFDGBRPRSKKHQIOERZPWZWWZQLSORYDOU9QV9UW9NZFVBGUCFBNGGJSPYDVPXO9ZBDR9WYJIYDRNKIJQTJCJOOAEQT9OTADGBDAZACMTWKWFDMSS9BGLSNKZVFTKDQDNSGBACUVFCQBJXMVNPIY9RUR9IUWTDUJFQWTJTWUQYNSSZB9QWGDPXJWNUSKWUYBVIC9BSMNHQVKXSOUSJUBZDOUOMEXAX9KDEWZSWRJZNQDBCXQZFEZJMCMPMOA9ZVCHLQDUCMFDNIFCHOSIJIPCKTFOPVUTZCTZWAWBIGMQRRQGCNQYMAYZXDPXBFAKVDEPMJUXPMRLEMXUMFNSMGHZ9MSEWKYPWOUPSIOZTEJYUFLRVHXCMCTQX9IVNKMTQYQCHW9VSSSXJBOJPBGBIDIIKNRUQBDZUSOMOSWRZCGBLZZWNJQFRUWPBPXHMPVGOEZATZSDRLULE9ECFUMNPWELRL9AAJCONHTXMXSSIXNQBCNNLGREGDPRDWBNOVCOJVTKDPVRAYLXMFMZHABVZXZAIKUJGHYGYQWTBIDFHLBCLRASI9MTFFFHLJOYSIOSGPFKPUDYAXVRVXGDERBTZIAEG9UFXMWDGOCMXZSOHSCAPPYKWUJQLXJCIKJOP9NJJXRLCDEBUWMAKTNLVSJEZNTDVRPXWWKEZXIKBWEQRIR9RDIKXNPTIKNQWWOMIAECGNCYWY9LDSZQBVAOIJFWBYFYKXPLWPNWGDVMOVTNYMH9ZLYUBXPCOWOHJEHBTWEX9XNBWKOTGKWYCTIIKTZSUJPPXNXZOS9USOUIPOAZFWZRMQKKOWSSRMMTIVYQHRIODKXAKPH9FSJNQ9ZUEJNUMHPOPINIUZGNAIDBWEDSGPDPXRWLNKCMJCGYQBDWIGULQKYKLPHQQDDHBWNRVEBXJDSBGWSXEJFBYVVNOIOOQOTKLJYVDVRQUZCVKFBPROB9VVSHLAEKEEJLQHHNZDQLNAKEHBVPDSKGNHXTZNA9WUXBTK99SZXZYRHHHGRZIRLRQEVQSGPVHIOPKP9T9AGGJBTFASXWMKAOFUUZYMRHBUXRBZAO9SGMACE9CXLXCQADLITOI9AWXSUXUPAYFVNIMUZAGCJLZGCKX9IFJQKSNAAG9YBZRJBGJFWBSYCYV99GOSLLMSAXJNQWMCCQWBARLWDDRXUYBUIKHTAOGWWXLTZKOCBYIGBKVFCHDAPQIBBMJFPCQMQCWZYAMGWRBTMBJNDCXP9ADBXSUBAROQYODUWKDSXFMPKANYEJYESWNCHVDKCDBCQXXCRRENIIABYT9WUMDWRVRPSLLS99HYAACBKEWJQXXEWMHXFAEPVQD9KTDZFIWTGBLEBWAYAHVRNLGKPHXFNFLSFWRIKX99OTIUQVFYA9YPJAJJEYGXFSINSXDGNPUKPERLCCSCPHU9WKCGNWMCQRXBTWRRXACOVLKPWSHOXKLRIRWBDMEEUJOOALMYZLIWPHSCWXHV9RNHTFAUSPRHZMR9OAJWFWQENFOFCPMVJEPBQAS9LJWDUP9WKFDWOZRREWX9TSNCCDCHNMVBYGCIF9VVVBWRKDRGJNQQLIP9CABUZRISLUJIZTWIEXGDLMBVIFVEUWSDGTRVLGOPTEUOWUY99G9OEKUFIORYCXXQMTSL9MCVUQJWMVTSVSEMXREZHBIETUVNNUACCVFUECTCKWMUUCLXOEY9LQFAYGUKWGFZWXTTVCXVYJYCRCCARSKWMIGBZONSJIAACSNZUFBVBASXEXHXIJEQTEANIDZSREFIUOEVRSKUGFHMNV9ZQDUFBZAXNHZLZTH9YSVRWNEXAZVXPYIPRSNRHNZUJPALZQHUO9QLAS9RX9QBIXMAGIRNM9GUUYOGUBQOXXLKQEZPZMHKNCITFOYBEUKAXHJLRRMMVF9SLJZDGQAM9UXQ9VMVLIHFUVSNLBVVMDLYULLELHMTFTWCNUEXXQFDIJSNWUDWYLWAXEUSVOJFCCCYZFLQNFFRTPOTVVUALPYZCTUSEQOKVHCTZETMDMFSNSNGDTUCEGJYYZTXGRMUZJTWCULIZWUIBOVJAISLCGJ9MFOJIDZROGYYXHEXAIIWOAVEJWXVVQEKZXVIT99LBOIKGZWNX9OPTPLSOQPEAOIRKYIMLXHYLPVPXG9AKFIOFBFEBLASXYENQ9WXIMKILNNJOAJHWODVRBGNCBGWT9BHZZYDPJXQQHSO9CNDSPNZZEIPVIMNAPVCSXTTFGJSRVDYTMIQAKFPUEZAT9AKAQDBMP9FKXLQZUDDSMKVK9ZKVWDAPAINQYCYHOFGOUCFRBLUYB9HGVWJPKQXLXF9JKQJLNMROEGCPFGXUSAIJNQ9YLVCCPUDJNJPNWLMYVDQPQXBTDEWMQVZYWDVKBTVEF9VOKDVHVZDZRWFK9WTMYU9ATRQJSKFDWXNPRDHQAYNGWXYFDKSIHFNA9UGGMVNCDMTZPEFBJAHGHMMDHEQLA9IGVDUGBQHJQORJ9ZWNEUJPVWVFDXKWDWLUHEVE9PYVYSMYPSYU9ZSMACZUAXCSAEJNVHOJGBRFYARSFZMYESXLNQOAB9HOH9VGQJTSAURKCMPYUFWZGEPHP9PUVFNHSCCHVVTGWYHLLVKIZCROMYQIYOCAHPONKRPEGJPKWTNQ9LIKTSHMKPESEZEPJETUUO99JDHXAUJIFEZCJLDGDTKZNLNEUSFYBWXHJILLHILNRXZKYAJDYYPNIJHIYXZ9RJKAGYLEVKVQDAIOCHGEKPQPCZOLSDXNFVFBDVCKKN9ZXJDSXGC9MMLCZGOBGDACJAHCOKJBDSTGANCAKNEVVTKARLTCPFRSGPPFPDIEDMCUEEFOGWUUXXQEPULAIFOEINWPDCMFXOJXCLQITCCMAUUDLGXDJDLVMOFEADOWJDVIXBBSINQMLGXGILLMHWIVHDBDTIHWOEETQZPJOSSWNWJYYGEDGMSNNJUDYTOATBYCACKRICFQALDFLDZGKFKCCLWZIKGWOGMEVKOITUUDCZCBQEDXWYGV9XARB9CKWNLCKVOZBWZAKAMAWNMLVGYDFQOARCUN9CA9YAKIZDBSFZXZRZJABWZLZGGNAXVOHZMXXMTCQZWIMSYYGS9QA9KLXYHLUFEGIFUVLAHKOINTMFMJZFUUWZKRT9GZZGSAWWCFUZUYNJXPWPKKYYZVUBCWSMWZFJEFZHDTLVACXIYPPFYWCFUDHZGTSOJPKNOADZPQPMYCJGSZRKANUOZRGKD9UAFAKUSDDPPPJORELCGTNZZQDBKZYWUBKM9GKGIBOJANBZFQMZKNVMLNZPQFFFVXYYUBHXQPBQZHCCZIP9Y99PIHURWQTJIJMA9L9UQIOMCWJLVCFTRQ9DNOWJKBEAANBCMLXX9DFYVDLVIYWAYPISVVYSMHYHHQMOVHMHLWPDWWMFYBUHNVSDU9BP9CSZVCLU9MEBETEJRNEQ9XPNGRPCMQSRNBZA9HUWBRCLEJEJZYVVFWGY9QMGCLYRVC9YBBKVDQNZDBTJGS9YZOH9XLNQFKPVWHEFPWOWOEPMRVBATFBOZAWIYVTPJMBCCBVSLBZTCXWQNGWLPCYXWHHHVUAAMABPWGIXMPIRPCWMKRPY9VYEGAHSIKDJT9GEXSPKFGUZWJBKRIGQSYUFFIRXWXFENFFHDHYROGHPVFHUXMMQETAHWJGJSVUUV9Z9CPWUTRDE9OYZAJXGXEJONLEUNSACYMXQBIBGELXFULFBU9AISG9IQSPASNHU9OWHILBVGYJAMEYMZOKMNFDBPMMORLENRVUOVZEBETIASNTBOHXUWAPAVJCZZGJUYAPTPREPLJOEW9OTD9DMALQOGUDZAKOYHEFALMNKGCKWECEQMSGDA9VPVHFEMYEVVHC9HVXQKQJABAYEGLFJVDWNCSOOPURHMYPGSWKSDFMCGTSZRYVQAKMATIRRGVIYHHTXATCXQHEJWOJMEVDXV9QCRGTGYQYDWCEJMRGSCHZOTERVNBDNCKZWUDZPXOOWDUXZ9GYQKNVUNZKUGOMPWDWGTTXGJIQ9XUOGKCEWMDKFYXIBUSAUGYJYJYUVEMAIKEXPLEBKMUEBECVIGYXJUQLISTYSXLQ9RNIHWVDWLXCXCYCUK9TAGBBFXCIYLOPRKZCKTDSMQVCUXU9WQCQ9GKPCN9PKUQYUAJDIAJKNTDWJH9PPGYGN9PVRKRMUBZZCW9SVGPLRRZDRADYMWGXWMWAFWLVGKVRI9WQGZIUHOXQJUCIBXQBB9VZNXDKT9ONCYCFZMTNHPJMJPUJZDWSPQLRAZNGV9QTKNYBZDSUQIPLVSQZHEOLUPFPRAXRHJSXADGQDBEVNPMVEC9TCYAGZSZASMGJLRZYWOKLUZULZZXTCBLZUQND9VPFJJHEDLOTRINEBFMPWSGDHKEOQACITVNPNTXKKQWCZLC9PYUHGSQEATWZRGZPELGOWUYVIHDYQPGJXAL9O9XNODA9GLDBYXXVPURQTQSWXZRWYRHOIQUUCRBZYTKSGSOMAXHRZSTUP9HRIMHNIBQJFCUBIWHIXHUWXATPHSVIFXMWJKKOBFMICGJGFJKLDPCVLFGHILHLIKFSDOPYFHEWVPGQISJQHKV9HBLKWX9JGDSUZWBUTPOHAINLBFNMUTEQ9NFFBKFSCZELK9XIXFTDZFQIYVIEULYEOEWMQWHZJZQR9SDBIOCXEPHXMCWCQSFCSDWY9QTJRDJDRFVJUCPBMRHIADTC9KZNDNUVDYSKQEDUX9BLFFNPNS9OCQHCHNMDYBRTOJNWAGWKLSTEAQHYCYEEYPKRUFPTWEWXMOQE9UKZYXHBFBHOHNDRYVTW9JKBIUZFF9OOFKFHPVCFYAEDUYSRMKKDCEOGNIJQYCYKVVUHUZRWMJFHVGTYFVFNXOIRXXZHBGMFQJEBUPSBKLAY9QTJZNIWMHYIQLVWF9TQMM9ZEDDKCCPEKDMJCJCKGDICZKINBYZGBCEUXAFMGWZTF9TUMVAEELCKMBESECIMAAVDRJWJBYEWDVB9HPVWNYUPUMOEFJETRHKD9N9KOAZRBFOQCXXMUBFPAVWZEEJ9FPOTLMLEMZ9EEJWKYMHDVXYFTKLRRCHWDWSCJTODJWIHWMFUTKGFLPDTFEYGCFAATPX9MTX9YCFWXWRMLZBNAAFOZMYUQZ9JYUXFQUXI9XKYVCTL9BIKJJPSVILKNDOHZWQQBG9QINKZPVG9EDU9WFVUZZQXZTCWWLHWIFQW9ECOJVGNYZFPXQAMKTVPEMAVLBQKUCBCQVFQFBDKATSOZGOQZJUKMOYZYHKECFQCR9NFEYCLFKFUMTSFZVYZYBFZQC9SAYIXTIPQJSKHTFEZ9NKPOYGRSOXROPRPGEJH9JPTLSI9VWQODQQZMAABCN9NNDUNO9WGWBSHLOXMTFWNTAFXAAMXBS9IHOPEPBRIBGDLKFCTEPSQWOZVKWJKZNGSTVYVJYKPCBUSIOY9FRPXCVBPCFMSKYDDXKYJJWMXMXDPZNAUNCKRCWDIHWGZUMUPMRBZKHSXEZSWWLXXVLLQBSVJFQWNSJZIA999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999";

        let sponge = Kerl::default();
        let mss_v1_public_key = MssV1PublicKey::<Kerl, WotsV1PublicKey<Kerl>>::new(&PUBLIC_KEY.trits(), DEPTH);
        let mss_v1_signature = MssV1Signature::<Kerl>::new(&SIGNATURE.trits(), INDEX);
        let mss_v1_valid = mss_v1_public_key.verify(&HASH.trits(), &mss_v1_signature, sponge);

        assert!(mss_v1_valid);
    }

    #[test]
    fn mss_v1_gen_test() {

        const SEED: &str = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";
        const DEPTH: usize = 4;

        let sponge = Kerl::default();
        let mut wotsv1_kerl_private_key_generator = WotsV1PrivateKeyGeneratorBuilder::default().security_level(1).build();
        let mss_v1_private_key = MssV1PrivateKey::new(&SEED.trits(), DEPTH, wotsv1_kerl_private_key_generator, sponge);
        // let mss_v1_public_key = mss_v1_private_key.generate_public_key(sponge);
        // println!("{:?}", mss_v1_public_key.key().trytes());

    }
}
