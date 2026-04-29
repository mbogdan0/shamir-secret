import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import fc from "fast-check";
import * as slip39 from "../src/ts/slip39/index.ts";
import {
  combineMnemonics as combineMnemonicsSource,
  generateMnemonics as generateMnemonicsSource
} from "../src/ts/slip39/mnemonics.ts";

type TestCrypto = {
  subtle: unknown;
  getRandomValues(target: Uint8Array): Uint8Array;
};

type AppTestApi = typeof slip39;

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR_PATH = resolve(projectRoot, "test", "fixtures", "slip39-vectors.json");
const INTEROP_MATRIX_PATH = resolve(projectRoot, "test", "fixtures", "slip39-interop-matrix.json");
const SECRET_16 = Uint8Array.from({ length: 16 }, (_, index) => index);
const SECRET_32 = Uint8Array.from({ length: 32 }, (_, index) => index);
const ALL_BYTES = Uint8Array.from({ length: 256 }, (_, index) => index);
const SECRET_16_HEX = "000102030405060708090a0b0c0d0e0f";
const SECRET_32_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ALL_BYTES_HEX =
  "000102030405060708090a0b0c0d0e0f" +
  "101112131415161718191a1b1c1d1e1f" +
  "202122232425262728292a2b2c2d2e2f" +
  "303132333435363738393a3b3c3d3e3f" +
  "404142434445464748494a4b4c4d4e4f" +
  "505152535455565758595a5b5c5d5e5f" +
  "606162636465666768696a6b6c6d6e6f" +
  "707172737475767778797a7b7c7d7e7f" +
  "808182838485868788898a8b8c8d8e8f" +
  "909192939495969798999a9b9c9d9e9f" +
  "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
  "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
  "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
  "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
  "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const INDEX_UNIVERSE = Array.from({ length: 16 }, (_, index) => index);
const PRINTABLE_ASCII_ARBITRARY = fc
  .array(fc.integer({ min: 32, max: 126 }), { minLength: 0, maxLength: 32 })
  .map((codes) => String.fromCharCode(...codes));
const INDEX_PERMUTATION_ARBITRARY = fc.shuffledSubarray(INDEX_UNIVERSE, {
  minLength: INDEX_UNIVERSE.length,
  maxLength: INDEX_UNIVERSE.length
});
const ROUND_TRIP_PARAMETERS_ARBITRARY = fc
  .tuple(fc.integer({ min: 1, max: 16 }), fc.integer({ min: 1, max: 16 }))
  .filter(
    ([threshold, shareCount]) => shareCount >= threshold && !(threshold === 1 && shareCount > 1)
  );
const THRESHOLD_PARAMETERS_ARBITRARY = fc
  .tuple(fc.integer({ min: 2, max: 16 }), fc.integer({ min: 2, max: 16 }))
  .filter(([threshold, shareCount]) => shareCount >= threshold);

type ReferenceFixture = {
  name: string;
  threshold: number;
  shareCount: number;
  secretHex: string;
  passphrase: string;
  options: { identifier: number };
  mnemonics: string[];
};

const REFERENCE_FIXTURES: ReferenceFixture[] = [
  {
    name: "128-bit 2-of-3 with empty passphrase",
    threshold: 2,
    shareCount: 3,
    secretHex: SECRET_16_HEX,
    passphrase: "",
    options: { identifier: 42 },
    mnemonics: [
      "acid fawn academic acid both silent single python romantic grownup paces beam prune geology gums salt husky album racism editor",
      "acid fawn academic agency dough quick finger mustang laundry credit problem paces year deadline modify gasoline gross quantity grasp humidity",
      "acid fawn academic always analysis dough modify weapon early work wolf cards type watch visual diagnose fragment rhyme spend lyrics"
    ]
  },
  {
    name: "256-bit 3-of-5 with TREZOR passphrase",
    threshold: 3,
    shareCount: 5,
    secretHex: SECRET_32_HEX,
    passphrase: "TREZOR",
    options: { identifier: 1234 },
    mnemonics: [
      "analysis morning academic acne academic acid adequate apart echo educate alive category method liberty apart describe teammate scandal beard entrance declare airline blue frequent legend endorse bumpy hush soldier lunar greatest oven umbrella",
      "analysis morning academic agree aluminum discuss smart shelter educate flavor pajamas scholar patrol volume timber legs webcam check obesity plains trash privacy bulb prepare best research reunion kernel teammate type browser upgrade python",
      "analysis morning academic amazing already scholar credit garden garden bucket smear glad estate erode branch playoff preach scared admit edge shame brother task premium flavor simple hazard fatigue provide crush aviation organize typical",
      "analysis morning academic arcade avoid woman tofu petition genuine avoid guilt luck jacket easel vampire carve purple chemical lyrics pajamas beaver purchase spark freshman scholar diet slap flexible legal engage income verify quick",
      "analysis morning academic axle alien explain senior crystal game treat slush dining exercise manager ladle subject together prize explain axis exchange exercise visitor nail fantasy failure group username herald raspy element practice drug"
    ]
  }
];

type TextSharingFixture = {
  name: string;
  text: string;
  threshold: number;
  shareCount: number;
  passphrase: string;
  options: { identifier: number; extendable?: boolean; iterationExponent?: number };
  info: {
    utf8ByteLength: number;
    masterSecretByteLength: number;
    paddingByteLength: number;
  };
  encodedHex: string;
  mnemonics: string[];
};

const TEXT_ENVELOPE_MAGIC = "SLIP39TXT";
const TEXT_ENVELOPE_VERSION_OFFSET = TEXT_ENVELOPE_MAGIC.length;
const TEXT_ENVELOPE_LENGTH_OFFSET = TEXT_ENVELOPE_VERSION_OFFSET + 1;
const TEXT_ENVELOPE_TAG_OFFSET = TEXT_ENVELOPE_LENGTH_OFFSET + 4;
const TEXT_ENVELOPE_TAG_LENGTH = 16;
const TEXT_ENVELOPE_PAYLOAD_OFFSET = TEXT_ENVELOPE_TAG_OFFSET + TEXT_ENVELOPE_TAG_LENGTH;

const TEXT_SHARING_FIXTURES: TextSharingFixture[] = [
  {
    name: "empty text 1-of-1 identifier zero",
    text: "",
    threshold: 1,
    shareCount: 1,
    passphrase: "",
    options: { identifier: 0, iterationExponent: 0, extendable: true },
    info: { utf8ByteLength: 0, masterSecretByteLength: 30, paddingByteLength: 0 },
    encodedHex: "534c4950333954585401000000001fc39856f8ab8680dcfb87cacae1a43d",
    mnemonics: [
      "academic again academic academic piece income snake daughter revenue guitar grin exchange yield teaspoon center patent violence husky satisfy software year desert priest rebuild spray beaver surface species swing taxi syndrome"
    ]
  },
  {
    name: "single ASCII character 2-of-2",
    text: "A",
    threshold: 2,
    shareCount: 2,
    passphrase: "",
    options: { identifier: 1, iterationExponent: 1, extendable: true },
    info: { utf8ByteLength: 1, masterSecretByteLength: 32, paddingByteLength: 1 },
    encodedHex: "534c495033395458540100000001da562bf0b5e7cbe992bf0946384f0b1d4100",
    mnemonics: [
      "academic aquatic academic acid aspect mayor herald ecology sidewalk inform herald medal marvel peasant sheriff cargo legend pile fiction cleanup camera beaver ajar deliver depart domain estate cleanup join garlic diagnose ocean artwork",
      "academic aquatic academic agency award mixture pharmacy imply ocean impact order credit brother tadpole privacy aluminum adjust window response smear unknown quarter permit species treat oasis reward estate episode thank surprise industry bumpy"
    ]
  },
  {
    name: "even ASCII bytes 2-of-3",
    text: "AB",
    threshold: 2,
    shareCount: 3,
    passphrase: "TREZOR",
    options: { identifier: 2, extendable: true },
    info: { utf8ByteLength: 2, masterSecretByteLength: 32, paddingByteLength: 0 },
    encodedHex: "534c4950333954585401000000026906fe4f037b7d31a788098f61b7651b4142",
    mnemonics: [
      "academic birthday academic acid aunt scramble glen order stilt usual makeup cricket diet curious frost vegan thank early lyrics problem alive hazard main window hearing unfold often magazine else safari item mandate tofu",
      "academic birthday academic agency acquire senior employer cricket playoff carve dish merchant response task mortgage prisoner emerald engage founder desert pupal temple aircraft device cinema mandate island valuable repeat unfair acrobat estate pants",
      "academic birthday academic always advance capture daughter obesity member have vintage founder level execute spider evidence pregnant lunch diagnose very switch laundry memory geology forward peasant float judicial pistol bundle merchant romp pile"
    ]
  },
  {
    name: "odd ASCII bytes 2-of-3 original checksum",
    text: "ABC",
    threshold: 2,
    shareCount: 3,
    passphrase: "printable-passphrase",
    options: { identifier: 3, iterationExponent: 0, extendable: false },
    info: { utf8ByteLength: 3, masterSecretByteLength: 34, paddingByteLength: 1 },
    encodedHex: "534c495033395458540100000003cf4280baa0e42ebd5e252861db174ca741424300",
    mnemonics: [
      "academic branch academic acid acne public detect mandate liquid column valid vitamins venture counter sunlight rebuild public shaft drug cover admit belong amount ultimate hearing scene insect airport juice family sled boring grill similar round",
      "academic branch academic agency acquire sugar vocal require fishing emphasis both ambition single primary much clothes emperor retreat organize answer geology practice either tenant timely safari threaten priest plot syndrome syndrome evaluate election genre rocky",
      "academic branch academic always academic gather adult premium dragon timely marvel example mason chest flash finger editor evoke knife critical salt armed lyrics diagnose have paper tolerate belong ruler coal triumph priority makeup join spelling"
    ]
  },
  {
    name: "ASCII sentence 3-of-5 high exponent",
    text: "Correct horse battery staple.",
    threshold: 3,
    shareCount: 5,
    passphrase: "with spaces and symbols !@#",
    options: { identifier: 42, iterationExponent: 4, extendable: true },
    info: { utf8ByteLength: 29, masterSecretByteLength: 60, paddingByteLength: 1 },
    encodedHex:
      "534c49503339545854010000001d9856081e0c54f9b0d2dbfcabaaa786b7436f727265637420686f727365206261747465727920737461706c652e00",
    mnemonics: [
      "acid filter academic acne academic again category ruin aircraft branch husky adjust ancestor crunch royal elevator average echo beard liquid biology fawn genius screw broken guilt puny alpha capital kind adequate envelope chubby method family maiden corner pencil patrol silent cultural regular venture aquatic deliver skunk elephant exclude dilemma teammate modify medal alto enjoy victim",
      "acid filter academic agree ancestor email drift scandal hearing umbrella herald fitness findings subject spray hazard spirit cards dismiss starting rhythm pharmacy satisfy regret explain domain username wireless shelter dismiss hobo petition starting snake stick excuse violence frequent theory canyon friar force group gums scene fortune year usual yelp pistol evoke radar maiden timber mother",
      "acid filter academic amazing tendency fawn family aide purple gross lily pancake income ancient easel romp device saver anxiety quarter likely dominant thank garbage example vampire tendency prune downtown acne anatomy flame either priority parking radar yoga webcam famous estimate blue auction ocean theory ceramic shame medical airport pleasure average miracle clay sled desire vampire",
      "acid filter academic arcade twin biology exhaust adapt survive moisture negative viral cubic wisdom criminal transfer unusual orbit class taught cradle sharp editor change building payroll pancake evil type emperor grocery repair raisin unfair critical husky check acrobat bike ordinary guard ultimate avoid loyalty station fused density relate gesture enforce exclude capture elevator muscle military",
      "acid filter academic axle cause easel meaning violence segment adjust hormone garden shaped timely juice fantasy bucket parcel hazard unwrap heat sniff smear devote junction solution obesity aspect chest facility station junk mouse impulse shelter hearing furl scholar maiden vegan being alarm military floral plan impact failure sheriff exhaust pickup ladle wealthy duke bucket academic"
    ]
  },
  {
    name: "leading trailing whitespace 2-of-4",
    text: "  leading and trailing whitespace  ",
    threshold: 2,
    shareCount: 4,
    passphrase: "",
    options: { identifier: 4096, iterationExponent: 1, extendable: true },
    info: { utf8ByteLength: 35, masterSecretByteLength: 66, paddingByteLength: 1 },
    encodedHex:
      "534c4950333954585401000000238d95fe5bfbb6633ef13e74df5281b8ea20206c656164696e6720616e6420747261696c696e672077686974657370616365202000",
    mnemonics: [
      "category agency academic acid drift often email replace twin license seafood disaster tidy dance dream ruin ecology knife mineral join browser often surface branch thank plunge necklace valuable fridge browser scatter realize silent marathon ladybug headset square threaten alarm repeat pile dish video reunion sheriff weapon equation best music blind modern benefit pupal away aide slice album lunar alto swing",
      "category agency academic agency campus moment spider boundary auction avoid husky hesitate sheriff plains spill traveler aviation fatal material laser gravity tricycle tackle tactics method safari bolt valuable idea often metric clay formal nervous exhaust rumor findings license patent writing fancy screw trip reunion mule duckling national glad headset presence yield diet bulb mustang theater academic rocky violence busy coal",
      "category agency academic always dismiss listen analysis valuable pharmacy learn safari check wireless dominant legal learn carve ceramic science indicate photo jewelry reunion move elegant juice uncover educate elite alarm helpful mobile transfer percent income darkness bedroom credit chest depend animal talent parcel argue install herd order eclipse cowboy kitchen evaluate float phantom ajar slow voter venture kidney threaten mama",
      "category agency academic aquatic breathe making nuclear friar elevator aquatic industry invasion starting retreat hanger pistol extra avoid stilt impulse sugar amazing regret fantasy declare belong goat educate hunting lily disaster adapt jewelry prospect elite lizard minister exclude losing iris wrist change river argue cradle prayer element declare spine scramble coding knife armed level cover document estate aspect yield hybrid"
    ]
  },
  {
    name: "multiline tabs 3-of-4",
    text: "line one\n\tline two\nline three",
    threshold: 3,
    shareCount: 4,
    passphrase: "tab passphrase",
    options: { identifier: 8191, iterationExponent: 2, extendable: false },
    info: { utf8ByteLength: 29, masterSecretByteLength: 60, paddingByteLength: 1 },
    encodedHex:
      "534c49503339545854010000001df9f64ecc8adeb94add0c42123bf0836d6c696e65206f6e650a096c696e652074776f0a6c696e6520746872656500",
    mnemonics: [
      "easel warn academic acne academic again category ruin aircraft branch husky adjust ancestor crunch royal elevator average echo beard liquid biology fawn genius screw broken guilt puny alpha capital kind adequate envelope chubby method family maiden corner pencil patrol silent cultural regular venture aquatic deliver skunk elephant exclude dilemma teammate modify medal exchange chew darkness",
      "easel warn academic agree superior declare findings recall type havoc drug editor cluster holiday unfold hand miracle cricket spine course genre behavior fiscal teammate yoga smart regret threaten relate describe single manager credit ceiling extra tenant lying adequate wavy bishop husky valid always cargo birthday justice evaluate playoff aunt carbon decent ruler watch iris discuss",
      "easel warn academic amazing diminish lunar tension revenue gray symbolic flip paid zero ivory froth wits scramble rocky spew union that starting cubic campus distance pupal born goat hamster mobile visitor pecan diet flexible slavery rescue purple animal omit group roster robin forget plan should recover decent involve lying taxi texture tidy anxiety become float",
      "easel warn academic arcade ultimate purple nail simple marathon process blimp swimming speak dismiss include squeeze flip spirit axis election museum mineral bumpy downtown tadpole bishop carbon leader slow superior disaster guard earth training smell spark being primary segment regular organize vitamins parking repair type aviation dish metric pulse capital educate playoff rhythm emission explain"
    ]
  },
  {
    name: "embedded control characters 2-of-5",
    text: "null\u0000unit\u0001separator\u001fend",
    threshold: 2,
    shareCount: 5,
    passphrase: "",
    options: { identifier: 16384, iterationExponent: 0, extendable: true },
    info: { utf8ByteLength: 23, masterSecretByteLength: 54, paddingByteLength: 1 },
    encodedHex:
      "534c495033395458540100000017790cc72b299821d6b516fbbd46324c206e756c6c00756e697401736570617261746f721f656e6400",
    mnemonics: [
      "leader again academic acid academic exclude credit moment cards trust wildlife crystal rainbow busy render jewelry bolt network story visual romantic sprinkle large forbid fawn square adjust scroll wine payroll hour scatter lair ultimate envelope racism angel remove cylinder much stay unusual living mansion class exercise crystal teammate equip lily benefit",
      "leader again academic agency acid piece ultimate join rumor nail fatal numb withdraw breathe prize scroll evidence smith magazine national visual squeeze rival ajar robin observe ancestor timely picture mental shame response hobo switch indicate pregnant math kitchen ordinary slim junior blanket secret dominant leader enemy remember behavior fragment thorn beaver",
      "leader again academic always acquire ordinary born anatomy rescue believe resident roster column blanket modern easy pregnant density shame increase custody rescue wits tendency nuclear example advance activity element museum chew income flexible mental category emission cargo depict epidemic chemical lunar impulse provide prepare lair depart alpha elevator webcam rainbow mortgage",
      "leader again academic aquatic acne iris software thorn golden hormone best injury hour become lunar zero valid greatest necklace behavior graduate resident drove reward imply actress animal charity carve render liquid anxiety evaluate rhythm cage freshman necklace vitamins western join clinic lungs vegan buyer symbolic downtown mixed pumps type spine museum",
      "leader again academic axis acquire legend edge humidity explain inform junior quiet mailman geology wavy marvel judicial pecan eraser wrap leaves arena item huge spine tolerate prospect epidemic method pencil tolerate custody demand damage discuss species cause scholar extra response gross relate unfold lift numerous stick hawk ceiling public mouse system"
    ]
  },
  {
    name: "BMP symbols 4-of-6",
    text: "Unicode BMP symbols: snowman ☃, pi π, omega Ω",
    threshold: 4,
    shareCount: 6,
    passphrase: "BMP-pass-123",
    options: { identifier: 24576, iterationExponent: 3, extendable: true },
    info: { utf8ByteLength: 49, masterSecretByteLength: 80, paddingByteLength: 1 },
    encodedHex:
      "534c4950333954585401000000310486c29415610b8147d80e57bbabb662556e69636f646520424d502073796d626f6c733a20736e6f776d616e20e298832c20706920cf802c206f6d65676120cea900",
    mnemonics: [
      "romp aide academic acquire academic again category ruin aircraft branch husky adjust ancestor crunch royal elevator average echo beard liquid biology fawn genius screw broken guilt puny alpha capital kind adequate envelope chubby method family maiden corner pencil patrol silent cultural regular venture aquatic deliver skunk elephant exclude dilemma teammate modify medal dramatic video theory smoking editor amount desert beaver endless camera lips famous evaluate decision spill moisture fawn armed wrap",
      "romp aide academic aide extra emphasis clinic spine finance fluff inmate body forecast hobo scramble flash galaxy legend blue network graduate move grin style hamster plastic realize bundle hormone reward alive freshman income soldier flame organize item timber piece tadpole knit webcam walnut cause level aspect entrance genre luck check nervous payment march devote trash therapy military erode display clock muscle fumes magazine grocery ocean imply strike pile coastal therapy easel",
      "romp aide academic ambition findings burning fortune papa trust prospect prisoner pupal benefit mayor lecture debut holy debut ajar petition strike view afraid memory building paid maximum shaft enemy aunt manual always glasses crunch process climate evidence lair cricket pupal texture math ecology equip training purchase withdraw patent explain tadpole crush camera idle pencil husband race clay jewelry lecture move famous medal galaxy similar license racism lizard wolf makeup story makeup",
      "romp aide academic arena sharp faint paper domain herd wrist work space easy ending river element skunk location faint plunge research arena eyebrow vampire yelp drove domestic domestic news class scramble cage voting peanut omit numerous peanut crowd gums inform express duration orbit fantasy database sharp exceed award crazy broken strike snapshot herald pickup saver auction depend hazard cradle gasoline spark ceiling triumph shame gasoline fantasy username paper teammate plan papa",
      "romp aide academic beam document downtown fangs plot expect shadow music kidney squeeze mixed execute mixture meaning crystal practice engage false negative alto smart expect grin erode champion ultimate explain ambition pistol secret drink union satisfy herd group indicate alto pacific plan column duckling strategy industry deadline living excuse fangs desktop dryer salon husky vanish civil crowd reject single hamster swimming spine being drove script epidemic findings again mustang keyboard nylon",
      "romp aide academic black veteran wits blue carpet superior juice body cargo march material fatal freshman slim remember column intimate exercise sheriff transfer moment helpful therapy literary modify fangs fangs lilac duckling distance gesture pacific credit legend fridge verify justice voice pecan burden transfer ecology mixed dough ugly detailed mansion bumpy capital punish literary traffic impact fused prevent reunion bundle usual metric average involve result species justice slow budget expand hanger"
    ]
  },
  {
    name: "emoji sequence 3-of-6",
    text: "Emoji sequence: 🙂🚀🔐",
    threshold: 3,
    shareCount: 6,
    passphrase: "emoji passphrase",
    options: { identifier: 30000, iterationExponent: 1, extendable: false },
    info: { utf8ByteLength: 28, masterSecretByteLength: 58, paddingByteLength: 0 },
    encodedHex:
      "534c49503339545854010000001ca5905a1e8b15cff691ab720c63887007456d6f6a692073657175656e63653a20f09f9982f09f9a80f09f9490",
    mnemonics: [
      "trip leaf academic acne academic academic eclipse adult away extra legs aluminum clay pancake satisfy argue disaster usual agency behavior evoke editor employer born garlic military losing busy industry tendency senior ceramic luxury demand amuse clothes oral level escape crisis prune space mansion deal scene chubby slap destroy stick increase auction library bolt flame",
      "trip leaf academic agree activity priest extra have pistol penalty visitor exhaust tracks center forbid health duckling trust trash traveler payment repeat glasses mortgage alien engage branch skin again medical emphasis exclude duke fact ticket actress smoking general total dryer careful adult intend cultural floral detailed result gasoline golden broken adjust mansion puny yoga",
      "trip leaf academic amazing admit document living hormone ugly snake avoid gasoline repair goat provide taste quick style living program climate check garbage ounce mild necklace network buyer flash lamp airline traveler decrease mustang training round canyon nuclear senior space holy task true airport thunder justice game machine physics category golden blessing spark bulb",
      "trip leaf academic arcade afraid music mouse alive favorite client item clothes join theater cricket remember random roster hairy fiber should strike jewelry canyon voting execute alarm skunk company axis lunch living loud veteran agency tolerate fact junior grief scandal salary auction body breathe jacket holy dance swimming budget escape guest canyon industry purchase",
      "trip leaf academic axle academic axis blanket best adjust genuine arena gravity already training item short echo capacity relate counter loud verify puny isolate soul spit remember screw tricycle testify manager trouble grant diminish remove group window threaten visual require segment vampire regret grill dwarf chemical warmth aunt level weapon fumes learn frozen expect",
      "trip leaf academic bishop activity reunion ajar juice replace much junk civil scared guest testify prepare endless already findings species hand always mustang wine railroad advocate column bolt oasis marathon alarm lobe soul favorite finger eclipse receiver alive founder priority guilt category emperor junk payroll describe lyrics forward duke mobile family lungs wealthy toxic"
    ]
  },
  {
    name: "combining marks 2-of-6 max identifier",
    text: "Combining marks: Cafe\u0301 and resume\u0301",
    threshold: 2,
    shareCount: 6,
    passphrase: "combining~pass",
    options: { identifier: 32767, iterationExponent: 0, extendable: true },
    info: { utf8ByteLength: 36, masterSecretByteLength: 66, paddingByteLength: 0 },
    encodedHex:
      "534c495033395458540100000024e395180dd344b926c7b86b43655ad748436f6d62696e696e67206d61726b733a2043616665cc8120616e6420726573756d65cc81",
    mnemonics: [
      "zero wisdom academic acid acid pickup flame smug soldier cargo craft inmate sprinkle sheriff belong hybrid company theater spray smell alien drug hanger wisdom satoshi adequate damage extra course thorn stadium tension peaceful taste tension center mule timber year expand agency spew increase magazine racism pupal fumes welfare program papa decrease axis large behavior usher muscle mouse depart eclipse oasis",
      "zero wisdom academic agency already pickup lift sled sister afraid jury realize suitable example armed stilt evoke taste ancient bulb weapon thorn perfect spew fatigue genius force rumor clock pecan gravity lungs unusual paid intimate jewelry living says hazard hamster criminal spray robin beam thorn glasses single method aide exotic swing garden valid boundary losing rapids capital dryer task spelling",
      "zero wisdom academic always award picture year welfare criminal coding thumb element single stick craft liberty inside obtain hour spider rich morning omit revenue chemical scatter segment index deploy grant rainbow music width game similar length idea plastic spirit advocate carpet sprinkle lobe plot spew answer lamp maximum lawsuit grasp lily username glimpse branch infant guard likely golden manual remove",
      "zero wisdom academic aquatic aluminum picture crazy toxic diminish dragon raspy leaf ruin froth diagnose crisis canyon pickup pumps activity either exclude eyebrow mountain python pile quarter tension duke climate alien work rapids carpet galaxy surface glad memory eclipse closet decision starting escape deploy lily subject ultimate thumb spider mama guitar leaves unfair canyon admit enforce amazing hawk benefit upstairs",
      "zero wisdom academic axis cargo pile agency move papa huge quiet breathe tension twin gather climate lily best similar floral username industry universe language engage mouse merchant both cards zero jerky recover axis scared pumps greatest cards knit primary iris very snake necklace smirk density superior carve believe average decent dictate soldier ending album walnut indicate regret decision sister elite",
      "zero wisdom academic birthday breathe pile snake lungs retailer increase temple surface unkind hour laser marvel unwrap darkness biology market award primary check fiscal staff visitor threaten location best rocky sidewalk soul freshman lily clogs dramatic armed forward discuss fake switch sniff fiction fishing glad angel material item penalty tadpole subject parcel shadow afraid maximum fiber depart easel fantasy ancient"
    ]
  },
  {
    name: "longer text 5-of-7",
    text: "This longer text exercises the text envelope across multiple share words, preserving punctuation, numbers 12345, and repeated phrases for recovery.",
    threshold: 5,
    shareCount: 7,
    passphrase: "long text passphrase with spaces",
    options: { identifier: 12345, iterationExponent: 2, extendable: true },
    info: { utf8ByteLength: 147, masterSecretByteLength: 178, paddingByteLength: 1 },
    encodedHex:
      "534c495033395458540100000093b3d1e4a8d4dd6ce83e8d2cf3e87e6afa54686973206c6f6e67657220746578742065786572636973657320746865207465787420656e76656c6f7065206163726f7373206d756c7469706c6520736861726520776f7264732c2070726573657276696e672070756e6374756174696f6e2c206e756d626572732031323334352c20616e64207265706561746564207068726173657320666f72207265636f766572792e00",
    mnemonics: [
      "garlic skin academic acrobat academic academic eclipse adult away extra legs aluminum clay pancake satisfy argue disaster usual agency behavior evoke editor employer born garlic military losing busy industry tendency senior ceramic luxury demand amuse clothes oral level escape crisis prune space mansion deal scene chubby slap destroy stick increase auction divorce ultimate says explain early acrobat biology metric email blanket graduate solution episode cover railroad best exercise drove aircraft fiber fantasy failure finance much flexible gray petition staff friendly jewelry visitor brave gesture material endless focus grownup parcel muscle object helpful random together surprise identify sheriff diminish campus install sympathy luck funding jury vampire station paid learn alarm corner teaspoon living budget ivory chemical makeup cylinder shame glimpse memory elder broken percent mortgage firm hamster timely numb have remove coding overall lamp ancestor guitar peanut mixed forecast platform pistol phrase plot true primary repeat wildlife crush width parcel average",
      "garlic skin academic aircraft adorn crisis umbrella random sugar justice daisy repeat universe simple humidity romantic adult busy public scene born helpful vanish sheriff crisis retreat depend smart early argue infant spelling fantasy friendly ranked stick grownup primary voice sympathy jury wrist discuss texture memory exercise join tracks peanut overall replace ultimate recall universe wisdom vampire simple early drove vocal taste memory lamp wireless very taste romantic academic again category ruin aircraft branch husky adjust ancestor crunch royal elevator average echo beard liquid biology fawn genius screw broken guilt puny alpha capital kind adequate envelope chubby method family maiden corner pencil patrol silent cultural regular venture aquatic deliver skunk elephant exclude dilemma teammate modify medal dramatic video theory smoking editor amount desert beaver endless camera lips famous evaluate decision spill moisture extra emphasis clinic spine finance fluff inmate body forecast hobo scramble flash galaxy legend blue network usher spill fragment",
      "garlic skin academic amount actress endless focus grownup parcel muscle object helpful random together surprise identify sheriff diminish campus install sympathy luck funding jury vampire station paid learn alarm corner teaspoon living budget ivory chemical makeup cylinder shame glimpse memory elder broken percent mortgage firm hamster timely numb have remove coding overall lamp ancestor guitar peanut mixed forecast platform pistol phrase plot true primary repeat wildlife crush purple smart evaluate holiday recall texture ocean problem retailer vocal twin upgrade sack animal dream declare seafood careful march improve simple depart swimming quiet snapshot enforce cultural view spray forward laden diagnose sugar human slice iris taste lift capital reject thumb nail hormone welcome trial preach rival dough universe romantic average kind very spelling galaxy reward watch tracks program yelp wrap wireless upgrade acid adequate apart echo educate alive category method liberty apart describe teammate scandal beard entrance declare airline omit space sharp",
      "garlic skin academic argue adult webcam elegant game woman should being force crush slavery percent trash browser symbolic watch terminal raisin extend permit various pickup dining boundary grumpy purple cleanup hesitate soldier august taught episode payroll should amuse artwork inform skin dress marathon deadline garbage safari software tofu artwork expand mule mother fitness owner spill prune starting grumpy station fused render wine acrobat diploma prepare sister analysis pajamas legend process rainbow dilemma infant racism modify debut pencil leaf ultimate scandal wireless boring depict tenant resident damage wrap thumb scroll acquire society receiver crucial carbon theater peasant ladybug national amazing emperor race smirk ranked income move similar shelter devote strategy advocate valid parking memory shelter crunch destroy viral filter bedroom news enemy quantity fortune human acquire magazine junior race domain eyebrow fatal density arena teammate surface invasion echo adorn diminish starting spray meaning jacket rebuild work rebound switch wine crucial fiscal",
      "garlic skin academic beard acne typical easel guilt training thunder energy prune adapt quick prepare charity random alto stadium fake view impulse genuine answer element hospital weapon paid both enforce wavy furl estate arena woman unhappy premium firefly smell method hormone voter punish goat sharp result regular oasis finance smoking perfect lilac language silent flavor method erode estate permit beaver puny premium therapy either training emperor genius blimp trust maiden pharmacy flame satoshi heat ecology starting cricket visitor industry vocal glimpse tendency moment move deliver taste theory bike mustang fatigue spew faint garlic climate flexible nuclear acquire broken execute sack famous mandate solution fragment energy leaf armed prepare suitable ruin mineral timely muscle hanger aide forget glance webcam symbolic username crush swimming family taught research flexible remind fawn mandate visual hairy yelp syndrome physics hawk salt element profile treat genre have beaver company steady priest agree elder taste pile adorn",
      "garlic skin academic blanket adult prevent hamster starting diploma drove decrease diploma valuable domestic robin hairy mineral mandate admit axle squeeze being easel dramatic numb lamp slap venture marvel luxury hazard findings medal class diagnose spend impulse froth freshman enlarge mansion hour furl survive radar lily screw mama retailer flame exceed prepare quarter merit liquid physics calcium grumpy group club liberty downtown package advance echo scandal jump luxury frozen wildlife ordinary satisfy network company patrol involve fridge visual failure exceed furl discuss mansion carbon temple enforce necklace merchant research friendly lobe frost cage mixture acquire bike drove keyboard helpful database galaxy retreat decrease ceiling canyon theater bumpy emphasis grownup pregnant tofu ladybug believe dish drove nuclear realize vexed unhappy simple prize pile escape recall insect easel group valid leaves scout science advance burning twice exact armed parking exotic trouble grief drink pink object sharp angel husky bolt saver admit method",
      "garlic skin academic broken adequate crush lobe away exhaust hairy dynamic necklace join family olympic capture quantity holy main beyond mayor company ounce treat founder vintage furl public legs obesity salon review gross hamster piece pants clothes artwork ranked friar aquatic faint math patrol trend lizard similar cradle holiday chubby geology nylon syndrome welcome enlarge rhyme gross moisture slice thank skin cinema cover year camera dream source easel ambition argue puny fluff move agree prospect nuclear pajamas bundle boundary threaten medal venture agency mental editor lair elephant acrobat duckling mouse blanket emphasis already realize champion alarm prayer friar criminal early dryer analysis luxury hamster romantic geology coding timber swimming debut unwrap burden bucket floral modify kernel scout already zero sunlight deploy false friar minister symbolic national keyboard lilac rapids iris unkind space railroad emerald coal document ranked wisdom fiber multiple genius mobile angry vegan texture adult mixed greatest darkness garden"
    ]
  }
];

function withGlobalCrypto<T>(cryptoValue: unknown, callback: () => T): T {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: cryptoValue
  });

  const restore = (): void => {
    if (descriptor) {
      Object.defineProperty(globalThis, "crypto", descriptor);
    } else {
      Reflect.deleteProperty(globalThis, "crypto");
    }
  };

  try {
    const result = callback();
    if (
      result &&
      typeof result === "object" &&
      "finally" in result &&
      typeof result.finally === "function"
    ) {
      return result.finally(restore) as T;
    }
    restore();
    return result;
  } catch (error) {
    restore();
    throw error;
  }
}

async function loadAppCore(
  crypto: TestCrypto = webcrypto as unknown as TestCrypto
): Promise<AppTestApi> {
  return {
    ...slip39,
    combineMnemonics: (mnemonics, passphrase) =>
      withGlobalCrypto(crypto, () => slip39.combineMnemonics(mnemonics, passphrase)),
    combineMnemonicsFlexible: (mnemonics, passphrase) =>
      withGlobalCrypto(crypto, () => slip39.combineMnemonicsFlexible(mnemonics, passphrase)),
    decodeTextMasterSecret: (bytes) =>
      withGlobalCrypto(crypto, () => slip39.decodeTextMasterSecret(bytes)),
    encodeTextMasterSecret: (value) =>
      withGlobalCrypto(crypto, () => slip39.encodeTextMasterSecret(value)),
    generateMnemonics: (threshold, shareCount, masterSecret, passphrase, options) =>
      withGlobalCrypto(crypto, () =>
        slip39.generateMnemonics(threshold, shareCount, masterSecret, passphrase, options)
      ),
    hasRequiredCrypto: () => withGlobalCrypto(crypto, () => slip39.hasRequiredCrypto()),
    isTextMasterSecretEnvelope: (bytes) =>
      withGlobalCrypto(crypto, () => slip39.isTextMasterSecretEnvelope(bytes)),
    splitSecret: (threshold, shareCount, sharedSecret) =>
      withGlobalCrypto(crypto, () => slip39.splitSecret(threshold, shareCount, sharedSecret))
  };
}

function deterministicCrypto(): TestCrypto {
  let counter = 0;
  return {
    subtle: webcrypto.subtle,
    getRandomValues(target: Uint8Array): Uint8Array {
      for (let index = 0; index < target.length; index += 1) {
        target[index] = counter & 0xff;
        counter = (counter + 1) & 0xff;
      }
      return target;
    }
  };
}

const appPromise = loadAppCore();

function asArray(bytes: Uint8Array): number[] {
  return [...bytes];
}

function bytesToHexLocal(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function thrownMessage(error: unknown): string {
  if (
    error &&
    typeof error === "object" &&
    "message" in error &&
    typeof (error as { message: unknown }).message === "string"
  ) {
    return (error as { message: string }).message;
  }
  assert.fail(`Expected thrown error with a message, got ${String(error)}`);
}

function writeUint32BigEndian(output: Uint8Array, offset: number, value: number): void {
  output[offset] = (value >>> 24) & 0xff;
  output[offset + 1] = (value >>> 16) & 0xff;
  output[offset + 2] = (value >>> 8) & 0xff;
  output[offset + 3] = value & 0xff;
}

function* combinations<T>(items: readonly T[], size: number): Generator<T[]> {
  if (size < 0 || size > items.length) {
    return;
  }
  if (size === 0) {
    yield [];
    return;
  }

  const current: T[] = [];

  function* visit(start: number): Generator<T[]> {
    if (current.length === size) {
      yield [...current];
      return;
    }

    const remaining = size - current.length;
    for (let index = start; index <= items.length - remaining; index += 1) {
      current.push(items[index]);
      yield* visit(index + 1);
      current.pop();
    }
  }

  yield* visit(0);
}

function validSingleGroupConfigs(): Array<[number, number]> {
  const configs: Array<[number, number]> = [];
  for (let threshold = 1; threshold <= 16; threshold += 1) {
    for (let shareCount = threshold; shareCount <= 16; shareCount += 1) {
      if (threshold === 1 && shareCount > 1) {
        continue;
      }
      configs.push([threshold, shareCount]);
    }
  }
  return configs;
}

async function retagTextEnvelope(bytes: Uint8Array): Promise<Uint8Array> {
  const digestInput = new Uint8Array(bytes);
  digestInput.fill(
    0,
    TEXT_ENVELOPE_TAG_OFFSET,
    TEXT_ENVELOPE_TAG_OFFSET + TEXT_ENVELOPE_TAG_LENGTH
  );
  const digest = new Uint8Array(await webcrypto.subtle.digest("SHA-256", digestInput));
  const output = new Uint8Array(bytes);
  output.set(digest.subarray(0, TEXT_ENVELOPE_TAG_LENGTH), TEXT_ENVELOPE_TAG_OFFSET);
  return output;
}

async function assertShareSetDoesNotRecoverText(
  app: AppTestApi,
  mnemonics: string[],
  passphrase: string,
  unexpectedText: string
): Promise<void> {
  try {
    const recovered = await app.combineMnemonics(mnemonics, passphrase);
    assert.notEqual(await app.decodeTextMasterSecret(recovered), unexpectedText);
  } catch (error) {
    assert.ok(error instanceof app.Slip39Error);
  }
}

function valuesSnapshot(
  map: Map<unknown, unknown>,
  originalValues: typeof Map.prototype.values
): unknown[] {
  return [...originalValues.call(map)];
}

function isStrictShareGroupValue(value: unknown): boolean {
  return (
    !!value &&
    typeof value === "object" &&
    "shares" in value &&
    value.shares instanceof Map &&
    "groupKeyValue" in value
  );
}

function isFlexibleGroupValue(value: unknown): boolean {
  return (
    !!value &&
    typeof value === "object" &&
    "groupKey" in value &&
    "sharesByMemberIndex" in value &&
    value.sharesByMemberIndex instanceof Map
  );
}

function isFlexibleEntryValue(value: unknown): boolean {
  return (
    !!value &&
    typeof value === "object" &&
    "mnemonic" in value &&
    typeof value.mnemonic === "string" &&
    "share" in value
  );
}

test("wordlist has the required size and unique entries", async () => {
  const { SLIP39_WORDS } = await appPromise;
  assert.equal(SLIP39_WORDS.length, 1024);
  assert.equal(new Set(SLIP39_WORDS).size, 1024);
});

test("required Web Crypto APIs are available", async () => {
  const { hasRequiredCrypto } = await appPromise;
  assert.equal(hasRequiredCrypto(), true);
});

test("GF(256) multiplication matches the AES field example", async () => {
  const { gfMultiply } = await appPromise;
  assert.equal(gfMultiply(0x57, 0x83), 0xc1);
  assert.equal(gfMultiply(0, 0x83), 0);
});

test("interpolation recovers a split secret", async () => {
  const { interpolate, splitSecret } = await appPromise;
  const shares = await splitSecret(2, 3, SECRET_16);
  assert.deepEqual(asArray(interpolate(shares.slice(0, 2), 255)), asArray(SECRET_16));
});

test("RS1024 checksum round trips", async () => {
  const { createChecksum, verifyChecksum } = await appPromise;
  const data = [0, 1, 2, 3, 4, 5, 6];
  const checksum = createChecksum(data, "shamir_extendable");
  assert.equal(checksum.length, 3);
  assert.equal(verifyChecksum([...data, ...checksum], "shamir_extendable"), true);
  assert.equal(
    verifyChecksum([...data, checksum[0], checksum[1], checksum[2] ^ 1], "shamir_extendable"),
    false
  );
});

test("mnemonic encode and decode round trip", async () => {
  const { Share, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "TREZOR", { identifier: 42 });
  const parsed = Share.fromMnemonic(shares[0]);
  assert.equal(parsed.toMnemonic(), shares[0]);
  assert.equal(parsed.identifier, 42);
  assert.equal(parsed.extendable, true);
  assert.equal(parsed.iterationExponent, 1);
  assert.equal(parsed.groupThreshold, 1);
  assert.equal(parsed.groupCount, 1);
  assert.equal(parsed.memberThreshold, 2);
});

test("single-group 2-of-3 generation and recovery works", async () => {
  const { bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "TREZOR");
  assert.equal(shares.length, 3);
  assert.equal(bytesToHex(await combineMnemonics([shares[0], shares[2]], "TREZOR")), SECRET_16_HEX);
});

test("single-group 3-of-5 generation and recovery works", async () => {
  const { bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(3, 5, SECRET_32, "");
  assert.equal(shares.length, 5);
  assert.equal(
    bytesToHex(await combineMnemonics([shares[1], shares[3], shares[4]], "")),
    SECRET_32_HEX
  );
});

test("deterministic generation fixtures are recoverable by Trezor reference", async () => {
  for (const fixture of REFERENCE_FIXTURES) {
    const app = await loadAppCore(deterministicCrypto());
    const shares = await app.generateMnemonics(
      fixture.threshold,
      fixture.shareCount,
      app.hexToBytes(fixture.secretHex),
      fixture.passphrase,
      fixture.options
    );

    assert.deepEqual([...shares], fixture.mnemonics, fixture.name);
    assert.equal(
      app.bytesToHex(
        await app.combineMnemonics(shares.slice(0, fixture.threshold), fixture.passphrase)
      ),
      fixture.secretHex,
      fixture.name
    );
  }
});

test("vendored deterministic interop matrix covers iteration exponent and checksum variants", async () => {
  const fixtures = JSON.parse(await readFile(INTEROP_MATRIX_PATH, "utf8"));
  for (const fixture of fixtures) {
    const app = await loadAppCore(deterministicCrypto());
    const shares = await app.generateMnemonics(
      fixture.threshold,
      fixture.shareCount,
      app.hexToBytes(fixture.secretHex),
      fixture.passphrase,
      {
        identifier: fixture.identifier,
        extendable: fixture.extendable,
        iterationExponent: fixture.iterationExponent
      }
    );

    assert.deepEqual([...shares], fixture.mnemonics, fixture.name);
    assert.equal(
      app.bytesToHex(
        await app.combineMnemonics(shares.slice(0, fixture.threshold), fixture.passphrase)
      ),
      fixture.secretHex,
      fixture.name
    );
  }
});

test("strict recovery still rejects surplus single-group shares", async () => {
  const { combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "");
  await assert.rejects(() => combineMnemonics(shares, ""), /Wrong number of mnemonics/);
});

test("flexible recovery accepts surplus and duplicate shares", async () => {
  const { bytesToHex, combineMnemonicsFlexible, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "");
  assert.equal(
    bytesToHex(await combineMnemonicsFlexible([shares[0], shares[1], shares[1], shares[2]], "")),
    SECRET_16_HEX
  );
});

test("flexible recovery rejects conflicting same-index shares", async () => {
  const { Share, combineMnemonicsFlexible, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "");
  const parsed = Share.fromMnemonic(shares[0]);
  const conflictingValue = new Uint8Array(parsed.value);
  conflictingValue[0] ^= 1;
  const conflictingShare = new Share(
    parsed.identifier,
    parsed.extendable,
    parsed.iterationExponent,
    parsed.groupIndex,
    parsed.groupThreshold,
    parsed.groupCount,
    parsed.index,
    parsed.memberThreshold,
    conflictingValue
  ).toMnemonic();

  await assert.rejects(
    () => combineMnemonicsFlexible([shares[0], conflictingShare, shares[1]], ""),
    /Conflicting mnemonic shares/
  );
});

test("flexible recovery rejects too many input lines before parsing", async () => {
  const { MAX_RECOVERY_INPUT_LINES, combineMnemonicsFlexible, generateMnemonics } =
    await appPromise;
  const [share] = await generateMnemonics(1, 1, SECRET_16, "", { identifier: 21 });
  const lines = Array.from({ length: MAX_RECOVERY_INPUT_LINES + 1 }, () => share);

  await assert.rejects(() => combineMnemonicsFlexible(lines, ""), /Too many mnemonic share lines/);
});

test("flexible recovery aborts too many candidate combinations", async () => {
  const { Share, combineMnemonicsFlexible } = await appPromise;
  const shares = Array.from({ length: 16 }, (_, shareIndex) =>
    new Share(
      22,
      true,
      1,
      0,
      1,
      1,
      shareIndex,
      8,
      Uint8Array.from({ length: 16 }, (_, byteIndex) => (shareIndex * 17 + byteIndex) & 0xff)
    ).toMnemonic()
  );

  await assert.rejects(
    () => combineMnemonicsFlexible(shares, ""),
    /Too many candidate combinations/
  );
});

test("hex helpers and master secret parsing validate pure byte input", async () => {
  const { bytesToHex, hexToBytes, normalizeHex, parseMasterSecretHex } = await appPromise;
  assert.deepEqual(asArray(hexToBytes("000102ff")), [0, 1, 2, 255]);
  assert.deepEqual(asArray(hexToBytes("00 01\n02\tff")), [0, 1, 2, 255]);
  assert.equal(bytesToHex(new Uint8Array([0, 1, 2, 255])), "000102ff");
  assert.equal(bytesToHex(ALL_BYTES), ALL_BYTES_HEX);
  assert.deepEqual(asArray(hexToBytes(ALL_BYTES_HEX.toUpperCase())), asArray(ALL_BYTES));
  assert.equal(
    normalizeHex(`  ${SECRET_16_HEX.slice(0, 12).toUpperCase()}\n${SECRET_16_HEX.slice(12)}  `),
    SECRET_16_HEX
  );
  assert.equal(
    bytesToHex(parseMasterSecretHex(`  ${SECRET_16_HEX.toUpperCase()}  `)),
    SECRET_16_HEX
  );

  assert.throws(() => parseMasterSecretHex(""), /empty/);
  assert.throws(() => parseMasterSecretHex("zz"), /hex digits and whitespace/);
  assert.throws(() => parseMasterSecretHex("00_01"), /hex digits and whitespace/);
  assert.throws(() => parseMasterSecretHex("0"), /odd number of digits/);
  assert.throws(() => parseMasterSecretHex("00".repeat(15)), /at least 16 bytes/);
  assert.throws(() => parseMasterSecretHex(`${SECRET_16_HEX}0`), /odd number of digits/);
  assert.throws(() => parseMasterSecretHex("00".repeat(17)), /multiple of 2/);
});

test("property: local hex encoder and decoder round-trip arbitrary bytes", async () => {
  const { bytesToHex, hexToBytes } = await appPromise;
  fc.assert(
    fc.property(fc.uint8Array({ minLength: 1, maxLength: 512 }), (bytes) => {
      const encoded = bytesToHex(bytes);
      assert.match(encoded, /^[0-9a-f]*$/);
      assert.equal(encoded.length, bytes.length * 2);
      assert.deepEqual(asArray(hexToBytes(encoded)), asArray(bytes));
    }),
    { numRuns: 1000 }
  );
});

test("hex parsing preserves exact validation error messages", async () => {
  const { parseMasterSecretHex } = await appPromise;
  const cases: Array<[string, string]> = [
    ["", "The master secret hex is empty."],
    ["zz", "The master secret hex can contain only hex digits and whitespace."],
    ["00_01", "The master secret hex can contain only hex digits and whitespace."],
    [
      "0",
      "The master secret hex has an odd number of digits. Add or remove one hex digit intentionally; this app will not auto-pad."
    ],
    ["00".repeat(15), "The master secret must be at least 16 bytes."],
    [
      "00".repeat(17),
      "The master secret byte length must be a multiple of 2. Add or remove a full byte intentionally; this app will not auto-pad."
    ]
  ];

  for (const [input, expectedMessage] of cases) {
    assert.throws(
      () => parseMasterSecretHex(input),
      (error: unknown) => {
        assert.equal(thrownMessage(error), expectedMessage);
        return true;
      }
    );
  }
});

test("text master secret envelopes round-trip user text", async () => {
  const {
    decodeTextMasterSecret,
    describeTextMasterSecret,
    encodeTextMasterSecret,
    isTextMasterSecretEnvelope
  } = await loadAppCore(deterministicCrypto());
  const cases = [
    "plain ASCII text",
    "Unicode text: snowman ☃ and emoji \u{1f642}",
    "  leading whitespace\nand trailing whitespace  ",
    "",
    "a",
    "ab"
  ];

  for (const text of cases) {
    const info = describeTextMasterSecret(text);
    const encoded = await encodeTextMasterSecret(text);
    assert.equal(info.utf8ByteLength, utf8Length(text));
    assert.equal(info.paddingByteLength, info.utf8ByteLength % 2);
    assert.equal(encoded.length, info.masterSecretByteLength);
    assert.equal(encoded.length % 2, 0);
    assert.ok(encoded.length >= 16);
    assert.equal(await isTextMasterSecretEnvelope(encoded), true);
    assert.equal(await decodeTextMasterSecret(encoded), text);
  }
});

test("text envelope decoder ignores unsupported or malformed bytes", async () => {
  const { decodeTextMasterSecret, encodeTextMasterSecret, isTextMasterSecretEnvelope } =
    await loadAppCore(deterministicCrypto());
  const valid = await encodeTextMasterSecret("a");
  const badVersion = new Uint8Array(valid);
  badVersion["SLIP39TXT".length] = 2;
  const badLength = new Uint8Array(valid);
  badLength["SLIP39TXT".length + 1] = 0xff;
  const missingPadding = valid.slice(0, -1);
  const invalidUtf8 = new Uint8Array(32);
  invalidUtf8.set(Uint8Array.from("SLIP39TXT", (char) => char.charCodeAt(0)));
  invalidUtf8["SLIP39TXT".length] = 1;
  invalidUtf8["SLIP39TXT".length + 4] = 1;
  invalidUtf8[30] = 0xff;

  for (const bytes of [SECRET_16, badVersion, badLength, missingPadding, invalidUtf8]) {
    assert.equal(await isTextMasterSecretEnvelope(bytes), false);
    assert.equal(await decodeTextMasterSecret(bytes), null);
  }
});

test("text envelope tag detects payload tampering", async () => {
  const { decodeTextMasterSecret, encodeTextMasterSecret, isTextMasterSecretEnvelope } =
    await loadAppCore(deterministicCrypto());
  const encoded = await encodeTextMasterSecret("hello world");
  const PAYLOAD_OFFSET = "SLIP39TXT".length + 1 + 4 + 16;
  const tampered = new Uint8Array(encoded);
  tampered[PAYLOAD_OFFSET] ^= 1;
  assert.equal(await isTextMasterSecretEnvelope(tampered), false);
  assert.equal(await decodeTextMasterSecret(tampered), null);

  const tamperedTag = new Uint8Array(encoded);
  tamperedTag["SLIP39TXT".length + 1 + 4] ^= 1;
  assert.equal(await decodeTextMasterSecret(tamperedTag), null);
});

test("text envelopes remain standard SLIP-0039 master-secret bytes", async () => {
  const app = await loadAppCore(deterministicCrypto());
  const encoded = await app.encodeTextMasterSecret("recover me\nexactly");
  const shares = await app.generateMnemonics(2, 3, encoded, "");
  const recovered = await app.combineMnemonics([shares[0], shares[1]], "");
  assert.deepEqual(asArray(recovered), asArray(encoded));
  assert.equal(await app.decodeTextMasterSecret(recovered), "recover me\nexactly");
});

test(
  "text sharing deterministic golden vectors cover text-to-parts",
  { timeout: 120000 },
  async () => {
    for (const fixture of TEXT_SHARING_FIXTURES) {
      const app = await loadAppCore(deterministicCrypto());
      const described = app.describeTextMasterSecret(fixture.text);
      const encoded = await app.encodeTextMasterSecret(fixture.text);
      const shares = await app.generateMnemonics(
        fixture.threshold,
        fixture.shareCount,
        encoded,
        fixture.passphrase,
        fixture.options
      );

      assert.deepEqual(described, fixture.info, fixture.name);
      assert.equal(app.bytesToHex(encoded), fixture.encodedHex, fixture.name);
      assert.equal(await app.isTextMasterSecretEnvelope(encoded), true, fixture.name);
      assert.equal(await app.decodeTextMasterSecret(encoded), fixture.text, fixture.name);
      assert.equal(shares.length, fixture.shareCount, fixture.name);
      assert.deepEqual([...shares], fixture.mnemonics, fixture.name);

      const parsedShares = shares.map((share) => app.Share.fromMnemonic(share));
      assert.equal(new Set(parsedShares.map((share) => share.index)).size, fixture.shareCount);
      for (const [shareIndex, share] of parsedShares.entries()) {
        assert.equal(share.identifier, fixture.options.identifier, fixture.name);
        assert.equal(share.extendable, fixture.options.extendable ?? true, fixture.name);
        assert.equal(share.iterationExponent, fixture.options.iterationExponent ?? 1, fixture.name);
        assert.equal(share.groupIndex, 0, fixture.name);
        assert.equal(share.groupThreshold, 1, fixture.name);
        assert.equal(share.groupCount, 1, fixture.name);
        assert.equal(share.index, shareIndex, fixture.name);
        assert.equal(share.memberThreshold, fixture.threshold, fixture.name);
        assert.equal(share.toMnemonic(), shares[shareIndex], fixture.name);
      }

      const recovered = await app.combineMnemonics(
        shares.slice(0, fixture.threshold),
        fixture.passphrase
      );
      assert.equal(app.bytesToHex(recovered), fixture.encodedHex, fixture.name);
      assert.equal(await app.decodeTextMasterSecret(recovered), fixture.text, fixture.name);
    }
  }
);

test("text sharing generated parts cover all valid single-group configurations", async () => {
  const app = await loadAppCore(deterministicCrypto());
  const encoded = await app.encodeTextMasterSecret("metadata coverage text");

  for (const [threshold, shareCount] of validSingleGroupConfigs()) {
    const shares = await app.generateMnemonics(threshold, shareCount, encoded, "", {
      identifier: 777,
      iterationExponent: 0,
      extendable: false
    });
    const parsedShares = shares.map((share) => app.Share.fromMnemonic(share));

    assert.equal(shares.length, shareCount, `${threshold}-of-${shareCount}`);
    assert.equal(new Set(shares).size, shareCount, `${threshold}-of-${shareCount}`);
    assert.deepEqual(
      parsedShares.map((share) => share.index),
      Array.from({ length: shareCount }, (_, index) => index),
      `${threshold}-of-${shareCount}`
    );

    for (const share of parsedShares) {
      assert.equal(share.identifier, 777, `${threshold}-of-${shareCount}`);
      assert.equal(share.extendable, false, `${threshold}-of-${shareCount}`);
      assert.equal(share.iterationExponent, 0, `${threshold}-of-${shareCount}`);
      assert.equal(share.groupIndex, 0, `${threshold}-of-${shareCount}`);
      assert.equal(share.groupThreshold, 1, `${threshold}-of-${shareCount}`);
      assert.equal(share.groupCount, 1, `${threshold}-of-${shareCount}`);
      assert.equal(share.memberThreshold, threshold, `${threshold}-of-${shareCount}`);
    }
  }
});

test(
  "text sharing recovers from every threshold-sized subset in representative configs",
  { timeout: 120000 },
  async () => {
    const representativeConfigs: Array<[number, number]> = [
      [1, 1],
      [2, 2],
      [2, 3],
      [2, 5],
      [3, 5],
      [4, 6],
      [5, 7]
    ];

    for (const [threshold, shareCount] of representativeConfigs) {
      const app = await loadAppCore(deterministicCrypto());
      const text = `threshold subset recovery ${threshold}-of-${shareCount}`;
      const encoded = await app.encodeTextMasterSecret(text);
      const shares = await app.generateMnemonics(
        threshold,
        shareCount,
        encoded,
        "subset passphrase !",
        {
          identifier: 900 + threshold * 16 + shareCount,
          iterationExponent: 0,
          extendable: threshold % 2 === 0
        }
      );

      for (const subset of combinations(shares, threshold)) {
        const recovered = await app.combineMnemonics(subset, "subset passphrase !");
        assert.equal(
          await app.decodeTextMasterSecret(recovered),
          text,
          `${threshold}-of-${shareCount}`
        );
      }
    }
  }
);

test("text sharing negative recovery cases do not recover the target text", async () => {
  const app = await loadAppCore(deterministicCrypto());
  const text = "negative recovery text with exact threshold semantics";
  const encoded = await app.encodeTextMasterSecret(text);
  const shares = await app.generateMnemonics(3, 5, encoded, "negative passphrase", {
    identifier: 222,
    iterationExponent: 0,
    extendable: true
  });

  for (const insufficient of combinations(shares, 2)) {
    await assertShareSetDoesNotRecoverText(app, insufficient, "negative passphrase", text);
  }

  await assert.rejects(
    () => app.combineMnemonics([shares[0], shares[1], shares[2], shares[3]], "negative passphrase"),
    /Wrong number of mnemonics/
  );
  await assert.rejects(
    () => app.combineMnemonics([shares[0], shares[0], shares[1]], "negative passphrase"),
    /unique/
  );

  const flexibleRecovered = await app.combineMnemonicsFlexible(
    [shares[0], shares[1], shares[1], shares[2], shares[3], shares[4]],
    "negative passphrase"
  );
  assert.equal(await app.decodeTextMasterSecret(flexibleRecovered), text);

  const wrongPassphraseRecovered = await app.combineMnemonics(
    shares.slice(0, 3),
    "wrong passphrase"
  );
  assert.notEqual(await app.decodeTextMasterSecret(wrongPassphraseRecovered), text);
  assert.equal(await app.isTextMasterSecretEnvelope(wrongPassphraseRecovered), false);
});

test("text sharing rejects tampered and mixed share sets", async () => {
  const app = await loadAppCore(deterministicCrypto());
  const firstText = "first mixed text";
  const secondText = "second mixed text";
  const firstEncoded = await app.encodeTextMasterSecret(firstText);
  const secondEncoded = await app.encodeTextMasterSecret(secondText);
  const firstShares = await app.generateMnemonics(2, 3, firstEncoded, "shared passphrase", {
    identifier: 314,
    iterationExponent: 0,
    extendable: true
  });
  const secondShares = await app.generateMnemonics(2, 3, secondEncoded, "shared passphrase", {
    identifier: 314,
    iterationExponent: 0,
    extendable: true
  });
  const differentPassphraseShares = await app.generateMnemonics(
    2,
    3,
    firstEncoded,
    "different passphrase",
    {
      identifier: 314,
      iterationExponent: 0,
      extendable: true
    }
  );
  const differentOptionShares = await app.generateMnemonics(
    2,
    3,
    firstEncoded,
    "shared passphrase",
    {
      identifier: 315,
      iterationExponent: 0,
      extendable: false
    }
  );

  await assertShareSetDoesNotRecoverText(
    app,
    [firstShares[0], secondShares[1]],
    "shared passphrase",
    firstText
  );
  await assertShareSetDoesNotRecoverText(
    app,
    [firstShares[0], differentPassphraseShares[1]],
    "shared passphrase",
    firstText
  );
  await assert.rejects(
    () => app.combineMnemonics([firstShares[0], differentOptionShares[1]], "shared passphrase"),
    /same 2 words|Group parameters/
  );

  const tamperedWords = firstShares[0].split(" ");
  tamperedWords[tamperedWords.length - 1] =
    tamperedWords[tamperedWords.length - 1] === "academic" ? "acid" : "academic";
  await assert.rejects(
    () => app.combineMnemonics([tamperedWords.join(" "), firstShares[1]], "shared passphrase"),
    /checksum/
  );

  const recovered = await app.combineMnemonics(
    [firstShares[0], firstShares[1]],
    "shared passphrase"
  );
  const corruptedEnvelope = new Uint8Array(recovered);
  corruptedEnvelope[TEXT_ENVELOPE_PAYLOAD_OFFSET] ^= 1;
  assert.equal(await app.isTextMasterSecretEnvelope(corruptedEnvelope), false);
  assert.equal(await app.decodeTextMasterSecret(corruptedEnvelope), null);
});

test("text envelope decoder rejects structural corruption classes", async () => {
  const app = await loadAppCore(deterministicCrypto());
  const valid = await app.encodeTextMasterSecret("integrity text");
  const validWithPadding = await app.encodeTextMasterSecret("A");
  const wrongMagic = new Uint8Array(valid);
  wrongMagic[0] ^= 1;
  const badVersion = new Uint8Array(valid);
  badVersion[TEXT_ENVELOPE_VERSION_OFFSET] = 2;
  const oversizedLength = new Uint8Array(valid);
  writeUint32BigEndian(oversizedLength, TEXT_ENVELOPE_LENGTH_OFFSET, 0xffffffff);
  const missingPadding = validWithPadding.slice(0, -1);
  const tamperedTag = new Uint8Array(valid);
  tamperedTag[TEXT_ENVELOPE_TAG_OFFSET] ^= 1;
  const tamperedPayload = new Uint8Array(valid);
  tamperedPayload[TEXT_ENVELOPE_PAYLOAD_OFFSET] ^= 1;
  const tamperedPadding = new Uint8Array(validWithPadding);
  tamperedPadding[tamperedPadding.length - 1] ^= 1;
  const invalidUtf8 = new Uint8Array(validWithPadding);
  invalidUtf8[TEXT_ENVELOPE_PAYLOAD_OFFSET] = 0xff;
  const retaggedInvalidUtf8 = await retagTextEnvelope(invalidUtf8);

  for (const bytes of [
    new Uint8Array(),
    valid.slice(0, TEXT_ENVELOPE_PAYLOAD_OFFSET - 1),
    wrongMagic,
    badVersion,
    oversizedLength,
    missingPadding,
    tamperedTag,
    tamperedPayload,
    tamperedPadding,
    retaggedInvalidUtf8
  ]) {
    assert.equal(await app.isTextMasterSecretEnvelope(bytes), false);
    assert.equal(await app.decodeTextMasterSecret(bytes), null);
  }
});

test("text APIs reject non-text and non-byte inputs", async () => {
  const app = await appPromise;

  assert.throws(
    () => app.describeTextMasterSecret(123 as unknown as string),
    /text master secret must be a string/
  );
  await assert.rejects(
    () => app.encodeTextMasterSecret(123 as unknown as string),
    /text master secret must be a string/
  );
  await assert.rejects(
    () => app.generateMnemonics(2, 3, "not bytes" as unknown as Uint8Array, ""),
    /master secret must be bytes/
  );
  assert.equal(await app.decodeTextMasterSecret("not bytes" as unknown as Uint8Array), null);
  assert.equal(await app.isTextMasterSecretEnvelope({} as unknown as Uint8Array), false);
});

test("official SLIP-0039 vector secrets are not text envelopes", async () => {
  const { combineMnemonics, decodeTextMasterSecret, isTextMasterSecretEnvelope } = await appPromise;
  const vectors = JSON.parse(await readFile(VECTOR_PATH, "utf8"));
  let checkedCount = 0;

  for (const [description, mnemonics, secretHex] of vectors) {
    if (!secretHex) {
      continue;
    }

    const recovered = await combineMnemonics(mnemonics, "TREZOR");
    assert.equal(await isTextMasterSecretEnvelope(recovered), false, description);
    assert.equal(await decodeTextMasterSecret(recovered), null, description);
    checkedCount += 1;
  }

  assert.ok(checkedCount > 0);
});

test("standard validation rejects invalid generation parameters", async () => {
  const { generateMnemonics } = await appPromise;
  await assert.rejects(() => generateMnemonics(2, 17, SECRET_16, ""), /must not exceed 16/);
  await assert.rejects(() => generateMnemonics(1, 2, SECRET_16, ""), /requires 1-of-1/);
  await assert.rejects(() => generateMnemonics(2, 3, SECRET_16, "bad☃"), /printable ASCII/);
  await assert.rejects(
    () => generateMnemonics(2, 3, SECRET_16, "", { identifier: -1 }),
    /identifier/
  );
  await assert.rejects(
    () => generateMnemonics(2, 3, SECRET_16, "", { identifier: 32768 }),
    /identifier/
  );
});

test("parsed shares reject invalid checksum, duplicates, mismatches, and group index", async () => {
  const { Share, combineMnemonics, generateMnemonics } = await appPromise;
  const first = await generateMnemonics(2, 3, SECRET_16, "TREZOR");
  const second = await generateMnemonics(2, 3, SECRET_16, "TREZOR");
  const words = first[0].split(" ");
  words[words.length - 1] = words[words.length - 1] === "academic" ? "acid" : "academic";
  const invalidGroupIndex = new Share(42, true, 1, 1, 1, 1, 0, 1, SECRET_16).toMnemonic();

  await assert.rejects(() => combineMnemonics([words.join(" "), first[1]], "TREZOR"), /checksum/);
  await assert.rejects(() => combineMnemonics([first[0], first[0]], "TREZOR"), /unique/);
  await assert.rejects(() => combineMnemonics([first[0]], "TREZOR"), /Wrong number/);
  await assert.rejects(() => combineMnemonics([first[0], second[0]], "TREZOR"), /same 2 words/);
  assert.throws(() => Share.fromMnemonic(invalidGroupIndex), /Group index/);
});

test("splitSecret rejects non-Uint8Array and short shared secrets", async () => {
  const { splitSecret } = await appPromise;
  await assert.rejects(
    () => splitSecret(2, 3, new Uint8Array(4)),
    (error: unknown) => {
      assert.match(thrownMessage(error), /at least \d+ bytes/);
      return true;
    }
  );
  await assert.rejects(
    () => splitSecret(2, 3, "not bytes" as unknown as Uint8Array),
    (error: unknown) => {
      assert.match(thrownMessage(error), /Uint8Array/);
      return true;
    }
  );
});

test("encrypt does not mutate the caller's master secret buffer", async () => {
  const app = await loadAppCore(deterministicCrypto());
  const original = new Uint8Array(SECRET_16);
  const snapshot = new Uint8Array(SECRET_16);
  await app.generateMnemonics(2, 3, original, "TREZOR", { identifier: 7 });
  assert.deepEqual(asArray(original), asArray(snapshot));
});

test(
  "combineMnemonics zeroizes its internal passphrase buffer",
  { concurrency: false },
  async () => {
    const passphrase = "sensitive-passphrase-0123456789";
    const passphraseBytes = new TextEncoder().encode(passphrase);
    const shares = await generateMnemonicsSource(2, 3, SECRET_16, passphrase, { identifier: 99 });
    const originalFill = Uint8Array.prototype.fill;
    let observedPassphraseZeroize = false;

    Uint8Array.prototype.fill = function patchedFill(
      this: Uint8Array,
      value: number,
      ...rest: number[]
    ): Uint8Array {
      const before = new Uint8Array(this);
      const result = originalFill.call(this, value, ...rest);

      if (value === 0 && rest.length === 0 && before.length === passphraseBytes.length) {
        const matchesPassphrase = before.every((byte, index) => byte === passphraseBytes[index]);
        const isZeroized = this.every((byte) => byte === 0);
        if (matchesPassphrase && isZeroized) {
          observedPassphraseZeroize = true;
        }
      }

      return result;
    } as typeof Uint8Array.prototype.fill;

    try {
      await combineMnemonicsSource([shares[0], shares[1]], passphrase);
    } finally {
      Uint8Array.prototype.fill = originalFill;
    }

    assert.equal(observedPassphraseZeroize, true);
  }
);

test("flexible recovery aggregates mixed root causes across failed subsets", async () => {
  const { Share, combineMnemonicsFlexible } = await appPromise;

  const lengthMismatchGroupFirst = new Share(
    777,
    true,
    1,
    0,
    1,
    2,
    0,
    2,
    Uint8Array.from({ length: 16 }, (_, index) => index)
  ).toMnemonic();
  const lengthMismatchGroupSecond = new Share(
    777,
    true,
    1,
    0,
    1,
    2,
    1,
    2,
    Uint8Array.from({ length: 18 }, (_, index) => (index + 1) & 0xff)
  ).toMnemonic();
  const digestFailureGroupFirst = new Share(
    777,
    true,
    1,
    1,
    1,
    2,
    0,
    2,
    Uint8Array.from({ length: 16 }, (_, index) => (index + 17) & 0xff)
  ).toMnemonic();
  const digestFailureGroupSecond = new Share(
    777,
    true,
    1,
    1,
    1,
    2,
    1,
    2,
    Uint8Array.from({ length: 16 }, (_, index) => (index + 33) & 0xff)
  ).toMnemonic();

  await assert.rejects(
    () =>
      combineMnemonicsFlexible(
        [
          lengthMismatchGroupFirst,
          lengthMismatchGroupSecond,
          digestFailureGroupFirst,
          digestFailureGroupSecond
        ],
        ""
      ),
    (error: unknown) => {
      const message = thrownMessage(error);
      assert.match(message, /No valid threshold-complete mnemonic subset was found/);
      assert.match(message, /Tried 2 combinations/);
      assert.match(message, /All share values must have the same length/);
      assert.match(message, /Invalid digest of the shared secret/);
      return true;
    }
  );
});

test("flexible recovery reports a sole subset failure directly", async () => {
  const { Share, combineMnemonicsFlexible } = await appPromise;
  const shares = Array.from({ length: 3 }, (_, shareIndex) =>
    new Share(
      778,
      true,
      1,
      0,
      1,
      1,
      shareIndex,
      2,
      Uint8Array.from({ length: 16 }, (_, byteIndex) => (shareIndex * 29 + byteIndex) & 0xff)
    ).toMnemonic()
  );

  await assert.rejects(
    () => combineMnemonicsFlexible(shares, ""),
    (error: unknown) => {
      const message = thrownMessage(error);
      assert.match(message, /Invalid digest of the shared secret/);
      assert.doesNotMatch(message, /No valid threshold-complete mnemonic subset was found/);
      return true;
    }
  );
});

test("strict recovery reports defensive internal map invariant failures", async () => {
  const { combineMnemonics, generateMnemonics, Share } = await appPromise;
  const [share] = await generateMnemonics(1, 1, SECRET_16, "", { identifier: 780 });
  const originalGet = Map.prototype.get;
  const originalValues = Map.prototype.values;
  const sizeDescriptor = Object.getOwnPropertyDescriptor(Map.prototype, "size");
  assert.ok(sizeDescriptor?.get);

  try {
    Map.prototype.get = function patchedGet(this: Map<unknown, unknown>, key: unknown): unknown {
      const value = originalGet.call(this, key);
      return isStrictShareGroupValue(value) ? undefined : value;
    } as typeof Map.prototype.get;
    await assert.rejects(() => combineMnemonics([share], ""), /Invalid mnemonic group state/);

    Map.prototype.get = originalGet;
    Map.prototype.values = function patchedValues(
      this: Map<unknown, unknown>
    ): IterableIterator<unknown> {
      const values = valuesSnapshot(this, originalValues);
      return values.length > 0 && values.every((value) => value instanceof Share)
        ? [][Symbol.iterator]()
        : originalValues.call(this);
    } as typeof Map.prototype.values;
    await assert.rejects(() => combineMnemonics([share], ""), /share group is empty/);

    Map.prototype.values = originalValues;
    Object.defineProperty(Map.prototype, "size", {
      configurable: true,
      get(this: Map<unknown, unknown>): number {
        return valuesSnapshot(this, originalValues).some(isStrictShareGroupValue)
          ? 0
          : sizeDescriptor.get?.call(this);
      }
    });
    await assert.rejects(() => combineMnemonics([share], ""), /set of shares is empty/);

    Object.defineProperty(Map.prototype, "size", sizeDescriptor);
    Map.prototype.values = function patchedEmptyGroupValues(
      this: Map<unknown, unknown>
    ): IterableIterator<unknown> {
      const values = valuesSnapshot(this, originalValues);
      return values.some(isStrictShareGroupValue)
        ? [][Symbol.iterator]()
        : originalValues.call(this);
    } as typeof Map.prototype.values;
    await assert.rejects(() => combineMnemonics([share], ""), /set of shares is empty/);
  } finally {
    Map.prototype.get = originalGet;
    Map.prototype.values = originalValues;
    Object.defineProperty(Map.prototype, "size", sizeDescriptor);
  }
});

test("flexible recovery reports defensive internal map invariant failures", async () => {
  const { Share, combineMnemonicsFlexible, generateMnemonics } = await appPromise;
  const [share] = await generateMnemonics(1, 1, SECRET_16, "", { identifier: 781 });
  const originalGet = Map.prototype.get;
  const originalValues = Map.prototype.values;
  const originalSetHas = Set.prototype.has;
  const originalFromMnemonic = Share.fromMnemonic;

  try {
    Map.prototype.get = function patchedGet(this: Map<unknown, unknown>, key: unknown): unknown {
      const value = originalGet.call(this, key);
      return isFlexibleGroupValue(value) ? undefined : value;
    } as typeof Map.prototype.get;
    await assert.rejects(
      () => combineMnemonicsFlexible([share], ""),
      /Invalid mnemonic group state/
    );

    Map.prototype.get = originalGet;
    Map.prototype.values = function patchedEmptyFlexibleGroups(
      this: Map<unknown, unknown>
    ): IterableIterator<unknown> {
      const values = valuesSnapshot(this, originalValues);
      return values.some(isFlexibleGroupValue) ? [][Symbol.iterator]() : originalValues.call(this);
    } as typeof Map.prototype.values;
    await assert.rejects(() => combineMnemonicsFlexible([share], ""), /list of mnemonics is empty/);

    Map.prototype.values = function patchedEmptyFlexibleEntries(
      this: Map<unknown, unknown>
    ): IterableIterator<unknown> {
      const values = valuesSnapshot(this, originalValues);
      return values.some(isFlexibleEntryValue) ? [][Symbol.iterator]() : originalValues.call(this);
    } as typeof Map.prototype.values;
    await assert.rejects(() => combineMnemonicsFlexible([share], ""), /list of mnemonics is empty/);

    let entryValuesCallCount = 0;
    Map.prototype.values = function patchedLaterEmptyFlexibleEntries(
      this: Map<unknown, unknown>
    ): IterableIterator<unknown> {
      const values = valuesSnapshot(this, originalValues);
      if (values.some(isFlexibleEntryValue)) {
        entryValuesCallCount += 1;
        return entryValuesCallCount === 1 ? originalValues.call(this) : [][Symbol.iterator]();
      }
      return originalValues.call(this);
    } as typeof Map.prototype.values;
    await assert.rejects(
      () => combineMnemonicsFlexible([share], ""),
      /Invalid mnemonic group state/
    );

    Map.prototype.values = originalValues;
    const fakeShare = (groupThreshold: number): InstanceType<typeof Share> =>
      ({
        groupIndex: 0,
        groupThreshold,
        index: 0,
        memberThreshold: 1,
        commonKey: () => `fake-common-${groupThreshold}`,
        groupKey: () => `fake-group-${groupThreshold}`,
        toMnemonic: () => `fake mnemonic ${groupThreshold}`
      }) as InstanceType<typeof Share>;

    Share.fromMnemonic = (() => fakeShare(-1)) as typeof Share.fromMnemonic;
    await assert.rejects(
      () => combineMnemonicsFlexible(["synthetic"], ""),
      /No valid threshold-complete mnemonic subset was found/
    );

    Share.fromMnemonic = (() => fakeShare(0)) as typeof Share.fromMnemonic;
    await assert.rejects(
      () => combineMnemonicsFlexible(["synthetic"], ""),
      /list of mnemonics is empty/
    );

    const duplicateFakeShare = fakeShare(-1);
    duplicateFakeShare.toMnemonic = () => "fake mnemonic duplicate";
    Share.fromMnemonic = (() => duplicateFakeShare) as typeof Share.fromMnemonic;
    Set.prototype.has = function patchedSetHas(this: Set<unknown>, value: unknown): boolean {
      return value === "fake mnemonic duplicate" ? false : originalSetHas.call(this, value);
    } as typeof Set.prototype.has;
    await assert.rejects(
      () => combineMnemonicsFlexible(["synthetic", "synthetic"], ""),
      /No valid threshold-complete mnemonic subset was found/
    );
  } finally {
    Map.prototype.get = originalGet;
    Map.prototype.values = originalValues;
    Set.prototype.has = originalSetHas;
    Share.fromMnemonic = originalFromMnemonic;
  }
});

test("wrong passphrase returns different bytes without app-specific rejection", async () => {
  const { bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "TREZOR");
  const recovered = await combineMnemonics([shares[0], shares[1]], "WRONG");
  assert.equal(recovered.length, SECRET_16.length);
  assert.notEqual(bytesToHex(recovered), SECRET_16_HEX);
});

test(
  "property: generate/combine round-trip for secret length, threshold, and passphrase variants",
  { timeout: 120000 },
  async () => {
    const { bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(16, 32),
        ROUND_TRIP_PARAMETERS_ARBITRARY,
        PRINTABLE_ASCII_ARBITRARY,
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        INDEX_PERMUTATION_ARBITRARY,
        async (
          secretLength,
          [threshold, shareCount],
          passphrase,
          randomBytes,
          indexPermutation
        ) => {
          const secret = randomBytes.slice(0, secretLength);
          const mnemonics = await generateMnemonics(threshold, shareCount, secret, passphrase, {
            identifier: 1
          });
          const subset = indexPermutation
            .filter((index) => index < shareCount)
            .slice(0, threshold)
            .map((index) => mnemonics[index]);
          const recovered = await combineMnemonics(subset, passphrase);
          assert.equal(bytesToHex(recovered), bytesToHexLocal(secret));
        }
      ),
      { numRuns: 50 }
    );
  }
);

test("property: combining fewer than threshold shares never deterministically recovers the secret", async () => {
  const { Slip39Error, bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  await fc.assert(
    fc.asyncProperty(
      THRESHOLD_PARAMETERS_ARBITRARY,
      INDEX_PERMUTATION_ARBITRARY,
      async ([threshold, shareCount], indexPermutation) => {
        const mnemonics = await generateMnemonics(threshold, shareCount, SECRET_16, "", {
          identifier: 1
        });
        const insufficient = indexPermutation
          .filter((index) => index < shareCount)
          .slice(0, threshold - 1)
          .map((index) => mnemonics[index]);

        try {
          const recovered = await combineMnemonics(insufficient, "");
          assert.notEqual(bytesToHex(recovered), SECRET_16_HEX);
        } catch (error) {
          assert.ok(error instanceof Slip39Error);
        }
      }
    ),
    { numRuns: 100 }
  );
});

test("property: GF(256) multiplication obeys associative, commutative, and identity laws", async () => {
  const { gfMultiply } = await appPromise;
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 255 }),
      fc.integer({ min: 1, max: 255 }),
      fc.integer({ min: 1, max: 255 }),
      (a, b, c) => {
        assert.equal(gfMultiply(a, gfMultiply(b, c)), gfMultiply(gfMultiply(a, b), c));
        assert.equal(gfMultiply(a, b), gfMultiply(b, a));
        assert.equal(gfMultiply(a, 1), a);
      }
    ),
    { numRuns: 1000 }
  );
});

test("recovery supports original and extendable checksum variants", async () => {
  const { Share, bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  const original = await generateMnemonics(2, 3, SECRET_16, "", {
    identifier: 42,
    extendable: false
  });
  const extendable = await generateMnemonics(2, 3, SECRET_16, "", {
    identifier: 42,
    extendable: true
  });

  assert.equal(Share.fromMnemonic(original[0]).extendable, false);
  assert.equal(Share.fromMnemonic(extendable[0]).extendable, true);
  assert.equal(bytesToHex(await combineMnemonics([original[0], original[1]], "")), SECRET_16_HEX);
  assert.equal(
    bytesToHex(await combineMnemonics([extendable[0], extendable[1]], "")),
    SECRET_16_HEX
  );
});

test("non-ASCII recovery passphrases are rejected", async () => {
  const { combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "");
  await assert.rejects(() => combineMnemonics([shares[0], shares[1]], "bad☃"), /printable ASCII/);
});

test("vendored official Trezor SLIP-0039 vectors", async () => {
  const { Slip39Error, bytesToHex, combineMnemonics } = await appPromise;
  const vectors = JSON.parse(await readFile(VECTOR_PATH, "utf8"));
  const coverage = {
    valid128: false,
    valid256: false,
    invalid128: false,
    invalid256: false
  };

  for (const [description, mnemonics, secretHex] of vectors) {
    if (secretHex) {
      const recovered = await combineMnemonics(mnemonics, "TREZOR");
      assert.equal(bytesToHex(recovered), secretHex, description);
      coverage.valid128 ||= recovered.length === 16;
      coverage.valid256 ||= recovered.length === 32;
    } else {
      await assert.rejects(() => combineMnemonics(mnemonics, ""), Slip39Error, description);
      coverage.invalid128 ||=
        description.includes("128 bits") || description.includes("insufficient length");
      coverage.invalid256 ||= description.includes("256 bits");
    }
  }

  assert.deepEqual(coverage, {
    valid128: true,
    valid256: true,
    invalid128: true,
    invalid256: true
  });
});
