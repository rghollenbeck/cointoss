// cointoss: A Linux command-line tool for generating Bitcoin BIP39 seed phrases.
//
// Functions Overview:
// 1. parse_arguments(): Parses command-line arguments using the clap crate to determine the desired entropy size.
// 2. prompt_coin_flips(): Guides the user through entering or generating 128 coin tosses for entropy.
// 3. generate_checksum(): Appends a checksum to the bitstream based on BIP39 standards.
// 4. bitstream_to_mnemonic(): Converts the final bitstream into a valid mnemonic by mapping bits to the BIP39 wordlist.
//
// This program supports generating entropy for 12, 15, 18, 21, or 24-word BIP39 seed phrases, ensuring
// compatibility with wallet standards. It includes user-friendly error handling and detailed guidance throughout.
//
// Usage:
//   - Run with the appropriate entropy flag: `--12`, `--15`, etc.
//   - For help: `--help`

/* 
## Function Overview for `main.rs`

This section provides a summary of the functions used in this program and their purpose. 
The functions are ordered to follow the logical flow of the program's workflow.

### 1. `parse_args`
**Purpose**: Parses command-line arguments to determine the number of seed phrase words (12, 15, 18, 21, or 24) or display the help message. 
**Details**: Ensures valid input and sets the appropriate number of coin tosses required based on the entropy size.

---

### 2. `prompt_for_coin_tosses`
**Purpose**: Guides the user through entering coin flips (`h` for heads, `t` for tails), randomizing remaining flips, or exiting the program. 
**Details**: Handles input validation and builds the initial entropy bitstream.

---

### 3. `fill_bitstream_with_heads`
**Purpose**: Fills the bitstream with all heads (`1`) when the user selects the `fill` option.
**Details**: Used for testing purposes to generate predictable entropy for debugging.

---

### 4. `calculate_checksum`
**Purpose**: Calculates the checksum bits for the given entropy using SHA-256. 
**Details**: Extracts the first `(ENT / 32)` bits of the hash to append to the bitstream.

---

### 5. `append_checksum`
**Purpose**: Appends the calculated checksum bits to the entropy bitstream.
**Details**: Ensures the final bitstream conforms to BIP39 standards.

---

### 6. `convert_to_bitstream`
**Purpose**: Converts user-entered coin tosses into a binary bitstream.
**Details**: Translates coin flips (`h` or `t`) into `1` or `0` bits.

---

### 7. `bitstream_to_mnemonic`
**Purpose**: Divides the final bitstream into 11-bit chunks and maps them to indices in the BIP39 word list.
**Details**: Constructs the mnemonic phrase and verifies its correctness.

---

### 8. `load_wordlist`
**Purpose**: Loads the BIP39 English word list into memory.
**Details**: Reads the word list file or hardcoded data and makes it accessible for index mapping.

---

### 9. `print_mnemonic`
**Purpose**: Outputs the final mnemonic phrase to the user.
**Details**: Formats the mnemonic as a space-separated string for easy copying and verification.

---

### 10. `print_help`
**Purpose**: Displays the usage instructions for the program.
**Details**: Provides details on how to use the command-line arguments effectively.

---

### 11. `main`
**Purpose**: The entry point of the program that orchestrates the entire workflow.
**Details**: Calls the above functions in sequence to parse input, generate entropy, calculate the checksum, and produce the final mnemonic phrase.

*/


use clap::{Parser, ArgAction};
use rand::Rng; // For randomizing remaining flips
use sha2::{Sha256, Digest};

#[derive(Parser, Debug)]
#[command(
    author = "Rich Hollenbeck <rghollenbeck@protonmail.com>",
    version = "0.1.0",
    about = "A utility to generate entropy for a BIP39 mnemonic.",
    long_about = "This utility, `cointoss`, converts multiple tosses of a coin into a Bitcoin BIP39 seed phrase. A command-line switch indicates whether to test for a 12, 15, 18, 21, or 24-word phrase."
)]
struct Args {
    /// Generate a mnemonic with 12 words (128 bits)
    #[arg(long = "12", action = ArgAction::SetTrue)]
    twelve: bool,

    /// Generate a mnemonic with 15 words (160 bits)
    #[arg(long = "15", action = ArgAction::SetTrue)]
    fifteen: bool,

    /// Generate a mnemonic with 18 words (192 bits)
    #[arg(long = "18", action = ArgAction::SetTrue)]
    eighteen: bool,

    /// Generate a mnemonic with 21 words (224 bits)
    #[arg(long = "21", action = ArgAction::SetTrue)]
    twenty_one: bool,

    /// Generate a mnemonic with 24 words (256 bits)
    #[arg(long = "24", action = ArgAction::SetTrue)]
    twenty_four: bool,
}


const BIP39_WORDLIST: [&str; 2048] = [
"abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual","adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction","audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty","because","become","beef","before","begin","behave","behind","believe","below","belt","bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike","bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless","blind","blood","blossom","blouse","blue","blur","blush","board","boat","body","boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","bunker","burden","burger","burst","bus","business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp","can","canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital","captain","car","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog","catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","chat","cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic","chuckle","chunk","churn","cigar","cinnamon","circle","citizen","city","civil","claim","clap","clarify","claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut","code","coffee","coil","coin","collect","color","column","combine","come","comfort","comic","common","company","concert","conduct","confirm","congress","connect","consider","control","convince","cook","cool","copper","copy","coral","core","corn","correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal","debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk","despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo","ecology","economy","edge","edit","educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact","end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","era","erase","erode","erosion","error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange","excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit","exotic","expand","expect","expire","explain","expose","express","extend","extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame","family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father","fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female","fence","festival","fetch","fever","few","fiber","fiction","field","figure","file","film","filter","final","find","fine","finger","finish","fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","flush","fly","foam","focus","fog","foil","fold","follow","food","foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front","frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic","garment","gas","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant","grape","grass","gravity","great","green","grid","grief","grit","grocery","group","grow","grunt","guard","guess","guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy","harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help","hen","hero","hidden","high","hill","hint","hip","hire","history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital","host","hotel","hour","hover","hub","huge","human","humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune","impact","impose","improve","impulse","inch","include","income","increase","index","indicate","indoor","industry","infant","inflict","inform","inhale","inherit","initial","inject","injury","inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire","install","intact","interest","into","invest","invite","involve","iron","island","isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel","job","join","joke","journey","joy","judge","juice","jump","jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife","knock","know","lab","label","labor","ladder","lady","lake","lamp","language","laptop","large","later","latin","laugh","laundry","lava","law","lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level","liar","liberty","library","license","life","lift","light","like","limb","limit","link","lion","liquid","list","little","live","lizard","load","loan","lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad","magic","magnet","maid","mail","main","major","make","mammal","man","manage","mandate","mango","mansion","manual","maple","marble","march","margin","marine","market","marriage","mask","mass","master","match","material","math","matrix","matter","maximum","maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt","member","memory","mention","menu","mercy","merge","merit","merry","mesh","message","metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor","minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile","model","modify","mom","moment","monitor","monkey","monster","month","moon","moral","more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual","myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature","near","neck","need","negative","neglect","neither","nephew","nerve","nest","net","network","neutral","never","news","next","nice","night","noble","noise","nominee","noodle","normal","north","nose","notable","note","nothing","notice","novel","now","nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","observe","obtain","obvious","occur","ocean","october","odor","off","offer","office","often","oil","okay","old","olive","olympic","omit","once","one","onion","online","only","open","opera","opinion","oppose","option","orange","orbit","orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output","outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact","paddle","page","pair","palace","palm","panda","panel","panic","panther","paper","parade","parent","park","parrot","party","pass","patch","path","patient","patrol","pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play","please","pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony","pool","popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority","prison","private","prize","problem","process","produce","profit","program","project","promote","proof","property","prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin","punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle","pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rail","rain","raise","rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven","raw","razor","ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release","relief","rely","remain","remember","remind","remove","render","renew","rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib","ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot","ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket","romance","roof","rookie","room","rose","rotate","rough","round","route","royal","rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salmon","salon","salt","salute","same","sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script","scrub","sea","search","season","seat","second","secret","section","security","seed","seek","segment","select","sell","seminar","senior","sense","sentence","series","service","session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side","siege","sight","sign","silent","silk","silly","silver","similar","simple","since","sing","siren","sister","situate","six","size","skate","sketch","ski","skill","skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda","soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry","sort","soul","sound","soup","source","south","space","spare","spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider","spike","spin","spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp","stand","start","state","stay","steak","steel","stem","step","stereo","stick","still","sting","stock","stomach","stone","stool","story","stove","strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny","sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey","suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swift","swim","swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag","tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term","test","text","thank","that","theme","then","theory","there","they","thing","this","thought","three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber","time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler","toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool","tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic","train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick","trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust","truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform","unique","unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold","upon","upper","upset","urban","urge","usage","use","used","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory","video","view","village","vintage","violin","virtual","virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash","wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather","web","wedding","weekend","weird","welcome","west","wet","whale","what","wheat","wheel","when","where","whip","whisper","wide","width","wife","wild","will","win","window","wine","wing","wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word","work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year","yellow","you","young","youth","zebra","zero","zone","zoo"
];




//	new main
fn main() {
    // Parse command-line arguments
    let args = Args::parse();

    // Determine the number of words
    let words = if args.twelve {
        12
    } else if args.fifteen {
        15
    } else if args.eighteen {
        18
    } else if args.twenty_one {
        21
    } else if args.twenty_four {
        24
    } else {
        panic!("No valid word count specified. Use --help for more information.");
    };

		// Calculate entropy bits
		let entropy_bits = get_entropy_bits(words);

    // Prompt the user for coin flips
    let coin_flips = prompt_for_coin_flips(entropy_bits);

    // Convert flips to bitstream
    let bitstream = flips_to_bitstream(coin_flips);

    // Hash the bitstream
    let sha256_hash = hash_bitstream(&bitstream);

    // Extract and append the checksum
    let final_bitstream = extract_checksum(bitstream, sha256_hash, entropy_bits as usize);

    // println!("Line 165: Final bitstream with checksum: {:?}", final_bitstream);

    // Convert bitstream to mnemonic
    let mnemonic = bitstream_to_mnemonic(final_bitstream, &BIP39_WORDLIST);

    // Print the mnemonic
    println!("Mnemonic: {:?}", mnemonic.join(" "));
}


// Calculate the number of entropy bits based on the number of words
fn get_entropy_bits(words: u8) -> u16 {
    match words {
        12 => 128,
        15 => 160,
        18 => 192,
        21 => 224,
        24 => 256,
        _ => panic!("Invalid number of words. Choose 12, 15, 18, 21, or 24."),
    }
}

// Prompt the user for coin flips// Prompt the user for coin flips
fn prompt_for_coin_flips(entropy_bits: u16) -> Vec<u8> {
    let mut flips = Vec::new();
    println!("Please input {} coin flips (h for heads, t for tails):", entropy_bits);
    println!("Enter 'qf' to quit flipping and randomize the rest.");
    println!("Enter 'qq' to quit the program.");
    println!("Enter 'preload' to load a predefined binary stream for testing.");
    println!("Enter 'fill' to fill the data with all heads.");

    for _ in 0..entropy_bits {
        let mut input = String::new();
        loop {
            print!("Flip {}: ", flips.len() + 1);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            std::io::stdin().read_line(&mut input).unwrap();
            let flip = input.trim().to_lowercase();

            match flip.as_str() {
                "h" => {
                    flips.push(1);
                    break;
                }
                "t" => {
                    flips.push(0);
                    break;
                }
                "qf" => {
                    println!("Randomizing the remaining flips...");
                    let remaining = (entropy_bits as usize) - flips.len();
                    let mut rng = rand::thread_rng();
                    flips.extend((0..remaining).map(|_| rng.gen_range(0..=1)));
                    return flips;
                }
                "qq" => {
                    println!("Exiting the program.");
                    std::process::exit(0);
                }
                "preload" => {
                    println!("Preloading binary stream...");
                    let binary_segments = vec![
                        "11111110000", "11111110000", "11111110000", "11111110000",
                        "11111110000", "11111110000", "11111110000", "11111110000",
                        "11111110000", "11111110000", "11111110000", "1111111",
                    ];
                    return binary_segments
                        .iter()
                        .flat_map(|segment| {
                            segment
                                .chars()
                                .map(|bit| bit.to_digit(2).unwrap() as u8)
                        })
                        .collect();
                }
                "fill" => {
                    println!("Filling the remaining flips with heads...");
                    let remaining = (entropy_bits as usize) - flips.len();
                    flips.extend(vec![1; remaining]);
                    return flips;
                }
                _ => println!("Invalid input. Please enter 'h', 't', 'qf', 'qq', 'preload', or 'fill'."),
            }
            input.clear();
        }
    }

    flips
}







// Hash the bitstream using SHA-256
fn hash_bitstream(bitstream: &[u8]) -> Vec<u8> {
    // println!("Bitstream passed to SHA-256: {:?}", bitstream);
    let mut hasher = Sha256::new();
    hasher.update(bitstream);
    hasher.finalize().to_vec()
}

// Convert coin flips into a bitstream
fn flips_to_bitstream(flips: Vec<u8>) -> Vec<u8> {
    let mut bitstream = Vec::new();
    let mut current_byte = 0u8;
    let mut bit_count = 0;

    for flip in flips {
        current_byte = (current_byte << 1) | flip;
        bit_count += 1;

        if bit_count == 8 {
            bitstream.push(current_byte);
            current_byte = 0;
            bit_count = 0;
        }
    }

    if bit_count > 0 {
        current_byte <<= 8 - bit_count;
        bitstream.push(current_byte);
    }

    bitstream
}

/*
The extract_checksum function is correctly extracting the checksum bits, but during concatenation, 
ensure that the entropy bits and checksum are added together without introducing extra bits.
The checksum should be appended to the entropy to form the final_bitstream:
*/
fn extract_checksum(bitstream: Vec<u8>, sha256_hash: Vec<u8>, ent: usize) -> Vec<u8> {
    let checksum_size = ent / 32; // Number of bits for the checksum
    println!("Checksum size (in bits): {}", checksum_size);

    // Extract checksum bits
    let mut checksum_bits = Vec::new();
    for byte in sha256_hash.iter() {
        for bit_index in (0..8).rev() {
            let bit = (byte >> bit_index) & 1;
            checksum_bits.push(bit);
            if checksum_bits.len() == checksum_size {
                break;
            }
        }
        if checksum_bits.len() == checksum_size {
            break;
        }
    }

    println!("Extracted checksum bits: {:?}", checksum_bits);

    // Create the final bitstream as a vector of bits
    let mut final_bitstream = Vec::new();
    for byte in &bitstream {
        for bit_index in (0..8).rev() {
            final_bitstream.push((byte >> bit_index) & 1);
        }
    }
/*
    println!(
        "Final bitstream before checksum append: {:?} (bit length: {})",
        final_bitstream,
        final_bitstream.len()
    );
*/
    // Append checksum bits
    final_bitstream.extend(checksum_bits);

    // Assert the final bitstream length
    assert_eq!(
        final_bitstream.len(),
        ent + checksum_size,
        "Final bitstream must have {} bits",
        ent + checksum_size
    );
/*
    println!(
        "Final bitstream with checksum: {:?} (bit length: {})",
        final_bitstream,
        final_bitstream.len()
    );
*/
    final_bitstream
}








/*
The bitstream_to_mnemonic function expects exactly 132 bits for a 12-word mnemonic (128 bits of entropy + 4 bits of checksum). Double-check that the final bitstream passed into this function has this exact length.
*/
fn bitstream_to_mnemonic(final_bitstream: Vec<u8>, wordlist: &[&str; 2048]) -> Vec<String> {
//    println!(
//        "at line 239 in fn bitstream_to_mnemonic() Final bitstream: {:?} (bit length: {})",
//        final_bitstream,
//        final_bitstream.len()
//    );

    // Ensure the concatenated bits match the expected 132 bits
    if final_bitstream.len() != 132 {
        panic!(
            "Unexpected bitstream length: {} (expected 132)",
            final_bitstream.len()
        );
    }

    // Divide into 11-bit chunks
	// Divide into 11-bit chunks
let mut mnemonic = Vec::new();
// println!("Line 382: Final bitstream: {:?}", final_bitstream);

for chunk_start in (0..132).step_by(11) {
    let chunk = &final_bitstream[chunk_start..chunk_start + 11];
    let index: u16 = chunk.iter().fold(0, |acc, &bit| (acc << 1) | bit as u16);
    assert!(index <= 2047, "Index out of range: {}", index); // Check that the index is valid
    mnemonic.push(wordlist[index as usize].to_string());
}
/*
println!("line 391: Generated mnemonic: {:?}", mnemonic);
*/
mnemonic // explicitly return the mnemonic vector

}


