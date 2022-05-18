use bip39::{Mnemonic, Language};
use bitcoin::{
    network::constants::Network,
    util::bip32::{ExtendedPrivKey, ExtendedPubKey, DerivationPath},
    secp256k1::{Secp256k1},
    util::{base58},
};
use clap::Parser;
use std::str::FromStr;

const ZPRV: [u8; 4] = [0x02, 0xAA, 0x7A, 0x99];
const ZPUB: [u8; 4] = [0x02, 0xAA, 0x7E, 0xD3];
const VPRV: [u8; 4] = [0x02, 0x57, 0x50, 0x48];
const VPUB: [u8; 4] = [0x02, 0x57, 0x54, 0x83];

trait PrefixedEncoding {
    fn encode_with_prefix(&self, prefix: &[u8; 4]) -> [u8; 78];
}

impl PrefixedEncoding for ExtendedPrivKey {
    fn encode_with_prefix(&self, prefix: &[u8; 4]) -> [u8; 78] {
        let mut ret: [u8; 78] = self.encode();
        ret[0..4].copy_from_slice(prefix);
        ret
    }
}

impl PrefixedEncoding for ExtendedPubKey {
    fn encode_with_prefix(&self, prefix: &[u8; 4]) -> [u8; 78] {
        let mut ret: [u8; 78] = self.encode();
        ret[0..4].copy_from_slice(prefix);
        ret
    }
}

fn specter_derivation_path(derivation_path: &DerivationPath) -> String {
    let derivation_path_string: String = format!("{}", derivation_path);
    derivation_path_string.replace("'", "h").replacen("m/", "", 1)
}

/// HumanRng - Don't Trust Your Random Number Generator
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// First words of the mnemonic
    #[clap(short, long)]
    words: String,

    /// Selects testnet
    #[clap(short, long)]
    testnet: bool,

    /// Enables verbose output
    #[clap(short, long)]
    verbose: bool,

    /// Checksum word index to select
    #[clap(short, long, default_value_t=0)]
    checksum: usize,
}

fn main() {
    let args = Args::parse();

    let first_words = args.words.trim();
    let mut checksum_words: Vec<&str> = Vec::new();

    for word in Language::English.words_by_prefix("") {
        let all_words = first_words.to_owned() + " " + word;
        let parsed: Result<Mnemonic, _> = all_words.as_str().parse();
        if parsed.is_ok() {
            checksum_words.push(word);
        }
    }

    if let Some(checksum_word) = checksum_words.get(args.checksum) {
        let secp = Secp256k1::new();
        let mnemonic_words = first_words.to_owned() + " " + checksum_word;
        let mnemonic: Mnemonic = mnemonic_words.as_str().parse().unwrap();
        let network: Network = match args.testnet {
            true => Network::Testnet,
            false => Network::Bitcoin,
        };

        println!("SECRET INFO:");
        println!("Full mnemonic (with checksum word): {}", mnemonic_words);
        println!("Full mnemonic length (# words): {}", mnemonic_words.as_str().split(' ').count());
        println!("{}", "-".repeat(80));
        println!("PUBLIC INFO:");

        let derivation_path = match args.testnet {
            true => DerivationPath::from_str("m/48'/1'/0'/2'").unwrap(),
            false => DerivationPath::from_str("m/48'/0'/0'/2'").unwrap(),
        };
        let prefix_prv = match args.testnet {
            true => VPRV,
            false => ZPRV,
        };
        let prefix_pub = match args.testnet {
            true => VPUB,
            false => ZPUB,
        };

        let root_xprv: ExtendedPrivKey = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();
        let xprv = root_xprv.derive_priv(&secp, &derivation_path).unwrap();
        let xpub: ExtendedPubKey = ExtendedPubKey::from_priv(&secp, &xprv);
        let xprv_encoded = base58::check_encode_slice(&xprv.encode());
        let xpub_encoded = base58::check_encode_slice(&xpub.encode());
        let xpub_slip132_encoded = base58::check_encode_slice(&xpub.encode_with_prefix(&prefix_pub));

        println!("SLIP32 Extended PubKey: {}", xpub_slip132_encoded);
        println!("Root Fingerprint: {}", root_xprv.fingerprint(&secp));
        println!("Network: {}", match args.testnet {
            true => "Testnet",
            false => "Mainnet",
        });
        println!("Derivation Path: {}", derivation_path);
        println!("Specter-Desktop Input Format:");
        println!("  [{}/{}]{}", root_xprv.fingerprint(&secp), specter_derivation_path(&derivation_path), xpub_slip132_encoded);
        println!("{}", "-".repeat(80));

        if args.verbose {
            let xprv_slip132_encoded = base58::check_encode_slice(&xprv.encode_with_prefix(&prefix_prv));

            println!("  Advanced Details:");
            println!("  child xpub: {}", xpub_encoded);
            println!("  child xpriv: {}", xprv_encoded);
            println!("  child xpriv (SLIP132 encoded): {}", xprv_slip132_encoded);
            println!("  {} valid checksums: {}", checksum_words.len(), checksum_words.as_slice().join(" "));
        }
    }
}
