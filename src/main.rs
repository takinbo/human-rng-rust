use bip39::{Language, Mnemonic};
use clap::Parser;

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
        let mnemonic = first_words.to_owned() + " " + checksum_word;
        println!("{:?}", mnemonic);
    }
}
