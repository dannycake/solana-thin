//! Writes starting inputs into `corpus/<target>/`, so each fuzzer begins from structure
//! rather than from nothing: valid proofs, transactions in all three encodings, bitmaps,
//! block components, validator sets. Run by `scripts/fuzz.sh` before it fuzzes; the files are
//! named `seed-*` and rewritten every time, so they follow the crate's formats as they change.
//!
//! Usage: `seed_corpus [corpus dir]` (default `corpus`, relative to the working directory).

use solana_thin::transaction::Transaction;
use solana_thin_fuzz::{
    client, seed_bitmaps, seed_components, seed_proofs, seed_transactions, seed_validator_sets,
    unhex,
};
use std::path::{Path, PathBuf};

/// Transactions Agave 4.4.1 itself serialized, from the conformance vectors, if they are there.
fn agave_transactions() -> Vec<(String, Vec<u8>)> {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/solana-thin/tests/vectors/agave-v4.4.1.json");
    let Ok(text) = std::fs::read_to_string(vectors) else {
        return Vec::new();
    };
    // Every `"wire":"<hex>"` in the file, without a JSON parser: hex needs no unescaping.
    const KEY: &str = "\"wire\":\"";
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find(KEY) {
        rest = &rest[at + KEY.len()..];
        let Some(end) = rest.find('"') else { break };
        if let Some(bytes) = unhex(&rest[..end]) {
            out.push((format!("agave-{}", out.len()), bytes));
        }
    }
    out
}

fn write(corpus: &Path, target: &str, seeds: &[(String, Vec<u8>)]) -> std::io::Result<()> {
    let dir = corpus.join(target);
    std::fs::create_dir_all(&dir)?;
    for (name, bytes) in seeds {
        std::fs::write(dir.join(format!("seed-{name}")), bytes)?;
    }
    println!("{target}: {} seeds", seeds.len());
    Ok(())
}

fn main() -> std::io::Result<()> {
    let corpus = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "corpus".into()));
    let proofs: Vec<(String, Vec<u8>)> = seed_proofs()
        .into_iter()
        .map(|(name, bytes)| (name.to_string(), bytes))
        .collect();
    let mut transactions = seed_transactions();
    transactions.extend(agave_transactions());
    // A seed that stopped being valid would leave a fuzzer starting from noise without saying
    // so: check them here, where it fails the run.
    for (name, bytes) in &proofs {
        if let Err(error) = client().verify_transaction_bytes(bytes) {
            panic!("seed proof {name} does not verify: {error}");
        }
    }
    for (name, bytes) in &transactions {
        if let Err(error) = Transaction::parse(bytes) {
            panic!("seed transaction {name} does not parse: {error}");
        }
    }
    write(&corpus, "proof_verify", &proofs)?;
    write(&corpus, "transaction_view", &transactions)?;
    write(&corpus, "transaction_wincode", &transactions)?;
    write(&corpus, "bitmap", &seed_bitmaps())?;
    write(&corpus, "marker", &seed_components())?;
    write(&corpus, "validator_set", &seed_validator_sets())?;
    Ok(())
}
